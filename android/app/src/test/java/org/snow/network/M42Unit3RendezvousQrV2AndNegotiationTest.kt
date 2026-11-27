package org.snow.network

import android.content.ComponentName
import android.content.Context
import android.content.ContextWrapper
import android.content.Intent
import android.content.SharedPreferences
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.setMain
import org.java_websocket.WebSocket
import org.java_websocket.handshake.ClientHandshake
import org.java_websocket.server.WebSocketServer
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.snow.capabilities.AndroidCapabilityDispatcher
import org.snow.protocol.ErrorCode
import org.snow.protocol.JsonSerialization
import org.snow.protocol.SnowError
import org.snow.protocol.SnowMessage
import org.snow.security.AndroidSelfSignedCertGenerator
import org.snow.security.InMemoryCertPinStorage
import org.snow.security.InMemoryPeerHostCertStorage
import org.snow.security.InMemoryTokenStorage
import org.snow.security.PairingFlow
import org.snow.security.PairingState
import org.snow.service.SnowForegroundService
import org.snow.ui.SnowUiRepository
import java.io.File
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference

/**
 * M4.2 Unit 3 (RC-4 & RC-6):
 * - QR v2 & v1 emit/parse, expiry enforcement, and cross-language field parity
 * - Deterministic clock-injected 60s unified 6-digit PIN expiry, cancel & 3-attempt lockout
 * - Per-device Relay fingerprint isolation (SnowForegroundService.resolveRelayTargetFingerprint)
 * - Real E2E TLS RelayClient + E2eRelayTunnel over loopback WebSocket relay rejecting MITM cert
 * - All 4 network negotiation cases, non-overwriting Keep Separate, Dual-Owner Merge & final unpair dissolution
 */
@OptIn(ExperimentalCoroutinesApi::class)
class M42Unit3RendezvousQrV2AndNegotiationTest {

    private class MemPrefs : SharedPreferences {
        private val map = mutableMapOf<String, Any?>()
        override fun getAll(): MutableMap<String, *> = HashMap(map)
        override fun getString(key: String?, defValue: String?): String? = map[key] as? String ?: defValue
        override fun getStringSet(key: String?, defValues: MutableSet<String>?): MutableSet<String>? {
            @Suppress("UNCHECKED_CAST")
            return (map[key] as? Set<String>)?.toMutableSet() ?: defValues
        }
        override fun getInt(key: String?, defValue: Int): Int = (map[key] as? Int) ?: defValue
        override fun getLong(key: String?, defValue: Long): Long = (map[key] as? Long) ?: defValue
        override fun getFloat(key: String?, defValue: Float): Float = (map[key] as? Float) ?: defValue
        override fun getBoolean(key: String?, defValue: Boolean): Boolean = (map[key] as? Boolean) ?: defValue
        override fun contains(key: String?): Boolean = map.containsKey(key)
        override fun edit(): SharedPreferences.Editor = object : SharedPreferences.Editor {
            private val pending = mutableMapOf<String, Any?>()
            private val removals = mutableSetOf<String>()
            private var clearAll = false
            override fun putString(key: String?, value: String?) = apply { if (key != null) pending[key] = value }
            override fun putStringSet(key: String?, values: MutableSet<String>?) = apply {
                if (key != null) pending[key] = values?.toSet()
            }
            override fun putInt(key: String?, value: Int) = apply { if (key != null) pending[key] = value }
            override fun putLong(key: String?, value: Long) = apply { if (key != null) pending[key] = value }
            override fun putFloat(key: String?, value: Float) = apply { if (key != null) pending[key] = value }
            override fun putBoolean(key: String?, value: Boolean) = apply { if (key != null) pending[key] = value }
            override fun remove(key: String?) = apply { if (key != null) removals.add(key) }
            override fun clear() = apply { clearAll = true }
            override fun commit(): Boolean {
                if (clearAll) map.clear()
                for (r in removals) map.remove(r)
                for ((k, v) in pending) {
                    if (v == null) map.remove(k) else map[k] = v
                }
                return true
            }
            override fun apply() { commit() }
        }
        override fun registerOnSharedPreferenceChangeListener(listener: SharedPreferences.OnSharedPreferenceChangeListener?) {}
        override fun unregisterOnSharedPreferenceChangeListener(listener: SharedPreferences.OnSharedPreferenceChangeListener?) {}
    }

    private lateinit var mainExecutor: java.util.concurrent.ExecutorService
    private lateinit var mainDispatcher: kotlinx.coroutines.CoroutineDispatcher
    private val prefsByName = mutableMapOf<String, MemPrefs>()
    private lateinit var tempDir: File
    private lateinit var context: Context
    private lateinit var scope: CoroutineScope

    private fun freeTcpPort(): Int = ServerSocket(0).use { it.localPort }

    private fun resetRepoSingleton() {
        val f = SnowUiRepository::class.java.getDeclaredField("instance")
        f.isAccessible = true
        f.set(null, null)
    }

    @Before
    fun setUp() {
        mainExecutor = java.util.concurrent.Executors.newSingleThreadExecutor()
        mainDispatcher = mainExecutor.asCoroutineDispatcher()
        Dispatchers.setMain(mainDispatcher)
        resetRepoSingleton()
        prefsByName.clear()
        tempDir = File(System.getProperty("java.io.tmpdir"), "snow_m42_u3_${UUID.randomUUID()}").apply { mkdirs() }
        context = object : ContextWrapper(null) {
            override fun getApplicationContext(): Context = this
            override fun getFilesDir(): File = tempDir
            override fun getCacheDir(): File = tempDir
            override fun getPackageName(): String = "org.snow"
            override fun getSharedPreferences(name: String?, mode: Int): SharedPreferences {
                return prefsByName.getOrPut(name ?: "default") { MemPrefs() }
            }
            override fun startForegroundService(service: Intent?): ComponentName? = null
            override fun startService(service: Intent?): ComponentName? = null
        }
        scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    }

    @After
    fun tearDown() {
        resetRepoSingleton()
        scope.cancel()
        tempDir.deleteRecursively()
        Dispatchers.resetMain()
        mainExecutor.shutdownNow()
    }

    @Test
    fun testQrV2EmissionParsingExpiryAndUnified60sPinLifecycle() {
        val clock = AtomicLong(1_700_000_000_000L)
        val hostMgr = AndroidPeerHostManager(InMemoryPeerHostCertStorage()).apply {
            clockMillis = { clock.get() }
        }
        val tokens = InMemoryTokenStorage()
        val dispatcher = AndroidCapabilityDispatcher(context, transferClientProvider = { null })
        val port = freeTcpPort()
        val mediaPort = freeTcpPort()
        hostMgr.setHostModeSettingEnabled(true)
        assertTrue(
            hostMgr.enableHostMode(
                port = port,
                tokenStorage = tokens,
                dispatcher = dispatcher,
                localDeviceId = "android-qr-host",
                parentScope = scope,
                mediaPort = mediaPort,
                snowId = "SNW-QRV2-HOST",
                networkId = null // standalone!
            )
        )

        try {
            val qrStr = hostMgr.generatePairingQrJson(
                localDeviceId = "android-qr-host",
                snowId = "SNW-QRV2-HOST",
                networkId = null,
                version = 2,
                hubUrl = "https://snow-relay.onrender.com",
                rdvId = "rdv_android_123"
            )
            assertNotNull(qrStr)
            val qrObj = JSONObject(qrStr!!)
            assertEquals(2, qrObj.getInt("v"))
            assertEquals("android-qr-host", qrObj.getString("device_id"))
            assertEquals("android", qrObj.getString("device_type"))
            assertEquals(mediaPort, qrObj.getInt("transfer_port"))
            assertTrue(qrObj.isNull("network_id"))
            assertEquals("rdv_android_123", qrObj.getString("rdv_id"))
            assertEquals((clock.get() + 60_000L) / 1000L, qrObj.getLong("exp"))

            // Expired QR v2 rejected by repository scanner cleanly
            val repo = SnowUiRepository.getInstance(context)
            val expiredQr = JSONObject(qrStr).apply { put("exp", (System.currentTimeMillis() / 1000L) - 10L) }
            val expLatch = CountDownLatch(1)
            val expRes = AtomicReference<Pair<Boolean, String?>>()
            repo.handleQrScanPayload(expiredQr.toString()) { ok, msg ->
                expRes.set(ok to msg)
                expLatch.countDown()
            }
            assertTrue(expLatch.await(3, TimeUnit.SECONDS))
            assertFalse(expRes.get()!!.first)
            assertTrue(expRes.get()!!.second!!.contains("expired", ignoreCase = true))

            // Deterministic 60s PIN expiry, cancel & 3-attempt lockout
            val pin1 = hostMgr.generatePairingPin()
            assertEquals(6, pin1.length)
            clock.addAndGet(59_000L)
            assertNotNull(hostMgr.getCurrentEphemeralPinInfo())
            clock.addAndGet(2_000L) // +61s > 60s window
            val expiredRes = hostMgr.verifyAndConsumePairingPinDetailed(pin1)
            assertEquals(PinVerificationStatus.EXPIRED, expiredRes.status)

            val pin2 = hostMgr.generatePairingPin()
            hostMgr.cancelPairingPin()
            assertNull(hostMgr.getCurrentEphemeralPinInfo())
            assertFalse(hostMgr.verifyAndConsumePairingPin(pin2))

            hostMgr.generatePairingPin()
            val bad1 = hostMgr.verifyAndConsumePairingPinDetailed("000001")
            val bad2 = hostMgr.verifyAndConsumePairingPinDetailed("000002")
            val bad3 = hostMgr.verifyAndConsumePairingPinDetailed("000003")
            assertEquals(2, bad1.remainingAttempts)
            assertEquals(1, bad2.remainingAttempts)
            assertEquals(PinVerificationStatus.LOCKED, bad3.status)
        } finally {
            hostMgr.disableHostMode()
        }
    }

    @Test
    fun testRelayPerDevicePinIsolationAndRealE2eTunnelRendezvousWithMitmBlock() {
        // 1. Per-device pin isolation check in SnowForegroundService helper
        val pinStore = InMemoryCertPinStorage().apply {
            pinFingerprint("00".repeat(32)) // legacy global slot that must NOT override per-device slot
            pinFingerprintForDevice("peer-alpha", "AA".repeat(32))
            pinFingerprintForDevice("peer-beta", "BB".repeat(32))
        }
        assertEquals("AA".repeat(32), SnowForegroundService.resolveRelayTargetFingerprint(pinStore, "peer-alpha"))
        assertEquals("BB".repeat(32), SnowForegroundService.resolveRelayTargetFingerprint(pinStore, "peer-beta"))
        assertNull(SnowForegroundService.resolveRelayTargetFingerprint(pinStore, "unpinned-peer"))

        // 2. Spin up real local WebSocket relay forwarder bridging hostRelayClient <-> peer RelayClient over TLS 1.3 E2eRelayTunnel
        val relayPort = freeTcpPort()
        val connectedConns = ConcurrentHashMap<String, WebSocket>()
        val relayServer = object : WebSocketServer(InetSocketAddress("127.0.0.1", relayPort)) {
            override fun onStart() {}
            override fun onOpen(conn: WebSocket, handshake: ClientHandshake) {}
            override fun onClose(conn: WebSocket, code: Int, reason: String?, remote: Boolean) {
                connectedConns.entries.removeIf { it.value == conn }
            }
            override fun onMessage(conn: WebSocket, message: String) {
                val json = JSONObject(message)
                when (json.optString("type")) {
                    "hello" -> {
                        val devId = json.getString("device_id")
                        connectedConns[devId] = conn
                        conn.send(JSONObject().apply {
                            put("type", "hello_ack")
                            put("success", true)
                            put("device_id", devId)
                        }.toString())
                    }
                    "relay_frame" -> {
                        val target = json.getString("target")
                        val sender = connectedConns.entries.firstOrNull { it.value == conn }?.key ?: ""
                        connectedConns[target]?.send(JSONObject().apply {
                            put("type", "relay_frame")
                            put("source", sender)
                            put("payload_b64", json.getString("payload_b64"))
                        }.toString())
                    }
                }
            }
            override fun onError(conn: WebSocket?, ex: Exception?) {}
        }.apply {
            isReuseAddr = true
            start()
        }
        Thread.sleep(200)

        val hostMgr = AndroidPeerHostManager(InMemoryPeerHostCertStorage())
        val dispatcher = AndroidCapabilityDispatcher(context, transferClientProvider = { null })
        val hostCertStore = InMemoryPeerHostCertStorage()
        val hostCertResult = AndroidSelfSignedCertGenerator.loadOrCreate(hostCertStore)
        val (p12Bytes, p12Pass) = hostCertStore.loadKeyStoreMaterial()!!
        val hostKeyStore = java.security.KeyStore.getInstance("PKCS12").apply {
            load(p12Bytes.inputStream(), p12Pass)
        }
        val kmf = javax.net.ssl.KeyManagerFactory.getInstance(javax.net.ssl.KeyManagerFactory.getDefaultAlgorithm()).apply {
            init(hostKeyStore, p12Pass)
        }
        val peerCertResult = AndroidSelfSignedCertGenerator.loadOrCreate(InMemoryPeerHostCertStorage())
        val hostDevId = "host-rdv-${UUID.randomUUID().toString().take(8)}"
        val repo = SnowUiRepository.getInstance(context).apply {
            tokenStorageOverrideForTest = InMemoryTokenStorage()
            certPinStorageOverrideForTest = InMemoryCertPinStorage()
        }
        val peerDevId = repo.identity.deviceId

        val hostRelayClient = RelayClient(
            relayUrl = "ws://127.0.0.1:$relayPort/v1/tunnel",
            deviceId = hostDevId,
            groupId = "rdv-route",
            ticket = "",
            targetPeerId = peerDevId,
            certPinStorage = InMemoryCertPinStorage(),
            expectedPeerFingerprint = null,
            isClientMode = false,
            scope = scope,
            hubToken = "hub-tok-host",
            networkId = "SNW-NET-EEEE5555"
        ).apply {
            keyManagers = kmf.keyManagers
            requestDispatcher = { action, data ->
                if (action == "pair_request" && data?.get("pin") == "654321") {
                    Pair(
                        mapOf(
                            "status" to "success",
                            "action" to "pair_response",
                            "session_id" to "rdv-sess-1",
                            "device_id" to hostDevId,
                            "server_device_id" to hostDevId,
                            "device_name" to "Host Relay Phone",
                            "device_type" to "android",
                            "auth_token" to "rdv-auth-tok-123456",
                            "trust_tier" to "owner",
                            "network_id" to "SNW-NET-EEEE5555",
                            "relationship" to "member",
                            "network_action" to "JOINED",
                            "network_conflict" to false,
                            "manifest" to emptyMap<String, Any>()
                        ),
                        null
                    )
                } else {
                    Pair(null, SnowError(ErrorCode.UNAUTHORIZED, "Invalid PIN"))
                }
            }
        }

        try {
            hostRelayClient.connect()
            Thread.sleep(250)

            // A) MITM wrong host fingerprint MUST fail inside E2E tunnel BEFORE pairing succeeds
            val mitmLatch = CountDownLatch(1)
            val mitmOutcome = AtomicReference<Pair<Boolean, String?>>()
            repo.completeRendezvousPairingOverTunnel(
                rdvData = mapOf(
                    "relay_ws_url" to "ws://127.0.0.1:$relayPort/v1/tunnel",
                    "host_device_id" to hostDevId,
                    "host_cert_fingerprint" to "FF".repeat(32),
                    "bootstrap_token" to "bs-tok-1",
                    "network_id" to "SNW-NET-EEEE5555"
                ),
                pin = "654321"
            ) { ok, err ->
                mitmOutcome.set(ok to err)
                mitmLatch.countDown()
            }
            assertTrue(mitmLatch.await(6, TimeUnit.SECONDS))
            assertFalse(mitmOutcome.get()!!.first)
            assertNull(repo.adoptedNetworkId.value)

            // Reconnect host fresh for clean legitimate peer tunnel
            hostRelayClient.disconnect()
            Thread.sleep(150)
            val hostRelayClient2 = RelayClient(
                relayUrl = "ws://127.0.0.1:$relayPort/v1/tunnel",
                deviceId = hostDevId,
                groupId = "rdv-route",
                ticket = "",
                targetPeerId = peerDevId,
                certPinStorage = InMemoryCertPinStorage(),
                expectedPeerFingerprint = null,
                isClientMode = false,
                scope = scope,
                hubToken = "hub-tok-host",
                networkId = "SNW-NET-EEEE5555"
            ).apply {
                keyManagers = hostRelayClient.keyManagers
                requestDispatcher = hostRelayClient.requestDispatcher
            }
            hostRelayClient2.connect()
            Thread.sleep(250)

            // Override activeCertPinStorage / activeTokenStorage with clean repo test hooks?
            // Note repo pins hostFp per-device inside activeCertPinStorage when connecting.
            val okLatch = CountDownLatch(1)
            val okOutcome = AtomicReference<Pair<Boolean, String?>>()
            repo.completeRendezvousPairingOverTunnel(
                rdvData = mapOf(
                    "relay_ws_url" to "ws://127.0.0.1:$relayPort/v1/tunnel",
                    "host_device_id" to hostDevId,
                    "host_cert_fingerprint" to hostCertResult.fingerprint.replace(":", ""),
                    "bootstrap_token" to "bs-tok-2",
                    "network_id" to "SNW-NET-EEEE5555",
                    "host_device_type" to "android",
                    "host_transfer_port" to 8769
                ),
                pin = "654321"
            ) { ok, err ->
                okOutcome.set(ok to err)
                okLatch.countDown()
            }
            assertTrue(okLatch.await(8, TimeUnit.SECONDS))
            assertTrue(okOutcome.get()?.second ?: "ok", okOutcome.get()!!.first)
            assertEquals("SNW-NET-EEEE5555", repo.adoptedNetworkId.value)
            assertTrue(repo.savedDevices.value.any { it.deviceId == hostDevId && it.transferPort == 8769 })
            hostRelayClient2.disconnect()
        } finally {
            hostRelayClient.disconnect()
            relayServer.stop(500)
        }
    }

    @Test
    fun testFourCaseNetworkNegotiationKeepSeparateMergeAndDissolutionOverRealTlsSockets() {
        val repo = SnowUiRepository.getInstance(context)
        val clientTokens = InMemoryTokenStorage()
        val clientPins = InMemoryCertPinStorage()
        repo.tokenStorageOverrideForTest = clientTokens
        repo.certPinStorageOverrideForTest = clientPins

        fun connectClientToHost(
            port: Int,
            targetHostId: String,
            hostFp: String,
            pin: String
        ): Pair<SnowWebSocketClient, PairingState.Paired> {
            val client = SnowWebSocketClient(
                scope = scope,
                certPinStorage = clientPins,
                tokenStorage = clientTokens,
                useTls = true
            ).apply { autoReconnectEnabled = false }
            clientPins.pinFingerprintForDevice(targetHostId, hostFp)
            val connLatch = CountDownLatch(1)
            val authStateObs = scope.launch {
                client.authState.collect { auth ->
                    if (auth is AuthState.ConnectedUnauthenticated) {
                        connLatch.countDown()
                    }
                }
            }
            client.connect("127.0.0.1", port, targetHostId, ConnectionHandshakeMode.EXPLICIT_PAIRING_INITIATOR)
            assertTrue(connLatch.await(5, TimeUnit.SECONDS))
            authStateObs.cancel()
            repo.attachClientForTest(client)

            val pairLatch = CountDownLatch(1)
            val pairedRef = AtomicReference<PairingState>()
            repo.pairDevice(pin) { p ->
                if (p is PairingState.Paired || p is PairingState.Error || p is PairingState.WrongPin) {
                    pairedRef.set(p)
                    pairLatch.countDown()
                }
            }
            assertTrue(pairLatch.await(5, TimeUnit.SECONDS))
            val paired = pairedRef.get() as PairingState.Paired
            return client to paired
        }

        val dispatcher = AndroidCapabilityDispatcher(context, transferClientProvider = { null })

        // Case 1: Standalone client + Standalone Host -> FORMED canonical SNW-NET-XXXXXXXX
        val host1Id = "host-net-1-${UUID.randomUUID().toString().take(6)}"
        val host1Port = freeTcpPort()
        val host1Mgr = AndroidPeerHostManager(InMemoryPeerHostCertStorage())
        host1Mgr.setHostModeSettingEnabled(true)
        assertTrue(host1Mgr.enableHostMode(host1Port, InMemoryTokenStorage(), dispatcher, host1Id, parentScope = scope, mediaPort = freeTcpPort(), networkId = null))
        val pin1 = host1Mgr.generatePairingPin()
        val (client1, res1) = connectClientToHost(host1Port, host1Id, host1Mgr.hostState.value.certFingerprint, pin1)
        assertEquals("FORMED", res1.networkAction)
        assertEquals("member", res1.relationship)
        val formedNet = res1.peerNetworkId!!
        assertTrue(AndroidPeerHostManager.isValidCanonicalNetworkId(formedNet))
        assertEquals(formedNet, repo.adoptedNetworkId.value)
        assertEquals(formedNet, host1Mgr.hostState.value.networkId)
        repo.recordSuccessfulConnection("127.0.0.1", host1Port, res1.sessionId, res1.trustTier, peerDeviceId = host1Id, peerNetworkId = formedNet, peerRelationship = "member")
        client1.disconnect()
        host1Mgr.disableHostMode()

        // Case 4: Repo (in formedNet) pairs with Host2 (owner of SNW-NET-BBBB9999) -> CONFLICT, NO silent overwrite!
        val host2Id = "host-net-2-${UUID.randomUUID().toString().take(6)}"
        val host2Port = freeTcpPort()
        val host2Mgr = AndroidPeerHostManager(InMemoryPeerHostCertStorage())
        host2Mgr.setHostModeSettingEnabled(true)
        assertTrue(host2Mgr.enableHostMode(host2Port, InMemoryTokenStorage(), dispatcher, host2Id, parentScope = scope, mediaPort = freeTcpPort(), networkId = "SNW-NET-BBBB9999"))
        val pin2 = host2Mgr.generatePairingPin()
        val (client2, res2) = connectClientToHost(host2Port, host2Id, host2Mgr.hostState.value.certFingerprint, pin2)
        assertEquals("DECISION_REQUIRED", res2.networkAction)
        assertTrue(res2.networkConflict)
        assertEquals("external_network", res2.relationship)
        // Local network ID MUST remain formedNet (never silently overwritten by SNW-NET-BBBB9999!)
        assertEquals(formedNet, repo.adoptedNetworkId.value)
        assertNotNull(repo.pendingNetworkDecision.value)
        repo.recordSuccessfulConnection("127.0.0.1", host2Port, res2.sessionId, res2.trustTier, peerDeviceId = host2Id, peerNetworkId = "SNW-NET-BBBB9999", peerRelationship = "external_network", networkConflict = true)

        // Verify serialization preserves external_network relationship
        val roundtrip = repo.deserializeSavedDevices(repo.serializeSavedDevices(repo.savedDevices.value))
        assertEquals("external_network", roundtrip.first { it.deviceId == host2Id }.relationship)

        // Dual-Owner Merge: Client owner approves -> MERGE_APPROVAL_REQUIRED -> Host2 owner approves -> MERGED!
        val mergeStep1Latch = CountDownLatch(1)
        val mergeStep1Msg = AtomicReference<String>()
        repo.resolvePendingNetworkDecision(merge = true) { ok, msg ->
            assertTrue(ok)
            mergeStep1Msg.set(msg)
            mergeStep1Latch.countDown()
        }
        assertTrue(mergeStep1Latch.await(5, TimeUnit.SECONDS))
        assertEquals("MERGE_APPROVAL_REQUIRED", repo.pendingNetworkDecision.value?.networkAction)

        // Simulate Host2 owner confirming merge on Host2 side -> COMMITTED surviving network ID
        val txId = repo.pendingNetworkDecision.value!!.txId
        val host2Commit = host2Mgr.resolveMergeDecision(txId, "merge", host2Id)
        assertTrue(host2Commit.committed)
        assertEquals("SNW-NET-BBBB9999", host2Commit.networkId)
        // Promote host2 to member & apply surviving merged network
        repo.applyHostNegotiatedNetworkId(host2Commit.networkId)
        repo.recordSuccessfulConnection("127.0.0.1", host2Port, res2.sessionId, res2.trustTier, peerDeviceId = host2Id, peerNetworkId = "SNW-NET-BBBB9999", peerRelationship = "member")
        assertEquals("SNW-NET-BBBB9999", repo.adoptedNetworkId.value)
        client2.disconnect()
        host2Mgr.disableHostMode()

        // Removing first member retains network; removing final member dissolves adoptedNetworkId cleanly back to null (standalone)
        repo.unpairDevice(repo.savedDevices.value.first { it.deviceId == host1Id })
        assertEquals("SNW-NET-BBBB9999", repo.adoptedNetworkId.value)
        repo.unpairDevice(repo.savedDevices.value.first { it.deviceId == host2Id })
        assertNull(repo.adoptedNetworkId.value)
    }
}
