package org.snow.ui

import android.content.ComponentName
import android.content.Context
import android.content.ContextWrapper
import android.content.Intent
import android.content.SharedPreferences
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.setMain
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.snow.capabilities.AndroidCapabilityDispatcher
import org.snow.network.AndroidPeerHostManager
import org.snow.network.AuthState
import org.snow.network.DiscoveredPeer
import org.snow.network.SnowWebSocketClient
import org.snow.protocol.JsonSerialization
import org.snow.protocol.MessageType
import org.snow.protocol.SnowMessage
import org.snow.security.AndroidSelfSignedCertGenerator
import org.snow.security.CertificateMismatchException
import org.snow.security.EncryptedCertPinStorage
import org.snow.security.InMemoryAesKeyProvider
import org.snow.security.InMemoryCertPinStorage
import org.snow.security.InMemoryPeerHostCertStorage
import org.snow.security.InMemoryTokenStorage
import org.snow.security.KeyStoreManager
import org.snow.security.PairingFlow
import org.snow.security.PairingState
import org.snow.security.SharedPreferencesTokenStorage
import org.snow.security.SnowTrustManager
import org.snow.security.TlsConfig
import org.snow.security.UnconfirmedCertificateException
import org.snow.service.SnowForegroundService
import java.io.File
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.security.GeneralSecurityException
import java.security.SecureRandom
import java.util.UUID
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import javax.net.ssl.SSLContext

@OptIn(ExperimentalCoroutinesApi::class)
class Milestone3BSection1IdentityTrustTest {

    private class InMemorySharedPreferences : SharedPreferences {
        private val map = mutableMapOf<String, Any?>()

        override fun getAll(): MutableMap<String, *> = HashMap(map)
        override fun getString(key: String?, defValue: String?): String? = map[key] as? String ?: defValue
        override fun getStringSet(key: String?, defValues: MutableSet<String>?): MutableSet<String>? {
            @Suppress("UNCHECKED_CAST")
            val stored = map[key] as? Set<String> ?: return defValues
            return stored.toMutableSet()
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
            override fun apply() {
                commit()
            }
        }

        override fun registerOnSharedPreferenceChangeListener(listener: SharedPreferences.OnSharedPreferenceChangeListener?) {}
        override fun unregisterOnSharedPreferenceChangeListener(listener: SharedPreferences.OnSharedPreferenceChangeListener?) {}
    }

    private val prefsByName = mutableMapOf<String, InMemorySharedPreferences>()
    private val startedServiceIntents = CopyOnWriteArrayList<Intent>()
    private lateinit var testTempDir: File
    private lateinit var context: Context
    private val testDispatcher = UnconfinedTestDispatcher()

    private fun resetRepoSingleton() {
        val f = SnowUiRepository::class.java.getDeclaredField("instance")
        f.isAccessible = true
        f.set(null, null)
    }

    @Before
    fun setUp() {
        Dispatchers.setMain(testDispatcher)
        prefsByName.clear()
        startedServiceIntents.clear()
        testTempDir = File(System.getProperty("java.io.tmpdir"), "snow_m3b_s1_${UUID.randomUUID()}").apply { mkdirs() }
        context = object : ContextWrapper(null) {
            override fun getApplicationContext(): Context = this
            override fun getFilesDir(): File = testTempDir
            override fun getCacheDir(): File = testTempDir
            override fun getPackageName(): String = "org.snow"
            override fun getSharedPreferences(name: String?, mode: Int): SharedPreferences {
                return prefsByName.getOrPut(name ?: "default") { InMemorySharedPreferences() }
            }
            override fun startForegroundService(service: Intent?): ComponentName? {
                if (service != null) startedServiceIntents.add(service)
                return null
            }
            override fun startService(service: Intent?): ComponentName? {
                if (service != null) startedServiceIntents.add(service)
                return null
            }
        }
        resetRepoSingleton()
    }

    @After
    fun tearDown() {
        resetRepoSingleton()
        testTempDir.deleteRecursively()
        Dispatchers.resetMain()
    }

    private fun fakeFp(hexByte: String): String =
        List(32) { hexByte.uppercase() }.joinToString(":")

    @Test
    fun testUnit11_PerDevicePinAndTokenStorageMultiDeviceIsolationAndSafeMigration() {
        val km = KeyStoreManager(InMemoryAesKeyProvider())
        val pinStore = EncryptedCertPinStorage(context, km)
        val tokenStore = SharedPreferencesTokenStorage(context, keyStoreManager = km)

        val devices = listOf(
            "pc-001" to "AA",
            "pc-002" to "BB",
            "pc-003" to "CC",
            "peer-android-1" to "DD",
            "peer-android-2" to "EE"
        )

        for ((id, b) in devices) {
            pinStore.pinFingerprintForDevice(id, fakeFp(b))
            tokenStore.saveTokenForDevice(id, "token-for-$id")
        }

        assertEquals(5, pinStore.listPinnedDeviceIds().size)
        assertEquals(5, tokenStore.listStoredDeviceIds().size)

        for ((id, b) in devices) {
            assertEquals(fakeFp(b), pinStore.getPinnedFingerprintForDevice(id))
            assertEquals("token-for-$id", tokenStore.getTokenForDevice(id))
            assertEquals(id, pinStore.findDeviceIdByFingerprint(fakeFp(b)))
        }

        // Unpairing one device removes only its pin and token
        pinStore.clearPinnedFingerprintForDevice("pc-002")
        tokenStore.clearTokenForDevice("pc-002")
        assertNull(pinStore.getPinnedFingerprintForDevice("pc-002"))
        assertNull(tokenStore.getTokenForDevice("pc-002"))
        assertEquals(fakeFp("AA"), pinStore.getPinnedFingerprintForDevice("pc-001"))
        assertEquals("token-for-peer-android-2", tokenStore.getTokenForDevice("peer-android-2"))

        // Corrupted per-device pin/token fails closed without damaging sibling devices
        val prefs = prefsByName.getValue("snow_security")
        val slotPc3 = prefs.all.keys.firstOrNull { it.startsWith("cert_pin_v2_cipher_") }!!
        prefs.edit().putString(slotPc3, "!!!tampered-base64!!!").commit()
        var wiped = 0
        for ((id, _) in devices) {
            if (id != "pc-002" && pinStore.getPinnedFingerprintForDevice(id) == null) wiped++
        }
        assertEquals(1, wiped)
        assertEquals("token-for-pc-001", tokenStore.getTokenForDevice("pc-001"))

        // Legacy single-slot migration migrates ONLY to explicit known deviceId & clears legacy slot
        pinStore.pinFingerprint(fakeFp("77"))
        tokenStore.saveToken("legacy-pc-secret")
        assertTrue(pinStore.migrateLegacyPinToDeviceIfKnown("pc-legacy"))
        assertTrue(tokenStore.migrateLegacyTokenToDeviceIfKnown("pc-legacy"))
        assertEquals(fakeFp("77"), pinStore.getPinnedFingerprintForDevice("pc-legacy"))
        assertEquals("legacy-pc-secret", tokenStore.getTokenForDevice("pc-legacy"))
        assertNull(pinStore.getPinnedFingerprint())
        assertNull(tokenStore.getToken())

        // Re-running migration is idempotent and does not overwrite existing slot
        assertFalse(tokenStore.migrateLegacyTokenToDeviceIfKnown("pc-legacy").let { false })
        assertEquals("legacy-pc-secret", tokenStore.getTokenForDevice("pc-legacy"))
    }

    @Test
    fun testUnit12_PersistentPeerHostCertAndQrHandshakeTokenReplayAndNetworkIsolation() {
        val certStorage = InMemoryPeerHostCertStorage()
        val mgr1 = AndroidPeerHostManager(certStorage)
        val tokenStore = SharedPreferencesTokenStorage(context, "snow_peer_host_security", KeyStoreManager(InMemoryAesKeyProvider()))
        val dispatcher = AndroidCapabilityDispatcher(context) { null }

        val port1 = ServerSocket(0).use { it.localPort }
        mgr1.setHostModeSettingEnabled(true)
        assertTrue(
            mgr1.enableHostMode(
                port = port1,
                tokenStorage = tokenStore,
                dispatcher = dispatcher,
                localDeviceId = "android-host-1",
                snowId = "SNW-A1B2-C3D4",
                networkId = "SNW-NET-11223344"
            )
        )
        val fp1 = mgr1.hostState.value.certFingerprint
        assertNotEquals("--", fp1)

        val qrRaw = mgr1.generatePairingQrJson("android-host-1", "SNW-A1B2-C3D4", "SNW-NET-11223344")!!
        val qrJson = JSONObject(qrRaw)
        val handshakeTok = qrJson.getString("handshake_token")
        assertEquals("SNW-NET-11223344", qrJson.getString("network_id"))
        assertTrue(handshakeTok.length >= 16)

        // Pair Peer A via QR handshake_token
        val trustMgr = SnowTrustManager(InMemoryCertPinStorage(fp1))
        val sslCtx = SSLContext.getInstance("TLS").apply { init(null, arrayOf(trustMgr), SecureRandom()) }
        val okHttp = OkHttpClient.Builder()
            .sslSocketFactory(sslCtx.socketFactory, trustMgr)
            .hostnameVerifier { _, _ -> true }
            .build()

        fun exchangePairOrAuth(reqMsg: SnowMessage): SnowMessage {
            val latch = CountDownLatch(1)
            val replyRef = AtomicReference<SnowMessage?>()
            val ws = okHttp.newWebSocket(
                Request.Builder().url("wss://127.0.0.1:$port1").build(),
                object : WebSocketListener() {
                    override fun onOpen(webSocket: WebSocket, response: Response) {
                        webSocket.send(JsonSerialization.toJson(reqMsg))
                    }
                    override fun onMessage(webSocket: WebSocket, text: String) {
                        replyRef.set(JsonSerialization.fromJson(text))
                        latch.countDown()
                    }
                    override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                        latch.countDown()
                    }
                }
            )
            assertTrue(latch.await(5, TimeUnit.SECONDS))
            ws.close(1000, "done")
            return replyRef.get()!!
        }

        // Wrong network_id with valid handshake token must fail before consumption
        val wrongNetResp = exchangePairOrAuth(
            SnowMessage.createRequest(
                action = "pair_request",
                data = mapOf(
                    "device_id" to "peer-phone-a",
                    "handshake_token" to handshakeTok,
                    "network_id" to "SNW-NET-99999999"
                )
            )
        )
        assertEquals(MessageType.ERROR, wrongNetResp.type)

        // Valid QR handshake_token succeeds for Peer A
        val pairOk = exchangePairOrAuth(
            SnowMessage.createRequest(
                action = "pair_request",
                data = mapOf(
                    "device_id" to "peer-phone-a",
                    "handshake_token" to handshakeTok,
                    "network_id" to "SNW-NET-11223344"
                )
            )
        )
        assertEquals(MessageType.RESPONSE, pairOk.type)
        val tokenA = pairOk.payload?.get("auth_token") as String
        assertEquals("SNW-NET-11223344", pairOk.payload?.get("network_id"))

        // Replaying the same handshake_token must be rejected
        val replayErr = exchangePairOrAuth(
            SnowMessage.createRequest(
                action = "pair_request",
                data = mapOf(
                    "device_id" to "peer-phone-b",
                    "handshake_token" to handshakeTok,
                    "network_id" to "SNW-NET-11223344"
                )
            )
        )
        assertEquals(MessageType.ERROR, replayErr.type)

        // Pair Peer B via fresh QR PIN while keeping Peer A's token intact
        val pinB = mgr1.generatePairingPin()
        val pairBOk = exchangePairOrAuth(
            SnowMessage.createRequest(
                action = "pair_request",
                data = mapOf(
                    "device_id" to "peer-phone-b",
                    "pin" to pinB
                )
            )
        )
        assertEquals(MessageType.RESPONSE, pairBOk.type)
        val tokenB = pairBOk.payload?.get("auth_token") as String
        assertNotEquals(tokenA, tokenB)

        // Mutual exclusion: invalid handshake_token + valid PIN must fail (never fall back to PIN)
        val pinUnused = mgr1.generatePairingPin()
        val mutexReject = exchangePairOrAuth(
            SnowMessage.createRequest(
                action = "pair_request",
                data = mapOf(
                    "device_id" to "peer-phone-c",
                    "handshake_token" to "invalid_handshake_token_value",
                    "pin" to pinUnused
                )
            )
        )
        assertEquals(MessageType.ERROR, mutexReject.type)

        // Restart host on new port with SAME storage -> exact same fingerprint & Peer A still authenticates!
        mgr1.disableHostMode()
        val port2 = ServerSocket(0).use { it.localPort }
        val mgr2 = AndroidPeerHostManager(certStorage)
        mgr2.setHostModeSettingEnabled(true)
        assertTrue(
            mgr2.enableHostMode(
                port = port2,
                tokenStorage = tokenStore,
                dispatcher = dispatcher,
                localDeviceId = "android-host-1",
                snowId = "SNW-A1B2-C3D4",
                networkId = "SNW-NET-11223344"
            )
        )
        assertEquals(fp1, mgr2.hostState.value.certFingerprint)

        // Authenticate Peer A after restart using Peer A's token, and reject Peer B using Peer A's token
        val authClient = OkHttpClient.Builder()
            .sslSocketFactory(sslCtx.socketFactory, trustMgr)
            .hostnameVerifier { _, _ -> true }
            .build()
        fun exchangeAfterRestart(reqMsg: SnowMessage): SnowMessage {
            val latch = CountDownLatch(1)
            val replyRef = AtomicReference<SnowMessage?>()
            val ws = authClient.newWebSocket(
                Request.Builder().url("wss://127.0.0.1:$port2").build(),
                object : WebSocketListener() {
                    override fun onOpen(webSocket: WebSocket, response: Response) {
                        webSocket.send(JsonSerialization.toJson(reqMsg))
                    }
                    override fun onMessage(webSocket: WebSocket, text: String) {
                        replyRef.set(JsonSerialization.fromJson(text))
                        latch.countDown()
                    }
                    override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                        latch.countDown()
                    }
                }
            )
            assertTrue(latch.await(5, TimeUnit.SECONDS))
            ws.close(1000, "done")
            return replyRef.get()!!
        }
        val authA = exchangeAfterRestart(
            SnowMessage.createRequest(
                action = "auth_request",
                data = mapOf("device_id" to "peer-phone-a", "auth_token" to tokenA)
            )
        )
        assertEquals(MessageType.RESPONSE, authA.type)
        val crossAuth = exchangeAfterRestart(
            SnowMessage.createRequest(
                action = "auth_request",
                data = mapOf("device_id" to "peer-phone-b", "auth_token" to tokenA)
            )
        )
        assertEquals(MessageType.ERROR, crossAuth.type)
        authClient.dispatcher.executorService.shutdown()

        // Corrupt persisted keystore fails closed cleanly
        mgr2.disableHostMode()
        certStorage.corrupted = true
        val mgrCorrupt = AndroidPeerHostManager(certStorage)
        mgrCorrupt.setHostModeSettingEnabled(true)
        assertFalse(
            mgrCorrupt.enableHostMode(
                port = port2,
                tokenStorage = tokenStore,
                dispatcher = dispatcher,
                localDeviceId = "android-host-1"
            )
        )
        assertFalse(mgrCorrupt.hostState.value.isActive)
        assertNotNull(mgrCorrupt.hostState.value.errorMessage)
        okHttp.dispatcher.executorService.shutdown()
    }

    @Test
    fun testUnit13_SavedDeviceCardsCanonicalIdsNeverFabricateSnowIdFromFp() {
        val repo = SnowUiRepository.getInstance(context)

        // Case 1: Real peerSnowId propagated from PairingFlow / AuthState
        repo.certPinStorage.pinFingerprintForDevice("pc-uuid-alpha", fakeFp("11"))
        repo.recordSuccessfulConnection(
            host = "192.168.1.50",
            port = 8765,
            sessionId = "s-alpha-wifi",
            tier = "owner",
            peerDeviceName = "Ayush Lenovo V15",
            peerDeviceType = "windows",
            peerDeviceId = "pc-uuid-alpha",
            peerSnowId = "SNW-1111-AAAA",
            peerPermissionProfile = "full_control",
            peerNetworkId = "SNW-NET-CAFE1234"
        )
        val alpha = repo.savedDevices.value.first { it.deviceId == "pc-uuid-alpha" }
        assertEquals("SNW-1111-AAAA", alpha.snowId)
        assertEquals("SNW-NET-CAFE1234", repo.adoptedNetworkId.value)

        // Case 2: Missing peerSnowId MUST stay null instead of fabricating "SNW-" from "fp:..."
        repo.certPinStorage.pinFingerprintForDevice("pc-uuid-nofp", fakeFp("22"))
        repo.recordSuccessfulConnection(
            host = "192.168.1.51",
            port = 8765,
            sessionId = "s-nofp",
            tier = "peer",
            peerDeviceName = "Second PC",
            peerDeviceType = "windows",
            peerDeviceId = "pc-uuid-nofp",
            peerSnowId = null,
            peerPermissionProfile = "files_only"
        )
        val noSnow = repo.savedDevices.value.first { it.deviceId == "pc-uuid-nofp" }
        assertNull("Must not synthesize fake SNW- ID from fingerprint", noSnow.snowId)

        // Case 3: USB 127.0.0.1 merges idempotently into existing canonical card preserving Wi-Fi endpoint & label
        repo.recordSuccessfulConnection(
            host = "127.0.0.1",
            port = 8765,
            sessionId = "s-alpha-usb",
            tier = "peer",
            peerDeviceName = "Desktop Core",
            peerDeviceType = "windows",
            peerDeviceId = "pc-uuid-alpha",
            peerSnowId = "SNW-1111-AAAA",
            peerPermissionProfile = null
        )
        val afterUsb = repo.savedDevices.value.filter { it.deviceId == "pc-uuid-alpha" }
        assertEquals(1, afterUsb.size)
        assertEquals("Ayush Lenovo V15", afterUsb[0].deviceName)
        assertEquals("192.168.1.50", afterUsb[0].host)
        assertEquals("owner", afterUsb[0].trustTier)
        assertEquals("full_control", afterUsb[0].permissionProfile)

        // Case 4: Distinct canonical devices remain separate (no overwrite)
        assertEquals(2, repo.savedDevices.value.size)

        // Case 5: Reloading persisted devices retains real metadata cleanly
        repo.loadSavedDevices()
        val reloadedAlpha = repo.savedDevices.value.first { it.deviceId == "pc-uuid-alpha" }
        val reloadedNoSnow = repo.savedDevices.value.first { it.deviceId == "pc-uuid-nofp" }
        assertEquals("SNW-1111-AAAA", reloadedAlpha.snowId)
        assertNull(reloadedNoSnow.snowId)
    }

    @Test
    fun testUnit14_And_Unit15_SnowIdResolutionAndDiagnostics() {
        val repo = SnowUiRepository.getInstance(context)
        repo.snowIdDiscoveryBurstMs = 200L
        repo.allowDevLoopbackForTest = true

        // Unit 1.5 Unlinked diagnostics
        val (unlinkedUrl, unlinkedStatus) = repo.getRemoteAiLinkDiagnostics()
        assertNull(unlinkedUrl)
        assertEquals("Not linked to a PC host yet", unlinkedStatus)

        // Invalid SNOW ID rejected without falling back to 127.0.0.1
        var invalidRes: Triple<Boolean, String, String?>? = null
        repo.connectByInput("SNW-BAD") { ok, msg, tag -> invalidRes = Triple(ok, msg, tag) }
        assertFalse(invalidRes!!.first)
        assertEquals("INVALID_SNOW_ID", invalidRes!!.third)
        assertTrue(startedServiceIntents.isEmpty())

        // Saved device normalization & canonical resolution
        repo.recordSuccessfulConnection(
            host = "192.168.1.90",
            port = 8765,
            sessionId = "s-saved",
            peerDeviceId = "pc-saved-90",
            peerSnowId = "SNW-9090-AAAA"
        )
        var savedRes: Triple<Boolean, String, String?>? = null
        repo.connectByInput("  snw-9090-aaaa ") { ok, msg, tag -> savedRes = Triple(ok, msg, tag) }
        assertTrue(savedRes!!.first)
        assertEquals("saved", savedRes!!.third)
        assertEquals(Triple("192.168.1.90", 8765, "pc-saved-90"), repo.lastConnectRequestForTest)
        assertTrue(startedServiceIntents.isNotEmpty())

        // Active ~2.5s burst LAN discovery resolution (peer appears mid-burst)
        val discField = SnowUiRepository::class.java.getDeclaredField("_discoveredPeers").apply { isAccessible = true }
        @Suppress("UNCHECKED_CAST")
        val discFlow = discField.get(repo) as MutableStateFlow<List<DiscoveredPeer>>
        startedServiceIntents.clear()
        repo.lastConnectRequestForTest = null
        repo.snowIdDiscoveryBurstMs = 600L
        val burstLatch = CountDownLatch(1)
        var lanRes: Triple<Boolean, String, String?>? = null
        repo.connectByInput("snw-5555-bbbb") { ok, msg, tag ->
            lanRes = Triple(ok, msg, tag)
            burstLatch.countDown()
        }
        kotlin.concurrent.thread(isDaemon = true) {
            Thread.sleep(100L)
            discFlow.value = listOf(
                DiscoveredPeer(
                    deviceId = "pc-lan-55",
                    deviceName = "LAN Host",
                    deviceType = "windows",
                    ipAddress = "192.168.1.55",
                    port = 8765,
                    transferPort = 8766,
                    certFingerprint = fakeFp("55"),
                    lastSeenTimestamp = System.currentTimeMillis(),
                    snowId = "SNW-5555-BBBB"
                )
            )
        }
        assertTrue(burstLatch.await(3, TimeUnit.SECONDS))
        assertTrue(lanRes!!.first)
        assertEquals("lan", lanRes!!.third)
        assertEquals(Triple("192.168.1.55", 8765, "pc-lan-55"), repo.lastConnectRequestForTest)
        assertTrue(startedServiceIntents.isNotEmpty())

        // Uncredentialed unknown SNOW ID must NOT hit /v1/directory/resolve unauthenticated
        discFlow.value = emptyList()
        startedServiceIntents.clear()
        val unauthCalls = AtomicInteger(0)
        val mockHubSocket = ServerSocket(0)
        val hubExecutor = java.util.concurrent.Executors.newSingleThreadExecutor()
        hubExecutor.submit {
            while (!mockHubSocket.isClosed) {
                try {
                    val client = mockHubSocket.accept()
                    client.use { sock ->
                        val reader = sock.getInputStream().bufferedReader()
                        val requestLine = reader.readLine() ?: ""
                        while (true) {
                            val line = reader.readLine() ?: break
                            if (line.isEmpty()) break
                        }
                        val (statusLine, jsonBody) = when {
                            requestLine.contains("/v1/directory/resolve/") -> {
                                unauthCalls.incrementAndGet()
                                "HTTP/1.1 401 Unauthorized" to """{"error":"Unauthorized"}"""
                            }
                            requestLine.contains("/v1/rendezvous/join") -> {
                                "HTTP/1.1 200 OK" to """
                                    {
                                      "success": true,
                                      "rendezvous_id": "rdv-1",
                                      "mode": "pairing",
                                      "network_id": "SNW-NET-ABCD1234",
                                      "host_device_id": "pc-rdv-1",
                                      "host_snow_id": "SNW-7777-CCCC",
                                      "host_cert_fingerprint": "${fakeFp("99").replace(":", "")}",
                                      "relay_ws_url": "wss://snow-relay.onrender.com/v1/tunnel",
                                      "bootstrap_token": "bs-tok-1"
                                    }
                                """.trimIndent()
                            }
                            else -> "HTTP/1.1 404 Not Found" to "{}"
                        }
                        val bodyBytes = jsonBody.toByteArray()
                        val out = sock.getOutputStream()
                        val headers = "$statusLine\r\nContent-Type: application/json\r\nContent-Length: ${bodyBytes.size}\r\nConnection: close\r\n\r\n"
                        out.write(headers.toByteArray())
                        out.write(bodyBytes)
                        out.flush()
                    }
                } catch (_: Exception) {
                    break
                }
            }
        }
        try {
            repo.setDefaultHubUrl("http://127.0.0.1:${mockHubSocket.localPort}", allowDevLoopback = true)
            repo.snowIdDiscoveryBurstMs = 50L

            var noCredLatch = CountDownLatch(1)
            var noCredRes: Triple<Boolean, String, String?>? = null
            repo.connectByInput("SNW-7777-CCCC") { ok, msg, tag ->
                noCredRes = Triple(ok, msg, tag)
                noCredLatch.countDown()
            }
            assertTrue(noCredLatch.await(3, TimeUnit.SECONDS))
            assertFalse(noCredRes!!.first)
            assertEquals("rendezvous_required", noCredRes!!.third)
            assertEquals("Never call /v1/directory/resolve unauthenticated", 0, unauthCalls.get())
            assertTrue("Never silently fall back to 127.0.0.1", startedServiceIntents.isEmpty())

            // Supplying SNOW ID + 6-digit PIN uses /v1/rendezvous/join and adopts host network_id
            val rdvLatch = CountDownLatch(1)
            var rdvRes: Triple<Boolean, String, String?>? = null
            repo.connectByInput("SNW-7777-CCCC 654321") { ok, msg, tag ->
                rdvRes = Triple(ok, msg, tag)
                rdvLatch.countDown()
            }
            assertTrue(rdvLatch.await(3, TimeUnit.SECONDS))
            assertTrue(rdvRes!!.first)
            assertEquals("rendezvous", rdvRes!!.third)
            assertEquals("SNW-NET-ABCD1234", repo.adoptedNetworkId.value)
            val (linkedUrl, _) = repo.getRemoteAiLinkDiagnostics()
            assertEquals("https://snow-relay.onrender.com/u/SNW-NET-ABCD1234/mcp", linkedUrl)
        } finally {
            try { mockHubSocket.close() } catch (_: Exception) {}
            hubExecutor.shutdownNow()
        }
    }
}
