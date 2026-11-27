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
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.setMain
import org.java_websocket.WebSocket
import org.java_websocket.handshake.ClientHandshake
import org.java_websocket.server.WebSocketServer
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.snow.protocol.ErrorCode
import org.snow.protocol.SnowError
import org.snow.security.AndroidSelfSignedCertGenerator
import org.snow.security.DeviceIdentity
import org.snow.security.InMemoryCertPinStorage
import org.snow.security.InMemoryPeerHostCertStorage
import org.snow.security.InMemoryTokenStorage
import org.snow.ui.SnowUiRepository
import java.io.BufferedInputStream
import java.io.File
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.security.KeyStore
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import javax.net.ssl.KeyManagerFactory
import kotlin.concurrent.thread

/**
 * M4.3 Stage 1 (Carry-Forward Verification):
 * - FIX 1: SnowUiRepository.connectByInput() with manual "SNOW_ID PIN" invokes
 *   completeRendezvousPairingOverTunnel() and never reports premature success on HTTP /join.
 * - FIX 2: SnowUiRepository.completeRendezvousPairingOverTunnel() uses deterministic lexical
 *   TLS role selection (identity.deviceId < hostDevId), supplies persisted keyManagers in TLS
 *   server role, fails closed on corrupted key material, and completes both UUID orderings.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class M43Unit0CarryForwardFixTest {

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

    private fun seedAndroidDeviceId(deviceId: String) {
        context.getSharedPreferences(DeviceIdentity.PREFS_NAME, Context.MODE_PRIVATE)
            .edit()
            .putString(DeviceIdentity.KEY_DEVICE_ID, deviceId)
            .putString(DeviceIdentity.KEY_DEVICE_NAME, "Test Android Peer")
            .putString(DeviceIdentity.KEY_CREATED_AT, "2026-11-27T00:00:00Z")
            .commit()
    }

    private fun startLoopbackRelayServer(port: Int): WebSocketServer {
        val conns = ConcurrentHashMap<String, WebSocket>()
        return object : WebSocketServer(InetSocketAddress("127.0.0.1", port)) {
            override fun onStart() {}
            override fun onOpen(conn: WebSocket, handshake: ClientHandshake) {}
            override fun onClose(conn: WebSocket, code: Int, reason: String?, remote: Boolean) {
                conns.entries.removeIf { it.value == conn }
            }
            override fun onMessage(conn: WebSocket, message: String) {
                val json = JSONObject(message)
                when (json.optString("type")) {
                    "hello" -> {
                        val devId = json.getString("device_id")
                        conns[devId] = conn
                        conn.send(JSONObject().apply {
                            put("type", "hello_ack")
                            put("success", true)
                            put("device_id", devId)
                        }.toString())
                    }
                    "relay_frame" -> {
                        val target = json.getString("target")
                        val sender = conns.entries.firstOrNull { it.value == conn }?.key ?: ""
                        conns[target]?.send(JSONObject().apply {
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
    }

    private fun buildKeyManagers(storage: InMemoryPeerHostCertStorage): Pair<String, Array<javax.net.ssl.KeyManager>> {
        val res = AndroidSelfSignedCertGenerator.loadOrCreate(storage)
        val (p12Bytes, p12Pass) = storage.loadKeyStoreMaterial()!!
        val ks = KeyStore.getInstance("PKCS12").apply { load(p12Bytes.inputStream(), p12Pass) }
        val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).apply { init(ks, p12Pass) }
        return res.fingerprint.replace(":", "") to kmf.keyManagers
    }

    @Before
    fun setUp() {
        mainExecutor = java.util.concurrent.Executors.newSingleThreadExecutor()
        mainDispatcher = mainExecutor.asCoroutineDispatcher()
        Dispatchers.setMain(mainDispatcher)
        resetRepoSingleton()
        prefsByName.clear()
        tempDir = File(System.getProperty("java.io.tmpdir"), "snow_m43_u0_${UUID.randomUUID()}").apply { mkdirs() }
        context = object : ContextWrapper(null) {
            override fun getApplicationContext(): Context = this
            override fun getFilesDir(): File = tempDir
            override fun getCacheDir(): File = tempDir
            override fun getExternalFilesDir(type: String?): File = File(tempDir, "ext_${type ?: "default"}").apply { mkdirs() }
            override fun getPackageName(): String = "org.snow"
            override fun getSharedPreferences(name: String?, mode: Int): SharedPreferences =
                prefsByName.getOrPut(name ?: "default") { MemPrefs() }
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
    fun testFix1_ManualSnowIdPinInvokesE2eTunnelAndRejectsPrematureSuccess() {
        val androidId = "11111111-1111-4111-8111-111111111111"
        val hostId = "ffffffff-ffff-4fff-8fff-ffffffffffff"
        val hostSnowId = "SNW-H111-2222"
        seedAndroidDeviceId(androidId)

        val hostCertStore = InMemoryPeerHostCertStorage()
        val (hostFp, hostKms) = buildKeyManagers(hostCertStore)
        val relayPort = freeTcpPort()
        val relayServer = startLoopbackRelayServer(relayPort)
        Thread.sleep(200)

        val hubServer = ServerSocket(0, 8, InetAddress.getByName("127.0.0.1"))
        val hubPort = hubServer.localPort
        val hubRunning = AtomicBoolean(true)
        val hubThread = thread(isDaemon = true) {
            while (hubRunning.get() && !hubServer.isClosed) {
                try {
                    hubServer.accept().use { sock ->
                        val inp = BufferedInputStream(sock.getInputStream())
                        val headerBuf = StringBuilder()
                        var cur: Int
                        var contentLen = 0
                        while (true) {
                            cur = inp.read()
                            if (cur == -1) break
                            headerBuf.append(cur.toChar())
                            if (headerBuf.endsWith("\r\n\r\n")) break
                        }
                        headerBuf.toString().lines().forEach { ln ->
                            if (ln.startsWith("Content-Length:", ignoreCase = true)) {
                                contentLen = ln.substringAfter(":").trim().toIntOrNull() ?: 0
                            }
                        }
                        val bodyBytes = if (contentLen > 0) ByteArray(contentLen).also { buf ->
                            var read = 0
                            while (read < contentLen) {
                                val n = inp.read(buf, read, contentLen - read)
                                if (n <= 0) break
                                read += n
                            }
                        } else ByteArray(0)
                        val reqJson = if (bodyBytes.isNotEmpty()) JSONObject(String(bodyBytes, Charsets.UTF_8)) else JSONObject()
                        val okJson = JSONObject().apply {
                            put("success", true)
                            put("rendezvous_id", "rdv-fix1")
                            put("mode", "pair")
                            put("network_id", "SNW-NET-F1112222")
                            put("host_device_id", hostId)
                            put("host_snow_id", reqJson.optString("snow_id", hostSnowId))
                            put("host_cert_fingerprint", hostFp)
                            put("relay_ws_url", "ws://127.0.0.1:$relayPort/v1/tunnel")
                            put("bootstrap_token", "bs-tok-fix1")
                        }.toString().toByteArray(Charsets.UTF_8)
                        val respHeader = (
                            "HTTP/1.1 200 OK\r\n" +
                                "Content-Type: application/json\r\n" +
                                "Content-Length: ${okJson.size}\r\n" +
                                "Connection: close\r\n\r\n"
                            ).toByteArray(Charsets.UTF_8)
                        sock.getOutputStream().write(respHeader)
                        sock.getOutputStream().write(okJson)
                        sock.getOutputStream().flush()
                    }
                } catch (_: Exception) {
                }
            }
        }

        val hostRelayClient = RelayClient(
            relayUrl = "ws://127.0.0.1:$relayPort/v1/tunnel",
            deviceId = hostId,
            groupId = "SNW-NET-F1112222",
            ticket = "",
            targetPeerId = androidId,
            certPinStorage = InMemoryCertPinStorage(),
            expectedPeerFingerprint = null,
            isClientMode = (hostId < androidId),
            scope = scope,
            hubToken = "hub-tok-host",
            networkId = "SNW-NET-F1112222"
        ).apply {
            keyManagers = hostKms
            requestDispatcher = { action, data ->
                if (action == "pair_request" && data?.get("pin") == "654321") {
                    Pair(
                        mapOf(
                            "status" to "success",
                            "action" to "pair_response",
                            "session_id" to "sess-fix1",
                            "device_id" to hostId,
                            "server_device_id" to hostId,
                            "device_name" to "Fix1 Host PC",
                            "device_type" to "windows",
                            "auth_token" to "auth-tok-fix1-0001",
                            "trust_tier" to "owner",
                            "network_id" to "SNW-NET-F1112222",
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

        val repo = SnowUiRepository.getInstance(context).apply {
            tokenStorageOverrideForTest = InMemoryTokenStorage()
            certPinStorageOverrideForTest = InMemoryCertPinStorage()
            peerHostCertStorageOverrideForTest = InMemoryPeerHostCertStorage()
            allowDevLoopbackForTest = true
            snowIdDiscoveryBurstMs = 0L
            setDefaultHubUrl("http://127.0.0.1:$hubPort", allowDevLoopback = true)
        }

        try {
            // Part A: If E2E tunnel pairing fails, connectByInput MUST NOT report premature success
            val hookCalled = AtomicBoolean(false)
            repo.customRendezvousTunnelPairerForTest = { rdv, pin, _, cb ->
                hookCalled.set(true)
                assertEquals("654321", pin)
                assertEquals(hostId, rdv["host_device_id"])
                cb(false, "Simulated E2E TLS tunnel failure")
            }
            val failLatch = CountDownLatch(1)
            val failOutcome = AtomicReference<Triple<Boolean, String, String?>>()
            repo.connectByInput("$hostSnowId 654321") { ok, msg, tag ->
                failOutcome.set(Triple(ok, msg, tag))
                failLatch.countDown()
            }
            assertTrue(failLatch.await(5, TimeUnit.SECONDS))
            assertTrue("Manual SNOW ID + PIN must invoke E2E tunnel pairing", hookCalled.get())
            assertFalse(failOutcome.get().first)
            assertEquals("hub_auth_failed", failOutcome.get().third)
            assertTrue(repo.savedDevices.value.isEmpty())
            assertNull(repo.adoptedNetworkId.value)

            // Part B: End-to-end real loopback E2E TLS tunnel pairing completes & persists peer
            repo.customRendezvousTunnelPairerForTest = null
            hostRelayClient.connect()
            Thread.sleep(250)

            val okLatch = CountDownLatch(1)
            val okOutcome = AtomicReference<Triple<Boolean, String, String?>>()
            repo.connectByInput("$hostSnowId 654321") { ok, msg, tag ->
                okOutcome.set(Triple(ok, msg, tag))
                okLatch.countDown()
            }
            assertTrue(okLatch.await(8, TimeUnit.SECONDS))
            assertTrue(okOutcome.get().second, okOutcome.get().first)
            assertEquals("rendezvous", okOutcome.get().third)
            assertEquals("SNW-NET-F1112222", repo.adoptedNetworkId.value)
            assertTrue(repo.savedDevices.value.any { it.deviceId == hostId })
        } finally {
            hostRelayClient.disconnect()
            relayServer.stop(500)
            hubRunning.set(false)
            hubServer.close()
            hubThread.join(1000)
        }
    }

    @Test
    fun testFix2_DeterministicTlsRolesComplimentaryInBothDeviceIdOrderings() {
        runDeterministicRolePairingCase(
            androidDevId = "11111111-1111-4111-8111-111111111111",
            hostDevId = "ffffffff-ffff-4fff-8fff-ffffffffffff",
            expectedAndroidClientMode = true
        )
        resetRepoSingleton()
        prefsByName.clear()
        runDeterministicRolePairingCase(
            androidDevId = "ffffffff-ffff-4fff-8fff-ffffffffffff",
            hostDevId = "11111111-1111-4111-8111-111111111111",
            expectedAndroidClientMode = false
        )
    }

    private fun runDeterministicRolePairingCase(
        androidDevId: String,
        hostDevId: String,
        expectedAndroidClientMode: Boolean
    ) {
        assertEquals(expectedAndroidClientMode, androidDevId < hostDevId)
        assertEquals(!expectedAndroidClientMode, hostDevId < androidDevId)

        seedAndroidDeviceId(androidDevId)
        val androidCertStore = InMemoryPeerHostCertStorage()
        AndroidSelfSignedCertGenerator.loadOrCreate(androidCertStore)

        val hostCertStore = InMemoryPeerHostCertStorage()
        val (hostFp, hostKms) = buildKeyManagers(hostCertStore)

        val relayPort = freeTcpPort()
        val relayServer = startLoopbackRelayServer(relayPort)
        Thread.sleep(200)

        val repo = SnowUiRepository.getInstance(context).apply {
            tokenStorageOverrideForTest = InMemoryTokenStorage()
            certPinStorageOverrideForTest = InMemoryCertPinStorage()
            peerHostCertStorageOverrideForTest = androidCertStore
        }

        val hostRelayClient = RelayClient(
            relayUrl = "ws://127.0.0.1:$relayPort/v1/tunnel",
            deviceId = hostDevId,
            groupId = "SNW-NET-D1234567",
            ticket = "",
            targetPeerId = androidDevId,
            certPinStorage = null,
            expectedPeerFingerprint = null,
            isClientMode = (hostDevId < androidDevId),
            scope = scope,
            hubToken = "hub-tok-role",
            networkId = "SNW-NET-D1234567"
        ).apply {
            keyManagers = hostKms
            requestDispatcher = { action, data ->
                if (action == "pair_request" && data?.get("pin") == "334455") {
                    Pair(
                        mapOf(
                            "status" to "success",
                            "action" to "pair_response",
                            "session_id" to "sess-role",
                            "device_id" to hostDevId,
                            "server_device_id" to hostDevId,
                            "device_name" to "Role Peer Host",
                            "device_type" to "windows",
                            "auth_token" to "role-auth-tok-0001",
                            "trust_tier" to "owner",
                            "network_id" to "SNW-NET-D1234567",
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

            val doneLatch = CountDownLatch(1)
            val outcome = AtomicReference<Pair<Boolean, String?>>()
            repo.completeRendezvousPairingOverTunnel(
                rdvData = mapOf(
                    "relay_ws_url" to "ws://127.0.0.1:$relayPort/v1/tunnel",
                    "host_device_id" to hostDevId,
                    "host_cert_fingerprint" to hostFp,
                    "bootstrap_token" to "bs-role-tok",
                    "network_id" to "SNW-NET-D1234567",
                    "host_device_type" to "windows",
                    "host_transfer_port" to 8766
                ),
                pin = "334455"
            ) { ok, err ->
                outcome.set(ok to err)
                doneLatch.countDown()
            }
            assertTrue("Pairing timed out for isClient=$expectedAndroidClientMode", doneLatch.await(8, TimeUnit.SECONDS))
            assertTrue(outcome.get()?.second ?: "ok", outcome.get()!!.first)
            assertTrue(repo.savedDevices.value.any { it.deviceId == hostDevId })
        } finally {
            hostRelayClient.disconnect()
            relayServer.stop(500)
        }
    }

    @Test
    fun testFix2_ServerRoleFailsClosedWhenPersistedTlsKeyMaterialCorrupt() {
        val androidDevId = "ffffffff-ffff-4fff-8fff-ffffffffffff"
        val hostDevId = "11111111-1111-4111-8111-111111111111"
        assertTrue(androidDevId > hostDevId)
        seedAndroidDeviceId(androidDevId)

        val corruptCertStore = InMemoryPeerHostCertStorage().apply {
            saveKeyStoreMaterial("corrupt-pkcs12-bytes".toByteArray(), "bad".toCharArray())
        }
        val repo = SnowUiRepository.getInstance(context).apply {
            tokenStorageOverrideForTest = InMemoryTokenStorage()
            certPinStorageOverrideForTest = InMemoryCertPinStorage()
            peerHostCertStorageOverrideForTest = corruptCertStore
        }

        val latch = CountDownLatch(1)
        val outcome = AtomicReference<Pair<Boolean, String?>>()
        repo.completeRendezvousPairingOverTunnel(
            rdvData = mapOf(
                "relay_ws_url" to "ws://127.0.0.1:1/v1/tunnel",
                "host_device_id" to hostDevId,
                "host_cert_fingerprint" to "AA".repeat(32),
                "bootstrap_token" to "bs-tok-bad",
                "network_id" to "SNW-NET-BAD00001"
            ),
            pin = "112233"
        ) { ok, err ->
            outcome.set(ok to err)
            latch.countDown()
        }
        assertTrue(latch.await(3, TimeUnit.SECONDS))
        assertFalse(outcome.get()!!.first)
        assertTrue(outcome.get()!!.second?.contains("server role", ignoreCase = true) == true)
    }
}
