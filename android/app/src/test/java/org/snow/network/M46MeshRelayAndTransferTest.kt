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
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.cancel
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.setMain
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
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
import org.snow.capabilities.AndroidFileHandler
import org.snow.capabilities.LiveScreenStreamHandler
import org.snow.capabilities.ScreenTargetEndpoint
import org.snow.security.AndroidSelfSignedCertGenerator
import org.snow.security.DeviceIdentity
import org.snow.security.InMemoryCertPinStorage
import org.snow.security.InMemoryPeerHostCertStorage
import org.snow.security.InMemoryTokenStorage
import org.snow.security.SnowTrustManager
import org.snow.security.TlsConfig
import org.snow.transfer.FileTransferClient
import org.snow.ui.ActiveTransferInfo
import org.snow.ui.SavedDevice
import org.snow.ui.SnowIdStep1Result
import org.snow.ui.SnowUiRepository
import org.snow.ui.TargetDeviceType
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.File
import java.net.ServerSocket
import java.security.MessageDigest
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.SSLSocket

/**
 * Milestone 4.6 Android Mesh, Always-On Relay, Multi-Target Screen Fan-Out,
 * Concurrent Transfers, Fast SAF/Storage Sandboxing & 2-Step SNOW ID -> PIN Resolution Tests.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class M46MeshRelayAndTransferTest {

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
            override fun apply() {
                commit()
            }
        }
        override fun registerOnSharedPreferenceChangeListener(listener: SharedPreferences.OnSharedPreferenceChangeListener?) {}
        override fun unregisterOnSharedPreferenceChangeListener(listener: SharedPreferences.OnSharedPreferenceChangeListener?) {}
    }

    private lateinit var mainExecutor: ExecutorService
    private val prefsByName = ConcurrentHashMap<String, MemPrefs>()
    private lateinit var tempDir: File
    private lateinit var context: Context
    private lateinit var ioScope: CoroutineScope

    private fun resetRepoSingleton() {
        val f = SnowUiRepository::class.java.getDeclaredField("instance")
        f.isAccessible = true
        f.set(null, null)
    }

    private fun freeTcpPort(): Int {
        ServerSocket(0).use { return it.localPort }
    }

    private fun sha256Hex(bytes: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(bytes)
        return digest.joinToString("") { "%02x".format(it) }
    }

    @Before
    fun setUp() {
        mainExecutor = Executors.newSingleThreadExecutor()
        val dispatcher = mainExecutor.asCoroutineDispatcher()
        Dispatchers.setMain(dispatcher)
        resetRepoSingleton()
        prefsByName.clear()
        tempDir = File(System.getProperty("java.io.tmpdir"), "snow_m46_${UUID.randomUUID()}").apply { mkdirs() }
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
        ioScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        LiveScreenStreamHandler.mockFrameProvider = null
        LiveScreenStreamHandler.mockFramePoster = null
        LiveScreenStreamHandler.mockTargetFramePoster = null
    }

    @After
    fun tearDown() {
        LiveScreenStreamHandler.mockFrameProvider = null
        LiveScreenStreamHandler.mockFramePoster = null
        LiveScreenStreamHandler.mockTargetFramePoster = null
        resetRepoSingleton()
        ioScope.cancel()
        Dispatchers.resetMain()
        mainExecutor.shutdownNow()
        tempDir.deleteRecursively()
    }

    @Test
    fun testInboundPeerAuthAndDisconnectCallbacksAndDynamicPeerCount() {
        val hostStorage = InMemoryPeerHostCertStorage()
        val hostManager = AndroidPeerHostManager(hostStorage)
        val hostTokens = InMemoryTokenStorage()
        val capDispatcher = AndroidCapabilityDispatcher(context, transferClientProvider = { null })
        val hostPort = freeTcpPort()
        val mediaPort = freeTcpPort()

        val authLatch = CountDownLatch(1)
        val disconnectLatch = CountDownLatch(1)
        val authEventRef = AtomicReference<PeerAuthEvent?>(null)
        val disconnectedIdRef = AtomicReference<String?>(null)
        val rendezvousPinRef = AtomicReference<String?>(null)
        val rendezvousLatch = CountDownLatch(1)

        hostManager.rendezvousRegistrar = { pin, _, snowId, netId, ttl ->
            if (snowId == "SNW-HOST-1111" && !netId.isNullOrBlank() && ttl in 10..120) {
                rendezvousPinRef.set(pin)
                rendezvousLatch.countDown()
            }
        }
        hostManager.onPeerAuthenticated = { ev ->
            authEventRef.set(ev)
            authLatch.countDown()
        }
        hostManager.onPeerDisconnected = { pid ->
            disconnectedIdRef.set(pid)
            disconnectLatch.countDown()
        }

        hostManager.setHostModeSettingEnabled(true)
        val started = hostManager.enableHostMode(
            port = hostPort,
            tokenStorage = hostTokens,
            dispatcher = capDispatcher,
            localDeviceId = "phone-host-m46",
            parentScope = ioScope,
            mediaPort = mediaPort,
            snowId = "SNW-HOST-1111",
            networkId = "SNW-NET-AABB1122"
        )
        assertTrue("Host mode must start on ephemeral port", started)
        assertEquals(0, hostManager.hostState.value.peerCount)

        val pin = hostManager.generatePairingPin()
        assertEquals(6, pin.length)
        assertTrue("Rendezvous slot should register asynchronously on PIN generation", rendezvousLatch.await(4, TimeUnit.SECONDS))
        assertEquals(pin, rendezvousPinRef.get())

        val peerPinStorage = InMemoryCertPinStorage()
        val peerTokenStorage = InMemoryTokenStorage()
        val hostFp = hostManager.hostState.value.certFingerprint
        peerPinStorage.pinFingerprintForDevice("phone-host-m46", hostFp)

        val peerDevUuid = "4b8b8e21-2222-4333-8444-555566667777"
        val peerIdentity = DeviceIdentity(peerDevUuid, "Phone B", "2026-11-28T00:00:00Z")
        val wsClient = SnowWebSocketClient(
            certPinStorage = peerPinStorage,
            tokenStorage = peerTokenStorage,
            identity = peerIdentity,
            useTls = true,
            scope = ioScope
        )

        val connectedLatch = CountDownLatch(1)
        val pairedLatch = CountDownLatch(1)
        val authWatcher = ioScope.async {
            wsClient.authState.collect { st ->
                if (st is AuthState.ConnectedUnauthenticated) {
                    connectedLatch.countDown()
                }
            }
        }

        try {
            wsClient.connect(
                host = "127.0.0.1",
                port = hostPort,
                targetDeviceId = "phone-host-m46",
                mode = ConnectionHandshakeMode.EXPLICIT_PAIRING_INITIATOR
            )
            assertTrue("Client should reach ConnectedUnauthenticated", connectedLatch.await(5, TimeUnit.SECONDS))

            wsClient.sendRequest(
                action = "pair_request",
                data = mapOf(
                    "device_id" to peerDevUuid,
                    "device_name" to "Phone B",
                    "device_type" to "android",
                    "snow_id" to "SNW-PEER-2222",
                    "pin" to pin,
                    "transfer_port" to 8769,
                    "client_network_id" to "SNW-NET-AABB1122"
                )
            ) { msg ->
                if (msg.isSuccess) {
                    pairedLatch.countDown()
                }
            }

            assertTrue("Pairing response must succeed", pairedLatch.await(5, TimeUnit.SECONDS))
            assertTrue("onPeerAuthenticated must fire", authLatch.await(5, TimeUnit.SECONDS))
            val ev = authEventRef.get()
            assertNotNull(ev)
            assertEquals(peerDevUuid, ev!!.peerDeviceId)
            assertEquals("Phone B", ev.peerDeviceName)
            assertEquals("android", ev.peerDeviceType)
            assertEquals("SNW-PEER-2222", ev.peerSnowId)
            assertEquals(8769, ev.transferPort)
            assertEquals("SNW-NET-AABB1122", ev.networkId)
            assertTrue(ev.isNewPairing)
            assertEquals(1, hostManager.hostState.value.peerCount)

            wsClient.disconnect()
            assertTrue("onPeerDisconnected must fire on socket close", disconnectLatch.await(5, TimeUnit.SECONDS))
            assertEquals(peerDevUuid, disconnectedIdRef.get())
            assertEquals(0, hostManager.hostState.value.peerCount)
        } finally {
            authWatcher.cancel()
            wsClient.teardown()
            hostManager.disableHostMode()
        }
    }

    @Test
    fun testRepoRelayDefaultTrueAndBidirectionalInboundPeerSync() {
        val repo = SnowUiRepository.getInstance(context)
        repo.certPinStorageOverrideForTest = InMemoryCertPinStorage()
        repo.tokenStorageOverrideForTest = InMemoryTokenStorage()

        assertTrue("Remote relay MUST default to true in M4.6", repo.isRemoteRelayEnabled())
        assertEquals(TargetDeviceType.NONE, repo.resolveTargetDeviceType())

        repo.onInboundPeerAuthenticated(
            PeerAuthEvent(
                peerDeviceId = "phone-b-inbound",
                peerDeviceName = "Pixel Peer",
                peerDeviceType = "android",
                peerSnowId = "SNW-BBBB-1234",
                peerHost = "192.168.1.55",
                transferPort = 8769,
                peerPort = 8767,
                networkId = "SNW-NET-DEADBEEF",
                authToken = "tok-inbound-123",
                isNewPairing = true
            )
        )

        assertEquals(ConnectionState.CONNECTED, repo.uiConnectionState.value)
        assertEquals("SNW-NET-DEADBEEF", repo.adoptedNetworkId.value)
        assertTrue(repo.savedDevices.value.any { it.deviceId == "phone-b-inbound" && it.isPhone && it.transferPort == 8769 })
        assertEquals(TargetDeviceType.ANDROID_PEER, repo.resolveTargetDeviceType())

        val pcDevice = SavedDevice(
            deviceId = "pc-win-1",
            deviceName = "Workstation",
            host = "192.168.1.10",
            port = 8765,
            deviceType = "pc",
            transferPort = 8766
        )
        assertEquals(TargetDeviceType.WINDOWS_PC, repo.resolveTargetDeviceType(pcDevice, ConnectionState.CONNECTED))
        assertEquals(TargetDeviceType.NONE, repo.resolveTargetDeviceType(pcDevice, ConnectionState.DISCONNECTED))

        // Screen fan-out endpoint resolution remains independent of active Home device selection
        repo.selectTargetDevice("phone-b-inbound")
        val fanOutEndpoints = repo.buildScreenTargetEndpoints(listOf("pc-win-1", "phone-b-inbound"))
        // Adding pc-win-1 to savedDevices lets buildScreenTargetEndpoints resolve both independently
        repo.recordSuccessfulConnection(
            host = "192.168.1.10",
            port = 8765,
            sessionId = "sess-pc",
            peerDeviceName = "Workstation",
            peerDeviceType = "pc",
            peerDeviceId = "pc-win-1",
            peerTransferPort = 8766,
            peerPermissionProfile = "full_control"
        )
        val bothEndpoints = repo.buildScreenTargetEndpoints(listOf("pc-win-1", "phone-b-inbound"))
        assertEquals(2, bothEndpoints.size)
        assertEquals(8766, bothEndpoints.first { it.deviceId == "pc-win-1" }.transferPort)
        assertEquals(8769, bothEndpoints.first { it.deviceId == "phone-b-inbound" }.transferPort)
        assertEquals(0, fanOutEndpoints.count { it.deviceId == "pc-win-1" })

        repo.onInboundPeerDisconnected("phone-b-inbound")
        assertEquals(ConnectionState.DISCONNECTED, repo.uiConnectionState.value)
    }

    @Test
    fun testLiveScreenStreamHandlerConcurrentMultiTargetFanOutViaMockFramePoster() = runBlocking {
        val handler = LiveScreenStreamHandler(context) { null }
        val targets = listOf(
            ScreenTargetEndpoint(deviceId = "pc-1", host = "192.168.1.10", transferPort = 8766, useRelay = false),
            ScreenTargetEndpoint(deviceId = "phone-2", host = "192.168.1.20", transferPort = 8769, useRelay = false),
            ScreenTargetEndpoint(deviceId = "relay-3", host = "", transferPort = 8766, useRelay = true)
        )
        val jpegSample = byteArrayOf(0xFF.toByte(), 0xD8.toByte(), 0x42, 0xFF.toByte(), 0xD9.toByte())

        val concurrentBarrier = CountDownLatch(targets.size)
        val invokedCount = AtomicInteger(0)
        LiveScreenStreamHandler.mockFramePoster = { bytes, sess, w, h, fps ->
            assertEquals("sess-m46", sess)
            assertEquals(720, w)
            assertEquals(1280, h)
            assertEquals(2.0f, fps, 0.001f)
            assertTrue(bytes.contentEquals(jpegSample))
            invokedCount.incrementAndGet()
            concurrentBarrier.countDown()
            // Prove true concurrent execution across all 3 targets simultaneously
            concurrentBarrier.await(2, TimeUnit.SECONDS)
        }

        val okMockPoster = handler.transmitFrameToTargets(
            targets = targets,
            frameBytes = jpegSample,
            sessionId = "sess-m46",
            width = 720,
            height = 1280,
            fps = 2.0f,
            senderDeviceId = "phone-a",
            senderName = "Phone A",
            frameSeq = 1L
        )
        assertTrue(okMockPoster)
        assertEquals(3, invokedCount.get())

        LiveScreenStreamHandler.mockFramePoster = null
        val capturedTargets = CopyOnWriteArrayList<ScreenTargetEndpoint>()
        LiveScreenStreamHandler.mockTargetFramePoster = { ep, bytes, _, _, _, _ ->
            assertTrue(bytes.contentEquals(jpegSample))
            capturedTargets.add(ep)
            true
        }

        val okTypedPoster = handler.transmitFrameToTargets(
            targets = targets,
            frameBytes = jpegSample,
            sessionId = "sess-m46",
            width = 720,
            height = 1280,
            fps = 2.0f,
            senderDeviceId = "phone-a",
            senderName = "Phone A",
            frameSeq = 2L
        )
        assertTrue(okTypedPoster)
        assertEquals(3, capturedTargets.size)
        assertTrue(capturedTargets.any { it.deviceId == "pc-1" && it.transferPort == 8766 && !it.useRelay })
        assertTrue(capturedTargets.any { it.deviceId == "phone-2" && it.transferPort == 8769 && !it.useRelay })
        assertTrue(capturedTargets.any { it.deviceId == "relay-3" && it.useRelay })
    }

    @Test
    fun testAndroidPeerMediaServerStatusAuthAnd403ProfileEnforcement() {
        val certResult = AndroidSelfSignedCertGenerator.loadOrCreate(InMemoryPeerHostCertStorage())
        val tokenStorage = InMemoryTokenStorage()
        val devFull = "phone-full"
        val devRestricted = "phone-files-only"
        val tokFull = "secret-full-control-token"
        val tokRestricted = "secret-files-only-token"
        tokenStorage.saveTokenForDevice(devFull, tokFull)
        tokenStorage.saveTokenForDevice(devRestricted, tokRestricted)

        val port = freeTcpPort()
        val mediaServer = AndroidPeerMediaServer(
            requestedPort = port,
            sslContext = certResult.sslContext,
            tokenStorage = tokenStorage,
            storageRootDir = File(tempDir, "media_srv"),
            perDeviceProfileProvider = { devId ->
                if (devId == devFull) "full_control" else "files_only"
            }
        )
        assertTrue(mediaServer.start())

        val pinStorage = InMemoryCertPinStorage().apply {
            pinFingerprintForDevice(devFull, certResult.fingerprint)
        }
        val tm = SnowTrustManager(pinStorage, targetDeviceIdProvider = { devFull })
        val sslCtx = TlsConfig.createSslContext(tm)
        val client = OkHttpClient.Builder()
            .sslSocketFactory(sslCtx.socketFactory, tm)
            .hostnameVerifier(TlsConfig.createHostnameVerifier(pinStorage, targetDeviceIdProvider = { devFull }))
            .build()
        val base = "https://127.0.0.1:${mediaServer.boundPort}"

        try {
            // 1. Unauthenticated /api/v1/screen/status -> 401
            client.newCall(Request.Builder().url("$base/api/v1/screen/status").get().build()).execute().use { resp ->
                assertEquals(401, resp.code)
            }

            // 2. files_only peer attempting /api/v1/screen/status & POST /frame -> 403 PERMISSION_DENIED
            client.newCall(
                Request.Builder()
                    .url("$base/api/v1/screen/status")
                    .addHeader("Authorization", "Bearer $tokRestricted")
                    .addHeader("X-Snow-Device-Id", devRestricted)
                    .get()
                    .build()
            ).execute().use { resp ->
                assertEquals(403, resp.code)
                assertTrue(resp.body?.string().orEmpty().contains("PERMISSION_DENIED"))
            }

            // 3. full_control peer posts a JPEG frame
            val jpeg = byteArrayOf(0xFF.toByte(), 0xD8.toByte(), 0x01, 0xFF.toByte(), 0xD9.toByte())
            client.newCall(
                Request.Builder()
                    .url("$base/api/v1/screen/frame")
                    .addHeader("Authorization", "Bearer $tokFull")
                    .addHeader("X-Snow-Device-Id", devFull)
                    .addHeader("X-Snow-Sender-Name", "Phone Sender")
                    .addHeader("X-Snow-Session-Id", "s123")
                    .addHeader("X-Snow-Frame-Seq", "1")
                    .post(jpeg.toRequestBody("image/jpeg".toMediaType()))
                    .build()
            ).execute().use { resp ->
                assertEquals(200, resp.code)
            }

            // 4. full_control peer queries /api/v1/screen/status -> active=true, sender_count=1
            client.newCall(
                Request.Builder()
                    .url("$base/api/v1/screen/status")
                    .addHeader("Authorization", "Bearer $tokFull")
                    .addHeader("X-Snow-Device-Id", devFull)
                    .get()
                    .build()
            ).execute().use { resp ->
                assertEquals(200, resp.code)
                val obj = JSONObject(resp.body?.string().orEmpty())
                assertTrue(obj.getBoolean("active"))
                assertEquals(1, obj.getInt("sender_count"))
            }

            // 5. full_control peer stops stream -> subsequent /status shows active=false
            client.newCall(
                Request.Builder()
                    .url("$base/api/v1/screen/stop")
                    .addHeader("Authorization", "Bearer $tokFull")
                    .addHeader("X-Snow-Device-Id", devFull)
                    .post(ByteArray(0).toRequestBody("application/json".toMediaType()))
                    .build()
            ).execute().use { resp ->
                assertEquals(200, resp.code)
            }

            client.newCall(
                Request.Builder()
                    .url("$base/api/v1/screen/status")
                    .addHeader("Authorization", "Bearer $tokFull")
                    .addHeader("X-Snow-Device-Id", devFull)
                    .get()
                    .build()
            ).execute().use { resp ->
                assertEquals(200, resp.code)
                val obj = JSONObject(resp.body?.string().orEmpty())
                assertFalse(obj.getBoolean("active"))
                assertEquals(0, obj.getInt("sender_count"))
            }
        } finally {
            mediaServer.stop()
        }
    }

    @Test
    fun testFileTransferClient3ConcurrentDownloadsWithSingleIdCancelIsolation() = runBlocking {
        val certResult = AndroidSelfSignedCertGenerator.loadOrCreate(InMemoryPeerHostCertStorage())
        val hostId = "peer-concurrent-host"
        val pinStorage = InMemoryCertPinStorage().apply {
            pinFingerprintForDevice(hostId, certResult.fingerprint)
        }
        val tokenStorage = InMemoryTokenStorage().apply {
            saveTokenForDevice(hostId, "tok-conc")
        }

        val payload1 = ByteArray(128 * 1024) { 0x11 }
        val payload2 = ByteArray(96 * 1024) { 0x22 }
        val payload3 = ByteArray(96 * 1024) { 0x33 }
        val sha2 = sha256Hex(payload2)
        val sha3 = sha256Hex(payload3)

        val t1StartedLatch = CountDownLatch(1)
        val running = AtomicBoolean(true)
        val srvSock = certResult.sslContext.serverSocketFactory.createServerSocket(0) as SSLServerSocket
        val srvThread = Thread {
            while (running.get()) {
                try {
                    val sock = srvSock.accept() as SSLSocket
                    Thread {
                        try {
                            sock.soTimeout = 10_000
                            val inp = BufferedInputStream(sock.inputStream)
                            val out = BufferedOutputStream(sock.outputStream)
                            val reader = inp.bufferedReader()
                            val reqLine = reader.readLine() ?: return@Thread
                            while (true) {
                                val h = reader.readLine() ?: break
                                if (h.isEmpty()) break
                            }
                            val path = reqLine.split(" ").getOrNull(1).orEmpty()
                            when {
                                path.endsWith("/t1") -> {
                                    val firstChunk = payload1.copyOfRange(0, 16 * 1024)
                                    val hdr = "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: ${payload1.size}\r\nConnection: close\r\n\r\n"
                                    out.write(hdr.toByteArray())
                                    out.write(firstChunk)
                                    out.flush()
                                    t1StartedLatch.countDown()
                                    // Trickle slowly so explicit cancelTransfer("t1") interrupts mid-flight
                                    var off = firstChunk.size
                                    while (running.get() && off < payload1.size) {
                                        Thread.sleep(100)
                                        val end = minOf(payload1.size, off + 2048)
                                        out.write(payload1, off, end - off)
                                        out.flush()
                                        off = end
                                    }
                                }
                                path.endsWith("/t2") || path.endsWith("/t3") -> {
                                    val bytes = if (path.endsWith("/t2")) payload2 else payload3
                                    val hdr = "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: ${bytes.size}\r\nConnection: close\r\n\r\n"
                                    out.write(hdr.toByteArray())
                                    out.write(bytes)
                                    out.flush()
                                }
                            }
                        } catch (_: Exception) {
                        } finally {
                            try { sock.close() } catch (_: Exception) {}
                        }
                    }.start()
                } catch (_: Exception) {
                    if (!running.get()) break
                }
            }
        }.apply { isDaemon = true; start() }

        val client = FileTransferClient(
            context = context,
            deviceId = "android-test-1",
            certPinStorage = pinStorage,
            tokenStorage = tokenStorage,
            useTls = true,
            targetDeviceIdProvider = { hostId },
            maxRetryAttempts = 0
        )

        try {
            val f1 = File(tempDir, "dl_t1.bin")
            val f2 = File(tempDir, "dl_t2.bin")
            val f3 = File(tempDir, "dl_t3.bin")

            val d1 = async(Dispatchers.IO) {
                client.downloadFile("127.0.0.1", srvSock.localPort, "t1", f1, sha256Hex(payload1))
            }
            assertTrue("t1 must begin streaming before cancellation", t1StartedLatch.await(4, TimeUnit.SECONDS))

            // Start 2nd and 3rd concurrent downloads AFTER t1 is active, then cancel ONLY t1
            val d2 = async(Dispatchers.IO) {
                client.downloadFile("127.0.0.1", srvSock.localPort, "t2", f2, sha2)
            }
            val d3 = async(Dispatchers.IO) {
                client.downloadFile("127.0.0.1", srvSock.localPort, "t3", f3, sha3)
            }

            client.cancelTransfer("t1")
            val (r1, r2, r3) = listOf(d1, d2, d3).awaitAll()

            assertTrue("t1 must fail with cancellation error", r1 is FileTransferClient.TransferResult.Error && r1.message.contains("cancel", ignoreCase = true))
            assertTrue("t2 must succeed unaffected by t1 cancel", r2 is FileTransferClient.TransferResult.Success && r2.sha256 == sha2)
            assertTrue("t3 must succeed unaffected by t1 cancel", r3 is FileTransferClient.TransferResult.Success && r3.sha256 == sha3)
            assertFalse("Cancelled t1 file must not remain committed", f1.exists())
            assertEquals(payload2.size.toLong(), f2.length())
            assertEquals(payload3.size.toLong(), f3.length())
        } finally {
            running.set(false)
            try { srvSock.close() } catch (_: Exception) {}
            srvThread.join(1000)
        }
    }

    @Test
    fun testRepoActiveTransfersConcurrentListAndSingleIdCancelDismiss() {
        val repo = SnowUiRepository.getInstance(context)
        val field = SnowUiRepository::class.java.getDeclaredField("_activeTransfers")
        field.isAccessible = true
        @Suppress("UNCHECKED_CAST")
        val stateList = field.get(repo) as kotlinx.coroutines.flow.MutableStateFlow<List<ActiveTransferInfo>>
        val mutateMethod = SnowUiRepository::class.java.getDeclaredMethod("mutateActiveTransfers", kotlin.jvm.functions.Function1::class.java)
        mutateMethod.isAccessible = true

        val t1 = ActiveTransferInfo("tr-1", "alpha.zip", "UPLOAD", 10L, 100L, "IN_PROGRESS")
        val t2 = ActiveTransferInfo("tr-2", "beta.pdf", "DOWNLOAD", 50L, 100L, "IN_PROGRESS")
        val t3 = ActiveTransferInfo("tr-3", "gamma.png", "UPLOAD", 100L, 100L, "COMPLETED")
        @Suppress("UNCHECKED_CAST")
        val updater: (List<ActiveTransferInfo>) -> List<ActiveTransferInfo> = { listOf(t1, t2, t3) }
        mutateMethod.invoke(repo, updater)

        assertEquals(3, repo.activeTransfers.value.size)
        assertEquals("tr-1", repo.activeTransfer.value?.transferId)

        // Cancel tr-1 ONLY -> tr-2 and tr-3 stay intact and derived activeTransfer promotes tr-2
        repo.cancelTransfer("tr-1")
        assertEquals(listOf("tr-2", "tr-3"), repo.activeTransfers.value.map { it.transferId })
        assertEquals("tr-2", repo.activeTransfer.value?.transferId)

        // Dismiss completed tr-3 ONLY -> tr-2 still in progress
        repo.dismissTransfer("tr-3")
        assertEquals(listOf("tr-2"), repo.activeTransfers.value.map { it.transferId })
        assertTrue(stateList.value.size == 1)
    }

    @Test
    fun testAndroidFileHandlerOwnerManualVsAiMcpSandboxing() = runBlocking {
        val sharedRoot = File(tempDir, "shared_storage_root").apply { mkdirs() }
        val secretFile = File(sharedRoot, "private_notes.txt").apply {
            writeText("sensitive-owner-content")
        }

        val handler = AndroidFileHandler(
            context = context,
            transferClientProvider = { null },
            storageRootDirProvider = { sharedRoot },
            allFilesAccessProvider = { true }
        )

        val ownerList = handler.handleFileList(mapOf("principal" to "OWNER_MANUAL", "scope" to "full"))
        assertEquals("success", ownerList["status"])
        assertEquals("full_shared_storage", ownerList["storage_mode"])
        @Suppress("UNCHECKED_CAST")
        val ownerItems = ownerList["items"] as List<Map<String, Any?>>
        assertTrue(ownerItems.any { it["name"] == secretFile.name })

        // AI_MCP MUST remain sandboxed to Transfer Folder even when All Files Access is granted & scope=full
        val aiList = handler.handleFileList(mapOf("principal" to "AI_MCP", "scope" to "full"))
        assertEquals("saf_tree", aiList["storage_mode"])
        assertEquals("SAF_FOLDER_NOT_CONFIGURED", aiList["status"])

        val aiReceive = handler.handleFileReceiveRequest(
            data = mapOf("file_name" to secretFile.name, "scope" to "full", "principal" to "AI_MCP"),
            serverHost = "127.0.0.1",
            defaultTransferPort = 8766
        )
        assertEquals("FILE_NOT_FOUND", aiReceive["error"])

        // Default handler without override returns false on JVM (Build.VERSION.SDK_INT == 0 < 30)
        val defaultHandler = AndroidFileHandler(context = context, transferClientProvider = { null })
        assertFalse(defaultHandler.isAllFilesAccessGranted())
    }

    @Test
    fun testTwoStepSnowIdPinResolutionPairedAndUnpairedWithRemainingAttempts() {
        val repo = SnowUiRepository.getInstance(context)
        repo.certPinStorageOverrideForTest = InMemoryCertPinStorage()
        repo.tokenStorageOverrideForTest = InMemoryTokenStorage()
        repo.snowIdDiscoveryBurstMs = 0L
        repo.allowDevLoopbackForTest = true

        // 1. Invalid syntax rejected immediately
        var step1Res: SnowIdStep1Result? = null
        repo.connectSnowIdStep1("INVALID-BAD-ID") { step1Res = it }
        assertTrue(step1Res is SnowIdStep1Result.Error)

        // 2. Paired saved device resolves zero-PIN via AlreadyConnected
        repo.recordSuccessfulConnection(
            host = "192.168.1.99",
            port = 8765,
            sessionId = "s-paired",
            peerDeviceName = "Paired Laptop",
            peerDeviceType = "pc",
            peerDeviceId = "pc-paired-1",
            peerSnowId = "SNW-PAIR-1234"
        )
        val pairedLatch2 = CountDownLatch(1)
        val pairedStep1Ref = AtomicReference<SnowIdStep1Result?>(null)
        repo.connectSnowIdStep1("SNW-PAIR-1234") {
            pairedStep1Ref.set(it)
            pairedLatch2.countDown()
        }
        assertTrue(pairedLatch2.await(5, TimeUnit.SECONDS))
        assertTrue(pairedStep1Ref.get() is SnowIdStep1Result.AlreadyConnected)

        // 3. Unpaired valid SNOW ID returns NeedsPin
        val unpairedLatch = CountDownLatch(1)
        val unpairedStep1Ref = AtomicReference<SnowIdStep1Result?>(null)
        repo.connectSnowIdStep1("SNW-NEWP-9876") {
            unpairedStep1Ref.set(it)
            unpairedLatch.countDown()
        }
        assertTrue(unpairedLatch.await(5, TimeUnit.SECONDS))
        val unpairedStep1 = unpairedStep1Ref.get()
        assertTrue(unpairedStep1 is SnowIdStep1Result.NeedsPin)
        assertEquals("SNW-NEWP-9876", (unpairedStep1 as SnowIdStep1Result.NeedsPin).snowId)

        // 4. Step 2 PIN submission against local HTTP Hub server returning 401 -> remainingAttempts, then 200 success
        val running = AtomicBoolean(true)
        val hubSrv = ServerSocket(0)
        val hostFpHex = "A1".repeat(32)
        val hubThread = Thread {
            while (running.get()) {
                try {
                    val sock = hubSrv.accept()
                    Thread {
                        try {
                            val reader = sock.getInputStream().bufferedReader()
                            var contentLen = 0
                            while (true) {
                                val line = reader.readLine() ?: break
                                if (line.isEmpty()) break
                                if (line.startsWith("Content-Length:", ignoreCase = true)) {
                                    contentLen = line.substringAfter(":").trim().toIntOrNull() ?: 0
                                }
                            }
                            val bodyChars = CharArray(contentLen)
                            var r = 0
                            while (r < contentLen) {
                                val n = reader.read(bodyChars, r, contentLen - r)
                                if (n <= 0) break
                                r += n
                            }
                            val reqJson = JSONObject(String(bodyChars, 0, r))
                            val submittedPin = reqJson.optString("pin")
                            val out = sock.getOutputStream()
                            val (status, respJson) = if (submittedPin == "654321") {
                                200 to JSONObject()
                                    .put("success", true)
                                    .put("rendezvous_id", "rdv_1")
                                    .put("mode", "pairing")
                                    .put("network_id", "SNW-NET-12345678")
                                    .put("host_device_id", "phone-host-9876")
                                    .put("host_snow_id", "SNW-NEWP-9876")
                                    .put("host_cert_fingerprint", hostFpHex)
                                    .put("relay_ws_url", "ws://127.0.0.1:${hubSrv.localPort}/v1/tunnel")
                                    .put("bootstrap_token", "rbs1_valid_token_abc123")
                                    .toString()
                            } else {
                                401 to JSONObject()
                                    .put("success", false)
                                    .put("error", "Rendezvous verification failed.")
                                    .toString()
                            }
                            val payloadBytes = respJson.toByteArray(Charsets.UTF_8)
                            val phrase = if (status == 200) "OK" else "Unauthorized"
                            val hdr = "HTTP/1.1 $status $phrase\r\nContent-Type: application/json\r\nContent-Length: ${payloadBytes.size}\r\nConnection: close\r\n\r\n"
                            out.write(hdr.toByteArray(Charsets.UTF_8))
                            out.write(payloadBytes)
                            out.flush()
                        } catch (_: Exception) {
                        } finally {
                            try { sock.close() } catch (_: Exception) {}
                        }
                    }.start()
                } catch (_: Exception) {
                    if (!running.get()) break
                }
            }
        }.apply { isDaemon = true; start() }

        try {
            repo.updateRemoteRelayConfig(true, "http://127.0.0.1:${hubSrv.localPort}")
            val pairCompleted = AtomicBoolean(false)
            repo.customRendezvousTunnelPairerForTest = { rdvData, pin, _, cb ->
                assertEquals("654321", pin)
                assertEquals("phone-host-9876", rdvData["host_device_id"])
                pairCompleted.set(true)
                cb(true, null)
            }

            // Wrong PIN #1 -> remainingAttempts = 2
            val wrong1Latch = CountDownLatch(1)
            val wrong1Rem = AtomicReference<Int?>(null)
            val wrong1Ok = AtomicBoolean(true)
            repo.connectSnowIdStep2WithPin("SNW-NEWP-9876", "000000") { ok, _, rem ->
                wrong1Ok.set(ok)
                wrong1Rem.set(rem)
                wrong1Latch.countDown()
            }
            assertTrue(wrong1Latch.await(5, TimeUnit.SECONDS))
            assertFalse(wrong1Ok.get())
            assertEquals(2, wrong1Rem.get())

            // Wrong PIN #2 -> remainingAttempts = 1
            val wrong2Latch = CountDownLatch(1)
            val wrong2Rem = AtomicReference<Int?>(null)
            repo.connectSnowIdStep2WithPin("SNW-NEWP-9876", "111111") { ok, _, rem ->
                assertFalse(ok)
                wrong2Rem.set(rem)
                wrong2Latch.countDown()
            }
            assertTrue(wrong2Latch.await(5, TimeUnit.SECONDS))
            assertEquals(1, wrong2Rem.get())

            // Correct PIN -> success
            val okLatch = CountDownLatch(1)
            val finalOk = AtomicBoolean(false)
            repo.connectSnowIdStep2WithPin("SNW-NEWP-9876", "654321") { ok, _, rem ->
                finalOk.set(ok)
                assertNull(rem)
                okLatch.countDown()
            }
            assertTrue(okLatch.await(5, TimeUnit.SECONDS))
            assertTrue(finalOk.get())
            assertTrue(pairCompleted.get())
        } finally {
            repo.customRendezvousTunnelPairerForTest = null
            running.set(false)
            try { hubSrv.close() } catch (_: Exception) {}
            hubThread.join(1000)
        }
    }

    @Test
    fun testPeerTransferPortRoutingBetweenPc8766AndAndroidPeer8769() {
        val repo = SnowUiRepository.getInstance(context)
        repo.certPinStorageOverrideForTest = InMemoryCertPinStorage()
        repo.tokenStorageOverrideForTest = InMemoryTokenStorage()

        repo.onInboundPeerAuthenticated(
            PeerAuthEvent(
                peerDeviceId = "android-peer-1",
                peerDeviceName = "Galaxy S",
                peerDeviceType = "android",
                peerSnowId = "SNW-GALA-1111",
                peerHost = "192.168.1.77",
                transferPort = 8769,
                peerPort = 8767,
                networkId = "SNW-NET-CAFEBABE",
                isNewPairing = true
            )
        )
        repo.recordSuccessfulConnection(
            host = "192.168.1.12",
            port = 8765,
            sessionId = "sess-win",
            peerDeviceName = "Desktop",
            peerDeviceType = "pc",
            peerDeviceId = "pc-desk-1",
            peerTransferPort = 8766,
            peerPermissionProfile = "full_control"
        )

        repo.selectTargetDevice("android-peer-1")
        assertEquals(TargetDeviceType.ANDROID_PEER, repo.resolveTargetDeviceType())
        assertEquals(8769, repo.resolveActiveTransferPort("android-peer-1"))

        repo.selectTargetDevice("pc-desk-1")
        assertEquals(TargetDeviceType.WINDOWS_PC, repo.resolveTargetDeviceType())
        assertEquals(8766, repo.resolveActiveTransferPort("pc-desk-1"))
    }
}
