package org.snow.network

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.setMain
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.snow.protocol.JsonSerialization
import org.snow.protocol.MessageType
import org.snow.protocol.SnowMessage
import org.snow.security.DeviceIdentity
import org.snow.security.InMemoryCertPinStorage
import org.snow.security.InMemoryTokenStorage
import java.util.concurrent.CopyOnWriteArrayList

/**
 * Stage 3 Make-Before-Break & Fallback tests for SnowWebSocketClient & TransportOrchestrator:
 * - Probing a failing standby host NEVER drops the existing healthy socket or pending requests
 * - Successful standby promotion atomically promotes active socket and drains in-flight RPCs cleanly
 * - Transport loss fails over in strict order USB -> Hotspot -> Wi-Fi -> Relay, unless manually pinned
 */
class M43Unit2MakeBeforeBreakAndFallbackTest {

    private class FakeWebSocket(
        val url: String,
        val onSend: (FakeWebSocket, String) -> Unit = { _, _ -> }
    ) : WebSocket {
        val sentFrames = CopyOnWriteArrayList<String>()
        var closedCode: Int? = null
        var closedReason: String? = null
        var cancelled: Boolean = false

        override fun request(): Request = Request.Builder().url(url).build()
        override fun queueSize(): Long = 0L
        override fun send(text: String): Boolean {
            sentFrames.add(text)
            onSend(this, text)
            return true
        }
        override fun send(bytes: okio.ByteString): Boolean = true
        override fun close(code: Int, reason: String?): Boolean {
            closedCode = code
            closedReason = reason
            return true
        }
        override fun cancel() {
            cancelled = true
        }
    }

    @Test
    fun mbbFailedStandbyLeavesHealthySessionAndInflightRequestsIntact() = runBlocking {
        val client = SnowWebSocketClient(
            certPinStorage = InMemoryCertPinStorage().apply {
                pinFingerprintForDevice("pc-1", "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99")
            },
            tokenStorage = InMemoryTokenStorage().apply {
                saveTokenForDevice("pc-1", "tok-123")
            },
            identity = DeviceIdentity(deviceId = "11111111-1111-4111-8111-111111111111", deviceName = "Pixel", createdAt = "2026-11-27T00:00:00Z"),
            useTls = false
        )

        val primaryWs = FakeWebSocket("ws://192.168.1.50:8765")
        val primaryGen = 1L
        client.attachSocketForTest(primaryWs, primaryGen)
        client.expectedTargetDeviceId = "pc-1"
        client.setAuthenticated(sessionId = "sess-1", peerDeviceId = "pc-1", peerDeviceName = "WorkPC")

        // Queue in-flight request on primary socket before standby probe
        val inFlightResp = CompletableDeferred<SnowMessage>()
        client.sendRequest("battery_status") { msg -> inFlightResp.complete(msg) }
        assertEquals(1, primaryWs.sentFrames.size)
        val primaryReq = JsonSerialization.fromJson(primaryWs.sentFrames[0])

        // Inject failing standby probe (127.0.0.1 rejects connection via onFailure)
        lateinit var badStandbyWs: FakeWebSocket
        client.webSocketFactory = { req, listener ->
            badStandbyWs = FakeWebSocket(req.url.toString())
            listener.onFailure(badStandbyWs, RuntimeException("Connection refused"), null)
            badStandbyWs
        }

        val probeRes = client.probeAndPromoteEndpoint(
            newHost = "127.0.0.1",
            newPort = 8765,
            targetDeviceId = "pc-1",
            timeoutMs = 1500L,
            verifyPing = true
        )

        assertFalse(probeRes.promoted)
        assertTrue(badStandbyWs.cancelled)
        assertNull(primaryWs.closedCode)
        assertFalse(primaryWs.cancelled)
        assertEquals(ConnectionState.CONNECTED, client.connectionState.value)
        assertTrue(client.authState.value is AuthState.Authenticated)

        // Primary socket can STILL receive response for its in-flight request
        val okMsg = SnowMessage.createResponse(
            correlationId = primaryReq.id,
            payload = mapOf("status" to "success", "battery" to 85)
        )
        client.handleIncomingMessage(primaryWs, JsonSerialization.toJson(okMsg), expectedGeneration = primaryGen)
        assertEquals(MessageType.RESPONSE, inFlightResp.await().type)
        client.teardown()
    }

    @Test
    fun mbbSuccessfulStandbyPromotesAndDrainsRetiringSocketInflightRpc() = runBlocking {
        val client = SnowWebSocketClient(
            certPinStorage = InMemoryCertPinStorage().apply {
                pinFingerprintForDevice("pc-1", "AA".repeat(32).chunked(2).joinToString(":"))
            },
            tokenStorage = InMemoryTokenStorage().apply {
                saveTokenForDevice("pc-1", "tok-123")
            },
            identity = DeviceIdentity(deviceId = "11111111-1111-4111-8111-111111111111", deviceName = "Pixel", createdAt = "2026-11-27T00:00:00Z"),
            useTls = false
        )

        val wifiWs = FakeWebSocket("ws://192.168.1.50:8765")
        val initialGen = 1L
        client.attachSocketForTest(wifiWs, initialGen)
        client.expectedTargetDeviceId = "pc-1"
        client.setAuthenticated(sessionId = "sess-wifi", peerDeviceId = "pc-1", peerDeviceName = "WorkPC")

        // In-flight RPC started on Wi-Fi BEFORE Make-Before-Break cutover
        val inFlightDone = CompletableDeferred<SnowMessage>()
        client.sendRequest("files_list") { msg -> inFlightDone.complete(msg) }
        val sentWifiReq = JsonSerialization.fromJson(wifiWs.sentFrames.first())

        var standbyListenerRef: WebSocketListener? = null
        lateinit var usbStandbyWs: FakeWebSocket
        client.webSocketFactory = { req, listener ->
            standbyListenerRef = listener
            usbStandbyWs = FakeWebSocket(req.url.toString()) { ws, text ->
                val incoming = JsonSerialization.fromJson(text)
                val action = incoming.payload?.get("action") as? String
                if (action == "auth_request") {
                    val authOk = SnowMessage.createResponse(
                        correlationId = incoming.id,
                        payload = mapOf(
                            "status" to "success",
                            "data" to mapOf(
                                "session_id" to "sess-usb",
                                "server_device_id" to "pc-1",
                                "device_name" to "WorkPC",
                                "device_type" to "windows"
                            )
                        )
                    )
                    listener.onMessage(ws, JsonSerialization.toJson(authOk))
                } else if (action == "ping") {
                    val pong = SnowMessage.createResponse(
                        correlationId = incoming.id,
                        payload = mapOf("status" to "success", "action" to "pong")
                    )
                    listener.onMessage(ws, JsonSerialization.toJson(pong))
                }
            }
            listener.onOpen(usbStandbyWs, Response.Builder().request(req).protocol(okhttp3.Protocol.HTTP_1_1).code(101).message("Switching").build())
            usbStandbyWs
        }

        val promo = client.probeAndPromoteEndpoint(
            newHost = "127.0.0.1",
            newPort = 8765,
            targetDeviceId = "pc-1",
            timeoutMs = 2000L,
            verifyPing = true
        )

        assertTrue(promo.promoted)
        assertEquals("127.0.0.1", client.currentTargetHost)
        assertEquals(ConnectionState.CONNECTED, client.connectionState.value)
        assertNotNull(standbyListenerRef)
        // Old socket was NOT closed yet while in-flight RPC is pending
        assertNull(wifiWs.closedCode)

        // Deliver delayed response on old Wi-Fi socket after cutover -> must succeed cleanly!
        val delayedResp = SnowMessage.createResponse(
            correlationId = sentWifiReq.id,
            payload = mapOf("status" to "success", "files" to listOf("doc.pdf"))
        )
        client.handleIncomingMessage(wifiWs, JsonSerialization.toJson(delayedResp), expectedGeneration = initialGen)
        assertEquals("success", inFlightDone.await().payload?.get("status"))
        client.teardown()
    }

    @Test
    fun orchestratorFailoverFollowsPriorityAndHonorsManualPin() {
        val orch = TransportOrchestrator()
        orch.markVerified("pc-1", TransportRoute.USB, host = "127.0.0.1", isActive = true)
        orch.markVerified("pc-1", TransportRoute.HOTSPOT, host = "192.168.43.1")
        orch.markVerified("pc-1", TransportRoute.WIFI_LAN, host = "192.168.1.25")
        orch.markVerified("pc-1", TransportRoute.REMOTE_RELAY, host = "relay")

        val next1 = orch.handleTransportLoss("pc-1", TransportRoute.USB, "Cable unplugged")
        assertEquals(TransportRoute.HOTSPOT, next1?.route)

        // When manually pinned to Hotspot, loss of Hotspot MUST fail closed (no silent bypass)
        assertTrue(orch.setMode("pc-1", TransportMode.HOTSPOT).first)
        val blocked = orch.handleTransportLoss("pc-1", TransportRoute.HOTSPOT, "Hotspot off")
        assertNull(blocked)
    }

    @Test
    fun relayClientVerifiesHandshakeBeforeEstablishedAndFailsOnRejectedAuth() = runBlocking {
        val relayClient = RelayClient(
            relayUrl = "wss://relay.snow.example/v1/relay",
            deviceId = "android-a",
            groupId = "grp-1",
            ticket = "tick-1",
            targetPeerId = "pc-b",
            usePublicCaForOuterRelay = true
        )
        var capturedListener: WebSocketListener? = null
        lateinit var wsSocket: FakeWebSocket
        relayClient.webSocketFactory = { req, listener ->
            capturedListener = listener
            wsSocket = FakeWebSocket(req.url.toString())
            wsSocket
        }

        val failedReason = CompletableDeferred<String>()
        relayClient.onTunnelFailed = { msg ->
            if (!failedReason.isCompleted) failedReason.complete(msg)
        }

        relayClient.connect()
        assertNotNull(capturedListener)
        capturedListener!!.onOpen(
            wsSocket,
            Response.Builder().request(wsSocket.request()).protocol(okhttp3.Protocol.HTTP_1_1).code(101).message("OK").build()
        )
        // Session hello_ack(success=true) alone must NOT mark the E2E tunnel verified yet!
        capturedListener!!.onMessage(wsSocket, """{"type":"hello_ack","success":true}""")
        assertEquals(ReachabilityState.ONLINE_RELAYED, relayClient.reachabilityState.value)
        assertFalse(relayClient.tunnelEstablished.value)
        assertFalse(relayClient.isSessionAndTunnelVerified())

        // Now simulate hub rejecting auth -> must emit onTunnelFailed and clear state
        capturedListener!!.onMessage(wsSocket, """{"type":"hello_ack","success":false,"error":"Invalid signature"}""")
        assertEquals("Invalid signature", failedReason.await())
        assertEquals(ReachabilityState.UNREACHABLE_OFFLINE, relayClient.reachabilityState.value)
        assertFalse(relayClient.isSessionAndTunnelVerified())
    }

    @OptIn(ExperimentalCoroutinesApi::class)
    @Test
    fun manualRemoteRelaySelectionFailsClosedPreservingWorkingRouteAndSucceedsOnlyWhenVerified() = runBlocking {
        val mainExec = java.util.concurrent.Executors.newSingleThreadExecutor()
        val mainDisp = mainExec.asCoroutineDispatcher()
        Dispatchers.setMain(mainDisp)
        val tempDir = java.nio.file.Files.createTempDirectory("m43_polish_repo_").toFile()
        val prefsMap = mutableMapOf<String, android.content.SharedPreferences>()
        fun newPrefs(): android.content.SharedPreferences = object : android.content.SharedPreferences {
            val map = mutableMapOf<String, Any?>()
            override fun getAll(): MutableMap<String, *> = HashMap(map)
            override fun getString(k: String?, d: String?) = map[k] as? String ?: d
            override fun getStringSet(k: String?, d: MutableSet<String>?) = d
            override fun getInt(k: String?, d: Int) = (map[k] as? Int) ?: d
            override fun getLong(k: String?, d: Long) = (map[k] as? Long) ?: d
            override fun getFloat(k: String?, d: Float) = (map[k] as? Float) ?: d
            override fun getBoolean(k: String?, d: Boolean) = (map[k] as? Boolean) ?: d
            override fun contains(k: String?) = map.containsKey(k)
            override fun edit() = object : android.content.SharedPreferences.Editor {
                val p = mutableMapOf<String, Any?>(); val r = mutableSetOf<String>(); var c = false
                override fun putString(k: String?, v: String?) = apply { if (k != null) p[k] = v }
                override fun putStringSet(k: String?, v: MutableSet<String>?) = apply {}
                override fun putInt(k: String?, v: Int) = apply { if (k != null) p[k] = v }
                override fun putLong(k: String?, v: Long) = apply { if (k != null) p[k] = v }
                override fun putFloat(k: String?, v: Float) = apply { if (k != null) p[k] = v }
                override fun putBoolean(k: String?, v: Boolean) = apply { if (k != null) p[k] = v }
                override fun remove(k: String?) = apply { if (k != null) r.add(k) }
                override fun clear() = apply { c = true }
                override fun commit(): Boolean {
                    if (c) map.clear(); r.forEach { map.remove(it) }
                    p.forEach { (k, v) -> if (v == null) map.remove(k) else map[k] = v }
                    return true
                }
                override fun apply() { commit() }
            }
            override fun registerOnSharedPreferenceChangeListener(l: android.content.SharedPreferences.OnSharedPreferenceChangeListener?) {}
            override fun unregisterOnSharedPreferenceChangeListener(l: android.content.SharedPreferences.OnSharedPreferenceChangeListener?) {}
        }

        val ctx = object : android.content.ContextWrapper(null) {
            override fun getApplicationContext(): android.content.Context = this
            override fun getFilesDir(): java.io.File = tempDir
            override fun getCacheDir(): java.io.File = tempDir
            override fun getPackageName(): String = "org.snow"
            override fun getSharedPreferences(name: String?, mode: Int) = prefsMap.getOrPut(name ?: "def") { newPrefs() }
        }
        val instField = org.snow.ui.SnowUiRepository::class.java.getDeclaredField("instance").apply { isAccessible = true }
        instField.set(null, null)
        try {
            val repo = org.snow.ui.SnowUiRepository.getInstance(ctx)
            val savedField = org.snow.ui.SnowUiRepository::class.java.getDeclaredField("_savedDevices").apply { isAccessible = true }
            @Suppress("UNCHECKED_CAST")
            val savedFlow = savedField.get(repo) as kotlinx.coroutines.flow.MutableStateFlow<List<org.snow.ui.SavedDevice>>
            savedFlow.value = listOf(
                org.snow.ui.SavedDevice(
                    deviceId = "pc-polish-1",
                    deviceName = "Laptop",
                    host = "192.168.1.30",
                    port = 8765,
                    connectionMode = "auto"
                )
            )
            repo.setRemoteRelayEndpoint("https://snow-relay.onrender.com")
            repo.activeTransportOrchestrator().markVerified("pc-polish-1", TransportRoute.WIFI_LAN, host = "192.168.1.30", isActive = true)

            // 1. Auth/handshake failure -> must fail closed, preserve Wi-Fi active, set honest error
            repo.relayActivationVerifierForTest = { _, _ -> false to "Hub challenge signature rejected" }
            val (okFail, errFail) = repo.switchDeviceTransport("pc-polish-1", "remote_relay")
            assertFalse(okFail)
            assertTrue(errFail.contains("Hub challenge signature rejected"))
            assertEquals("Hub challenge signature rejected", repo.lastTransportError.value)
            val snapAfterFail = repo.activeTransportOrchestrator().snapshotFor("pc-polish-1")
            assertEquals(TransportRoute.WIFI_LAN, snapAfterFail.activeRoute)
            assertEquals(TransportMode.AUTO, snapAfterFail.mode)

            // 2. Real authenticated handshake success -> activates REMOTE_RELAY and clears error
            repo.relayActivationVerifierForTest = { _, _ -> true to "Remote relay authenticated and verified." }
            val (okPass, _) = repo.switchDeviceTransport("pc-polish-1", "remote_relay")
            assertTrue(okPass)
            assertNull(repo.lastTransportError.value)
            val snapAfterPass = repo.activeTransportOrchestrator().snapshotFor("pc-polish-1")
            assertEquals(TransportRoute.REMOTE_RELAY, snapAfterPass.activeRoute)
            assertEquals(TransportMode.REMOTE_RELAY, snapAfterPass.mode)
        } finally {
            instField.set(null, null)
            tempDir.deleteRecursively()
            Dispatchers.resetMain()
            mainExec.shutdownNow()
        }
    }
}
