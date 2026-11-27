package org.snow.network

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.runBlocking
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
}
