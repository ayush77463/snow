package org.snow.security

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.snow.protocol.ErrorCode
import org.snow.protocol.SnowMessage
import java.util.UUID

class PairingFlowTest {

    private lateinit var identity: DeviceIdentity
    private lateinit var flow: PairingFlow

    @Before
    fun setUp() {
        identity = DeviceIdentity(
            deviceId = UUID.randomUUID().toString(),
            deviceName = "Test Realme Device",
            createdAt = "2026-11-16T08:00:00Z"
        )
        flow = PairingFlow(identity)
    }

    @Test
    fun testSixDigitPinValidation() {
        // Valid 6 decimal digits (including leading zeroes)
        assertTrue(flow.validatePin("004821"))
        assertTrue(flow.validatePin("123456"))
        assertTrue(flow.validatePin("000000"))
        assertTrue(flow.validatePin("999999"))

        // Invalid lengths or characters
        assertFalse(flow.validatePin("12345"))     // 5 digits
        assertFalse(flow.validatePin("1234567"))   // 7 digits
        assertFalse(flow.validatePin("12345a"))   // Contains letter
        assertFalse(flow.validatePin("abcdef"))   // All letters
        assertFalse(flow.validatePin(""))         // Empty
        assertFalse(flow.validatePin(null))       // Null
        // Whitespace trimming behavior
        assertTrue(flow.validatePin(" 123456 "))
    }

    @Test
    fun testSuccessResponseStateMapping() {
        val requestId = UUID.randomUUID().toString()
        val desktopId = UUID.randomUUID().toString()
        val sessionId = UUID.randomUUID().toString()

        val response = SnowMessage.createResponse(
            correlationId = requestId,
            payload = mapOf(
                "status" to "success",
                "action" to "pair_request",
                "data" to mapOf(
                    "device_id" to desktopId,
                    "device_name" to "SNOW Desktop Core",
                    "session_id" to sessionId
                )
            )
        )

        val state = flow.handlePairingResponse(response)
        assertTrue("State must map to Paired on success", state is PairingState.Paired)
        val paired = state as PairingState.Paired
        assertEquals(desktopId, paired.desktopId)
        assertEquals("SNOW Desktop Core", paired.desktopName)
        assertEquals(sessionId, paired.sessionId)
    }

    @Test
    fun testWrongPinErrorStateMapping() {
        val requestId = UUID.randomUUID().toString()
        val errorMsg = "Invalid pairing PIN. 2 attempt(s) remaining."

        val errorResponse = SnowMessage.createError(
            code = ErrorCode.INVALID_PIN,
            message = errorMsg,
            correlationId = requestId
        )

        val state = flow.handlePairingResponse(errorResponse)
        assertTrue("State must map to WrongPin", state is PairingState.WrongPin)
        val wrong = state as PairingState.WrongPin
        assertEquals(errorMsg, wrong.message)
        assertEquals(2, wrong.remainingAttempts)
    }

    @Test
    fun testPinExpiredErrorStateMapping() {
        val requestId = UUID.randomUUID().toString()
        val errorMsg = "Pairing PIN has expired. Please request a new PIN."

        val errorResponse = SnowMessage.createError(
            code = ErrorCode.PIN_EXPIRED,
            message = errorMsg,
            correlationId = requestId
        )

        val state = flow.handlePairingResponse(errorResponse)
        assertTrue("State must map to Expired", state is PairingState.Expired)
        val expired = state as PairingState.Expired
        assertEquals(errorMsg, expired.message)
    }

    @Test
    fun testPairingLockedErrorStateMapping() {
        val requestId = UUID.randomUUID().toString()
        val errorMsg = "Pairing locked: Exceeded maximum allowed attempts (3)."

        val errorResponse = SnowMessage.createError(
            code = ErrorCode.PAIRING_LOCKED,
            message = errorMsg,
            correlationId = requestId
        )

        val state = flow.handlePairingResponse(errorResponse)
        assertTrue("State must map to Locked", state is PairingState.Locked)
        val locked = state as PairingState.Locked
        assertEquals(errorMsg, locked.message)
    }

    @Test
    fun testAlreadyPairedErrorStateMapping() {
        val requestId = UUID.randomUUID().toString()
        val errorMsg = "Device is already paired in this session."

        val errorResponse = SnowMessage.createError(
            code = ErrorCode.ALREADY_PAIRED,
            message = errorMsg,
            correlationId = requestId
        )

        val state = flow.handlePairingResponse(errorResponse)
        assertTrue("Already paired maps gracefully to Paired state", state is PairingState.Paired)
    }

    @Test
    fun testSuccessResponseSavesTokenWhenPresent() {
        val storage = InMemoryTokenStorage()
        val flowWithStorage = PairingFlow(identity, storage)

        val requestId = UUID.randomUUID().toString()
        val desktopId = UUID.randomUUID().toString()
        val sessionId = UUID.randomUUID().toString()
        val authToken = "secret-token-xyz789"

        val response = SnowMessage.createResponse(
            correlationId = requestId,
            payload = mapOf(
                "status" to "success",
                "action" to "pair_request",
                "data" to mapOf(
                    "device_id" to desktopId,
                    "device_name" to "SNOW Desktop Core",
                    "session_id" to sessionId,
                    "auth_token" to authToken
                )
            )
        )

        val state = flowWithStorage.handlePairingResponse(response)
        assertTrue(state is PairingState.Paired)
        val paired = state as PairingState.Paired
        assertEquals(authToken, paired.authToken)
        assertTrue(storage.hasToken())
        assertEquals(authToken, storage.getToken())
    }

    @Test
    fun testQrHandshakeTokenSubmissionExcludesPinAndIncludesNetworkId() {
        val sentPayloads = mutableListOf<String>()
        val fakeWs = object : okhttp3.WebSocket {
            override fun request(): okhttp3.Request = okhttp3.Request.Builder().url("https://192.168.1.50:8765").build()
            override fun queueSize(): Long = 0L
            override fun send(text: String): Boolean {
                sentPayloads.add(text)
                return true
            }
            override fun send(bytes: okio.ByteString): Boolean = true
            override fun close(code: Int, reason: String?): Boolean = true
            override fun cancel() {}
        }

        val client = org.snow.network.SnowWebSocketClient(useTls = true)
        client.autoReconnectEnabled = false
        val wsField = client.javaClass.getDeclaredField("webSocket").apply { isAccessible = true }
        wsField.set(client, fakeWs)
        val hostField = client.javaClass.getDeclaredField("targetHost").apply { isAccessible = true }
        hostField.set(client, "192.168.1.50")
        val connStateField = client.javaClass.getDeclaredField("_connectionState").apply { isAccessible = true }
        @Suppress("UNCHECKED_CAST")
        val connStateFlow = connStateField.get(client) as kotlinx.coroutines.flow.MutableStateFlow<org.snow.network.ConnectionState>
        connStateFlow.value = org.snow.network.ConnectionState.CONNECTED

        val dispatched = flow.submitHandshakeToken(
            handshakeToken = "htok_valid_0123456789abcdef",
            networkId = "snw-net-1122aabb",
            client = client
        )
        assertTrue(dispatched)
        assertEquals(1, sentPayloads.size)

        val msgJson = org.json.JSONObject(sentPayloads[0])
        val dataJson = msgJson.getJSONObject("payload").getJSONObject("data")
        assertEquals("pair_request", msgJson.getJSONObject("payload").getString("action"))
        assertEquals("htok_valid_0123456789abcdef", dataJson.getString("handshake_token"))
        assertEquals("SNW-NET-1122AABB", dataJson.getString("network_id"))
        assertFalse("QR handshake token request must not include PIN", dataJson.has("pin"))

        // Reset lock and verify manual PIN submission omits handshake_token
        flow.resetSubmitting()
        val pinDispatched = flow.submitPin(pin = "654321", client = client)
        assertTrue(pinDispatched)
        assertEquals(2, sentPayloads.size)
        val pinDataJson = org.json.JSONObject(sentPayloads[1]).getJSONObject("payload").getJSONObject("data")
        assertEquals("654321", pinDataJson.getString("pin"))
        assertFalse("Manual PIN request must not include handshake_token", pinDataJson.has("handshake_token"))

        client.teardown()
    }

    @Test
    fun testQrHandshakeRejectsMalformedShortTokenWithoutConnecting() {
        val client = org.snow.network.SnowWebSocketClient(useTls = true)
        var captured: PairingState? = null
        val ok = flow.submitHandshakeToken("short", "SNW-NET-1122AABB", client) { st ->
            captured = st
        }
        assertFalse(ok)
        assertTrue(captured is PairingState.Error)
        assertTrue((captured as PairingState.Error).message.contains("Invalid QR handshake token"))
        client.teardown()
    }
}
