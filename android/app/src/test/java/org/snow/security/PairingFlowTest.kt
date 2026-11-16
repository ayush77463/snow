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
}
