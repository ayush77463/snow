package org.snow.capabilities

import android.content.Context
import android.content.ContextWrapper
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.setMain
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.snow.protocol.ErrorCode

@OptIn(ExperimentalCoroutinesApi::class)
class MessagingHandlerTest {

    private val testDispatcher = UnconfinedTestDispatcher()

    @Before
    fun setUp() {
        Dispatchers.setMain(testDispatcher)
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
    }

    @Test
    fun testMessagingConstants() {
        assertEquals("intent", MessagingHandler.MODE_INTENT)
        assertEquals("sms", MessagingHandler.MODE_SMS)
    }

    @Test
    fun testCreateComposeIntentContract() {
        val recipient = "+1234567890"
        val message = "Hello from SNOW test"

        // Verify compile-time and runtime intent contract constants
        assertEquals("android.intent.action.SENDTO", MessagingHandler.ACTION_COMPOSE)
        assertEquals("smsto", MessagingHandler.SCHEME_SMSTO)
        assertEquals("smsto:+1234567890", MessagingHandler.buildSmstoUri(recipient))

        val intent = MessagingHandler.createComposeIntent(recipient, message)
        assertNotNull(intent)
    }

    @Test
    fun testRecipientNullOrEmptyValidation() = runBlocking {
        val dummyContext = object : ContextWrapper(null) {}
        val handler = MessagingHandler(dummyContext)

        val resNull = handler.sendMessage(recipient = null, message = "Hello")
        assertEquals("error", resNull["status"])
        assertEquals("INVALID_ARGUMENT", resNull["error"])
        assertTrue((resNull["message"] as String).contains("Recipient cannot be null"))

        val resBlank = handler.sendMessage(recipient = "   ", message = "Hello")
        assertEquals("error", resBlank["status"])
        assertEquals("INVALID_ARGUMENT", resBlank["error"])
    }

    @Test
    fun testMessageBodyNullValidation() = runBlocking {
        val dummyContext = object : ContextWrapper(null) {}
        val handler = MessagingHandler(dummyContext)

        val resNull = handler.sendMessage(recipient = "+1234567890", message = null)
        assertEquals("error", resNull["status"])
        assertEquals("INVALID_ARGUMENT", resNull["error"])
        assertTrue((resNull["message"] as String).contains("Message body cannot be null"))
    }

    @Test
    fun testUnsupportedModeReturnsError() = runBlocking {
        val dummyContext = object : ContextWrapper(null) {}
        val handler = MessagingHandler(dummyContext)

        val res = handler.sendMessage(recipient = "+1234567890", message = "Hello", mode = "carrier_pigeon")
        assertEquals("error", res["status"])
        assertEquals("UNSUPPORTED_MODE", res["error"])
    }

    @Test
    fun testSmsModeDirectlyRejectedAsUnsupportedMode() = runBlocking {
        val dummyContext = object : ContextWrapper(null) {}
        val handler = MessagingHandler(dummyContext)

        val res = handler.sendMessage(
            recipient = "+1234567890",
            message = "Test SMS",
            mode = "sms",
            userConfirmed = true
        )
        assertEquals("error", res["status"])
        assertEquals("UNSUPPORTED_MODE", res["error"])
        assertEquals("sms", res["mode"])
        assertTrue((res["message"] as String).contains("Direct SMS is not supported"))
    }

    @Test
    fun testCapabilityDispatcherDispatchesSendMessage() = runBlocking {
        val dummyContext = object : ContextWrapper(null) {}
        val dispatcher = AndroidCapabilityDispatcher(dummyContext, transferClientProvider = { null })
        ClipboardHandler.isAppInForeground = true

        // 1. Invalid payload: missing recipient
        val (resInvalid, errInvalid) = dispatcher.dispatch(
            action = "send_message",
            data = mapOf("message" to "Hello"),
            serverHost = "127.0.0.1",
            defaultTransferPort = 8766
        )
        assertNull(resInvalid)
        assertNotNull(errInvalid)
        assertEquals(ErrorCode.INVALID_PAYLOAD, errInvalid?.code)

        // 2. Direct SMS mode rejected via dispatcher as UNSUPPORTED_MODE
        val (resSms, errSms) = dispatcher.dispatch(
            action = "send_message",
            data = mapOf("recipient" to "+1234567890", "message" to "Hello", "mode" to "sms", "user_confirmed" to true),
            serverHost = "127.0.0.1",
            defaultTransferPort = 8766
        )
        assertNull(resSms)
        assertNotNull(errSms)
        assertEquals(ErrorCode.UNAUTHORIZED, errSms?.code)
        assertTrue(errSms?.message?.contains("UNSUPPORTED_MODE") == true)
    }
}
