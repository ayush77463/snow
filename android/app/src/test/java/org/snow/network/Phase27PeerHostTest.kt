package org.snow.network

import android.content.ContextWrapper
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import org.java_websocket.client.WebSocketClient
import org.java_websocket.handshake.ServerHandshake
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.snow.capabilities.AndroidCapabilityDispatcher
import org.snow.protocol.ErrorCode
import org.snow.protocol.JsonSerialization
import org.snow.protocol.MessageType
import org.snow.protocol.SnowMessage
import org.snow.security.TokenStorage
import java.net.ConnectException
import java.net.ServerSocket
import java.net.Socket
import java.net.URI
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit

/**
 * JVM unit and lifecycle tests for Phase 27: Android-to-Android Peer Host Mode.
 *
 * NOTE: JVM unit tests validate local socket bounds, message protocols, and lifecycle
 * transitions. They do NOT validate physical two-phone RF interoperability, Wi-Fi Direct,
 * or vendor OEM battery management.
 */
class Phase27PeerHostTest {

    private lateinit var testScope: CoroutineScope
    private lateinit var hostManager: AndroidPeerHostManager
    private lateinit var mockTokenStorage: TokenStorage
    private lateinit var dispatcher: AndroidCapabilityDispatcher
    private var testPort: Int = 0

    class MemoryTokenStorage(private var storedToken: String? = "phase27-test-token-xyz") : TokenStorage {
        override fun saveToken(token: String) { this.storedToken = token }
        override fun getToken(): String? = storedToken
        override fun clearToken() { storedToken = null }
        override fun hasToken(): Boolean = storedToken != null
    }

    private class TestWsClient(uri: URI) : WebSocketClient(uri) {
        val messages = LinkedBlockingQueue<String>()

        override fun onOpen(handshakedata: ServerHandshake?) {}
        override fun onMessage(message: String) { messages.offer(message) }
        override fun onClose(code: Int, reason: String?, remote: Boolean) {}
        override fun onError(ex: Exception?) {}

        fun receiveMessage(timeoutSeconds: Long = 5): String? {
            return messages.poll(timeoutSeconds, TimeUnit.SECONDS)
        }
    }

    @Before
    fun setUp() {
        testScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        hostManager = AndroidPeerHostManager()
        mockTokenStorage = MemoryTokenStorage()

        val dummyContext = object : ContextWrapper(null) {}
        dispatcher = AndroidCapabilityDispatcher(dummyContext, transferClientProvider = { null })

        val ss = ServerSocket(0)
        testPort = ss.localPort
        ss.close()
    }

    @After
    fun tearDown() {
        hostManager.disableHostMode()
        testScope.cancel()
    }

    @Test
    fun test1_hostModeDefaultOffAndDisabledRefusal() {
        assertFalse("Host mode must be OFF by default", hostManager.isHostModeSettingEnabled())
        assertFalse("Host manager must not be active", hostManager.isHostModeActive())
        assertEquals(ReachabilityProfile.ACTIVE_SESSION_PEER, hostManager.getReachabilityProfile())

        // Refuses to start while disabled
        val started = hostManager.enableHostMode(
            port = testPort,
            tokenStorage = mockTokenStorage,
            dispatcher = dispatcher,
            localDeviceId = "phone-a-id",
            parentScope = testScope
        )
        assertFalse("Must fail closed when setting is disabled", started)
        assertFalse(hostManager.isHostModeActive())
    }

    @Test
    fun test2_explicitEnableStartsHostServer() {
        hostManager.setHostModeSettingEnabled(true)
        assertTrue(hostManager.isHostModeSettingEnabled())

        val started = hostManager.enableHostMode(
            port = testPort,
            tokenStorage = mockTokenStorage,
            dispatcher = dispatcher,
            localDeviceId = "phone-a-id",
            parentScope = testScope
        )
        assertTrue("Server should bind when setting is enabled", started)
        assertTrue(hostManager.isHostModeActive())
        assertEquals(ReachabilityProfile.FOREGROUND_HOST, hostManager.getReachabilityProfile())

        // Socket should be open and connectable
        val s = Socket("127.0.0.1", testPort)
        assertTrue(s.isConnected)
        s.close()

        hostManager.disableHostMode()
        assertFalse(hostManager.isHostModeActive())
        assertEquals(ReachabilityProfile.ACTIVE_SESSION_PEER, hostManager.getReachabilityProfile())
    }

    @Test
    fun test3_pairingPinLifecycleAndSingleUse() {
        val pin = hostManager.generatePairingPin()
        assertEquals(6, pin.length)
        assertTrue("PIN must be 6 numeric digits", pin.matches(Regex("^\\d{6}$")))
        assertTrue(pin.toIntOrNull() != null)

        val info = hostManager.getCurrentEphemeralPinInfo()
        assertNotNull(info)
        assertEquals(pin, info?.first)
        assertTrue(info!!.second > 0L)

        // Invalid pin rejected (wrong pin)
        val wrongPin = if (pin == "999999") "000000" else "999999"
        assertFalse(hostManager.verifyAndConsumePairingPin(wrongPin))

        // Correct pin consumed
        assertTrue(hostManager.verifyAndConsumePairingPin(pin))

        // Single-use: Second attempt must fail
        assertFalse("PIN must be single-use and fail after consumption", hostManager.verifyAndConsumePairingPin(pin))
    }

    @Test
    fun test4_authenticatedPeerAdmission() {
        hostManager.setHostModeSettingEnabled(true)
        hostManager.enableHostMode(
            port = testPort,
            tokenStorage = mockTokenStorage,
            dispatcher = dispatcher,
            localDeviceId = "phone-a-id",
            parentScope = testScope
        )

        val client = TestWsClient(URI("ws://127.0.0.1:$testPort"))
        assertTrue("WebSocket client should connect", client.connectBlocking(5, TimeUnit.SECONDS))

        // Authenticate with valid token
        val authMsg = SnowMessage.createRequest(
            action = "auth_request",
            data = mapOf(
                "auth_token" to "phase27-test-token-xyz",
                "device_id" to "phone-b-id"
            )
        )
        client.send(JsonSerialization.toJson(authMsg))

        val respStr = client.receiveMessage()
        assertNotNull(respStr)
        val respMsg = JsonSerialization.fromJson(respStr!!)
        assertEquals(MessageType.RESPONSE, respMsg.type)
        assertEquals("success", respMsg.payload?.get("status"))
        assertEquals("phone-a-id", respMsg.payload?.get("device_id"))

        client.closeBlocking()
    }

    @Test
    fun test5_untrustedPeerRejection() {
        hostManager.setHostModeSettingEnabled(true)
        hostManager.enableHostMode(
            port = testPort,
            tokenStorage = mockTokenStorage,
            dispatcher = dispatcher,
            localDeviceId = "phone-a-id",
            parentScope = testScope
        )

        val client = TestWsClient(URI("ws://127.0.0.1:$testPort"))
        assertTrue("WebSocket client should connect", client.connectBlocking(5, TimeUnit.SECONDS))

        // Authenticate with invalid token
        val authMsg = SnowMessage.createRequest(
            action = "auth_request",
            data = mapOf(
                "auth_token" to "wrong-untrusted-token",
                "device_id" to "untrusted-peer-id"
            )
        )
        client.send(JsonSerialization.toJson(authMsg))

        val respStr = client.receiveMessage()
        assertNotNull(respStr)
        val respMsg = JsonSerialization.fromJson(respStr!!)
        assertEquals(MessageType.ERROR, respMsg.type)
        assertEquals(ErrorCode.UNAUTHORIZED, respMsg.error?.code)

        client.closeBlocking()
    }

    @Test
    fun test6_stopAndTeardownCleanlyClosesSocket() {
        hostManager.setHostModeSettingEnabled(true)
        hostManager.enableHostMode(
            port = testPort,
            tokenStorage = mockTokenStorage,
            dispatcher = dispatcher,
            localDeviceId = "phone-a-id",
            parentScope = testScope
        )
        assertTrue(hostManager.isHostModeActive())

        hostManager.disableHostMode()
        assertFalse(hostManager.isHostModeActive())

        var failedToConnect = false
        try {
            Socket("127.0.0.1", testPort).close()
        } catch (_: Exception) {
            failedToConnect = true
        }
        assertTrue("Socket must be closed after disableHostMode", failedToConnect)
    }
}
