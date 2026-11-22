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
import org.snow.capabilities.ClipboardHandler
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

class AndroidPeerHostTest {

    private lateinit var testScope: CoroutineScope
    private lateinit var hostManager: AndroidPeerHostManager
    private lateinit var mockTokenStorage: TokenStorage
    private lateinit var dispatcher: AndroidCapabilityDispatcher
    private var peerHostServer: AndroidPeerHostServer? = null
    private var testPort: Int = 0

    class MemoryTokenStorage(private var storedToken: String? = "test-token-secret-1234") : TokenStorage {
        override fun saveToken(token: String) { this.storedToken = token }
        override fun getToken(): String? = storedToken
        override fun clearToken() { storedToken = null }
        override fun hasToken(): Boolean = storedToken != null
    }

    private class TestWsClient(uri: URI) : WebSocketClient(uri) {
        val messages = LinkedBlockingQueue<String>()

        init {
            if (uri.scheme.equals("wss", ignoreCase = true)) {
                val trustAll = arrayOf<javax.net.ssl.TrustManager>(object : javax.net.ssl.X509TrustManager {
                    override fun checkClientTrusted(chain: Array<out java.security.cert.X509Certificate>?, authType: String?) {}
                    override fun checkServerTrusted(chain: Array<out java.security.cert.X509Certificate>?, authType: String?) {}
                    override fun getAcceptedIssuers(): Array<java.security.cert.X509Certificate> = emptyArray()
                })
                val sc = javax.net.ssl.SSLContext.getInstance("TLS")
                sc.init(null, trustAll, java.security.SecureRandom())
                setSocketFactory(sc.socketFactory)
            }
        }

        override fun onSetSSLParameters(sslParameters: javax.net.ssl.SSLParameters) {
            sslParameters.endpointIdentificationAlgorithm = null
        }

        override fun onOpen(handshakedata: ServerHandshake?) {}
        override fun onMessage(message: String) {
            messages.offer(message)
        }
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

        // Find free ephemeral port
        val ss = ServerSocket(0)
        testPort = ss.localPort
        ss.close()

        ClipboardHandler.isAppInForeground = false
        ClipboardHandler.isUserIntentGranted = false
    }

    @After
    fun tearDown() {
        hostManager.disableHostMode()
        peerHostServer?.stop()
        peerHostServer = null
        testScope.cancel()
    }

    private fun startDirectServer(
        port: Int,
        manifestProvider: () -> Map<String, Any?> = { emptyMap() }
    ): AndroidPeerHostServer {
        val certResult = org.snow.security.AndroidSelfSignedCertGenerator.generate()
        val s = AndroidPeerHostServer(
            requestedPort = port,
            tokenStorage = mockTokenStorage,
            dispatcher = dispatcher,
            localDeviceId = "android-node-test-1",
            manifestProvider = manifestProvider,
            parentScope = testScope,
            sslContext = certResult.sslContext
        )
        assertTrue("Direct AndroidPeerHostServer should bind", s.start())
        peerHostServer = s
        testPort = s.boundPort
        return s
    }

    @Test
    fun testHostModeLifecycleAndDisabledRefusal() {
        assertFalse(hostManager.isHostModeActive())
        assertEquals(ReachabilityProfile.ACTIVE_SESSION_PEER, hostManager.getReachabilityProfile())

        // Under disabled host mode setting, enableHostMode must fail closed
        val enabled = hostManager.enableHostMode(
            port = testPort,
            tokenStorage = mockTokenStorage,
            dispatcher = dispatcher,
            localDeviceId = "android-node-test-1",
            manifestProvider = { mapOf("supported_capabilities" to listOf("android.telemetry.get")) },
            parentScope = testScope
        )

        assertFalse("Disabled host manager must return false", enabled)
        assertFalse(hostManager.isHostModeActive())
        assertEquals(ReachabilityProfile.ACTIVE_SESSION_PEER, hostManager.getReachabilityProfile())

        // Verify socket is not opened
        var failedToConnect = false
        try {
            Socket("127.0.0.1", testPort).close()
        } catch (_: ConnectException) {
            failedToConnect = true
        } catch (_: Exception) {
            failedToConnect = true
        }
        assertTrue("Disabled host manager must not open socket", failedToConnect)

        // When setting is enabled, start succeeds
        hostManager.setHostModeSettingEnabled(true)
        val started = hostManager.enableHostMode(
            port = testPort,
            tokenStorage = mockTokenStorage,
            dispatcher = dispatcher,
            localDeviceId = "android-node-test-1",
            manifestProvider = { mapOf("supported_capabilities" to listOf("android.telemetry.get")) },
            parentScope = testScope
        )
        assertTrue("Host manager should start when setting enabled", started)
        assertTrue(hostManager.isHostModeActive())
        assertEquals(ReachabilityProfile.FOREGROUND_HOST, hostManager.getReachabilityProfile())

        hostManager.disableHostMode()
        assertFalse(hostManager.isHostModeActive())
        assertEquals(ReachabilityProfile.ACTIVE_SESSION_PEER, hostManager.getReachabilityProfile())
    }

    @Test
    fun testPingPongOverPeerHostWebSocket() {
        val s = startDirectServer(testPort)
        val client = TestWsClient(URI("wss://127.0.0.1:${s.boundPort}"))
        assertTrue("WebSocket client should connect", client.connectBlocking(5, TimeUnit.SECONDS))

        try {
            val pingMsg = SnowMessage.createRequest("ping")
            client.send(JsonSerialization.toJson(pingMsg))

            val responseJson = client.receiveMessage()
            assertNotNull("Should receive pong message", responseJson)
            val resp = JsonSerialization.fromJson(responseJson!!)
            assertEquals(MessageType.RESPONSE, resp.type)
            assertEquals("pong", resp.payload?.get("action"))
            assertEquals("success", resp.payload?.get("status"))
        } finally {
            client.closeBlocking()
        }
    }

    @Test
    fun testUnauthenticatedCapabilityRequestRejected() {
        val s = startDirectServer(testPort)
        val client = TestWsClient(URI("wss://127.0.0.1:${s.boundPort}"))
        assertTrue("WebSocket client should connect", client.connectBlocking(5, TimeUnit.SECONDS))

        try {
            val req = SnowMessage.createRequest("battery_status")
            client.send(JsonSerialization.toJson(req))

            val responseJson = client.receiveMessage()
            assertNotNull(responseJson)
            val resp = JsonSerialization.fromJson(responseJson!!)
            assertEquals(MessageType.ERROR, resp.type)
            assertEquals(ErrorCode.UNAUTHORIZED, resp.error?.code)
        } finally {
            client.closeBlocking()
        }
    }

    @Test
    fun testPairRequestCannotBypassAuthentication() {
        val s = startDirectServer(testPort)
        val client = TestWsClient(URI("wss://127.0.0.1:${s.boundPort}"))
        assertTrue("WebSocket client should connect", client.connectBlocking(5, TimeUnit.SECONDS))

        try {
            val bypassReq = SnowMessage.createRequest(
                action = "pair_request",
                data = mapOf("device_id" to "attacker-peer")
            )
            client.send(JsonSerialization.toJson(bypassReq))

            val responseJson = client.receiveMessage()
            assertNotNull(responseJson)
            val resp = JsonSerialization.fromJson(responseJson!!)
            assertEquals(MessageType.ERROR, resp.type)
            assertEquals(ErrorCode.UNAUTHORIZED, resp.error?.code)
        } finally {
            client.closeBlocking()
        }
    }

    @Test
    fun testAuthenticationWithValidTokenSucceeds() {
        val s = startDirectServer(
            port = testPort,
            manifestProvider = { mapOf("manifest_version" to "2.0") }
        )
        val client = TestWsClient(URI("wss://127.0.0.1:${s.boundPort}"))
        assertTrue("WebSocket client should connect", client.connectBlocking(5, TimeUnit.SECONDS))

        try {
            val authReq = SnowMessage.createRequest(
                action = "auth_request",
                data = mapOf(
                    "auth_token" to "test-token-secret-1234",
                    "device_id" to "remote-peer-99"
                )
            )
            client.send(JsonSerialization.toJson(authReq))

            val responseJson = client.receiveMessage()
            assertNotNull(responseJson)
            val resp = JsonSerialization.fromJson(responseJson!!)
            assertEquals(MessageType.RESPONSE, resp.type)
            assertEquals("success", resp.payload?.get("status"))
            assertEquals("android-node-test-1", resp.payload?.get("device_id"))
            assertNotNull(resp.payload?.get("session_id"))
        } finally {
            client.closeBlocking()
        }
    }

    @Test
    fun testAuthenticationWithInvalidTokenRejected() {
        val s = startDirectServer(testPort)
        val client = TestWsClient(URI("wss://127.0.0.1:${s.boundPort}"))
        assertTrue("WebSocket client should connect", client.connectBlocking(5, TimeUnit.SECONDS))

        try {
            val authReq = SnowMessage.createRequest(
                action = "auth_request",
                data = mapOf(
                    "auth_token" to "WRONG-TOKEN-FAIL",
                    "device_id" to "attacker-peer"
                )
            )
            client.send(JsonSerialization.toJson(authReq))

            val responseJson = client.receiveMessage()
            assertNotNull(responseJson)
            val resp = JsonSerialization.fromJson(responseJson!!)
            assertEquals(MessageType.ERROR, resp.type)
            assertEquals(ErrorCode.UNAUTHORIZED, resp.error?.code)
        } finally {
            client.closeBlocking()
        }
    }

    @Test
    fun testAuthenticatedCapabilityExecutionThroughDispatcher() {
        val s = startDirectServer(testPort)
        val client = TestWsClient(URI("wss://127.0.0.1:${s.boundPort}"))
        assertTrue("WebSocket client should connect", client.connectBlocking(5, TimeUnit.SECONDS))

        try {
            // 1. Authenticate
            val authReq = SnowMessage.createRequest(
                action = "auth_request",
                data = mapOf("auth_token" to "test-token-secret-1234")
            )
            client.send(JsonSerialization.toJson(authReq))
            client.receiveMessage() // auth response

            // 2. Dispatch battery_status
            val batReq = SnowMessage.createRequest("battery_status")
            client.send(JsonSerialization.toJson(batReq))

            val responseJson = client.receiveMessage()
            assertNotNull(responseJson)
            val resp = JsonSerialization.fromJson(responseJson!!)
            assertEquals(MessageType.RESPONSE, resp.type)
            assertEquals("success", resp.payload?.get("status"))
        } finally {
            client.closeBlocking()
        }
    }

    @Test
    fun testExecutionContractEnforcedForForegroundOperation() {
        ClipboardHandler.isAppInForeground = false
        ClipboardHandler.isUserIntentGranted = false

        val s = startDirectServer(testPort)
        val client = TestWsClient(URI("wss://127.0.0.1:${s.boundPort}"))
        assertTrue("WebSocket client should connect", client.connectBlocking(5, TimeUnit.SECONDS))

        try {
            val authReq = SnowMessage.createRequest(
                action = "auth_request",
                data = mapOf("auth_token" to "test-token-secret-1234")
            )
            client.send(JsonSerialization.toJson(authReq))
            client.receiveMessage()

            // Request clipboard_pull which requires foreground
            val clipReq = SnowMessage.createRequest("clipboard_pull")
            client.send(JsonSerialization.toJson(clipReq))

            val responseJson = client.receiveMessage()
            assertNotNull(responseJson)
            val resp = JsonSerialization.fromJson(responseJson!!)
            assertEquals(MessageType.ERROR, resp.type)
            assertEquals(ErrorCode.UNAUTHORIZED, resp.error?.code)
            assertTrue(resp.error?.message?.contains("foreground") == true)
        } finally {
            client.closeBlocking()
        }
    }

    @Test
    fun testStopClosesSocketCleanly() {
        val server = startDirectServer(testPort)
        assertTrue(server.isListening())

        server.stop()
        assertFalse(server.isListening())

        var failedToConnect = false
        val startTime = System.currentTimeMillis()
        while (System.currentTimeMillis() - startTime < 3000) {
            try {
                Socket("127.0.0.1", server.boundPort).use {
                    Thread.sleep(50)
                }
            } catch (_: Exception) {
                failedToConnect = true
                break
            }
        }
        assertTrue("Port should not accept connections when server is stopped", failedToConnect)
    }
}
