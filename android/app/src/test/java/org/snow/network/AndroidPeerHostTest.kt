package org.snow.network

import android.content.ContextWrapper
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.runBlocking
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
import java.io.BufferedReader
import java.io.BufferedWriter
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.net.ConnectException
import java.net.ServerSocket
import java.net.Socket

class AndroidPeerHostTest {

    private lateinit var testScope: CoroutineScope
    private lateinit var hostManager: AndroidPeerHostManager
    private lateinit var mockTokenStorage: TokenStorage
    private lateinit var dispatcher: AndroidCapabilityDispatcher
    private var testPort: Int = 0

    class MemoryTokenStorage(private var storedToken: String? = "test-token-secret-1234") : TokenStorage {
        override fun saveToken(token: String) { this.storedToken = token }
        override fun getToken(): String? = storedToken
        override fun clearToken() { storedToken = null }
        override fun hasToken(): Boolean = storedToken != null
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
        testScope.cancel()
    }

    @Test
    fun testHostModeLifecycleAndProfileTransitions() {
        assertFalse(hostManager.isHostModeActive())
        assertEquals(ReachabilityProfile.ACTIVE_SESSION_PEER, hostManager.getReachabilityProfile())

        val enabled = hostManager.enableHostMode(
            port = testPort,
            tokenStorage = mockTokenStorage,
            dispatcher = dispatcher,
            localDeviceId = "android-node-test-1",
            manifestProvider = { mapOf("supported_capabilities" to listOf("android.telemetry.get")) },
            parentScope = testScope
        )

        assertTrue(enabled)
        assertTrue(hostManager.isHostModeActive())
        assertEquals(ReachabilityProfile.FOREGROUND_HOST, hostManager.getReachabilityProfile())

        hostManager.disableHostMode()
        assertFalse(hostManager.isHostModeActive())
        assertEquals(ReachabilityProfile.ACTIVE_SESSION_PEER, hostManager.getReachabilityProfile())
    }

    @Test
    fun testPingPongOverPeerHostSocket() = runBlocking {
        hostManager.enableHostMode(
            port = testPort,
            tokenStorage = mockTokenStorage,
            dispatcher = dispatcher,
            localDeviceId = "android-node-test-1",
            parentScope = testScope
        )

        Socket("127.0.0.1", testPort).use { socket ->
            val writer = BufferedWriter(OutputStreamWriter(socket.getOutputStream(), Charsets.UTF_8))
            val reader = BufferedReader(InputStreamReader(socket.getInputStream(), Charsets.UTF_8))

            val pingMsg = SnowMessage.createRequest("ping")
            writer.write(JsonSerialization.toJson(pingMsg) + "\n")
            writer.flush()

            val line = reader.readLine()
            assertNotNull(line)
            val resp = JsonSerialization.fromJson(line)
            assertEquals(MessageType.RESPONSE, resp.type)
            assertEquals("pong", resp.payload?.get("action"))
            assertEquals("success", resp.payload?.get("status"))
        }
    }

    @Test
    fun testUnauthenticatedCapabilityRequestRejected() = runBlocking {
        hostManager.enableHostMode(
            port = testPort,
            tokenStorage = mockTokenStorage,
            dispatcher = dispatcher,
            localDeviceId = "android-node-test-1",
            parentScope = testScope
        )

        Socket("127.0.0.1", testPort).use { socket ->
            val writer = BufferedWriter(OutputStreamWriter(socket.getOutputStream(), Charsets.UTF_8))
            val reader = BufferedReader(InputStreamReader(socket.getInputStream(), Charsets.UTF_8))

            val req = SnowMessage.createRequest("battery_status")
            writer.write(JsonSerialization.toJson(req) + "\n")
            writer.flush()

            val line = reader.readLine()
            assertNotNull(line)
            val resp = JsonSerialization.fromJson(line)
            assertEquals(MessageType.ERROR, resp.type)
            assertEquals(ErrorCode.UNAUTHORIZED, resp.error?.code)
        }
    }

    @Test
    fun testPairRequestCannotBypassAuthentication() = runBlocking {
        hostManager.enableHostMode(
            port = testPort,
            tokenStorage = mockTokenStorage,
            dispatcher = dispatcher,
            localDeviceId = "android-node-test-1",
            parentScope = testScope
        )

        Socket("127.0.0.1", testPort).use { socket ->
            val writer = BufferedWriter(OutputStreamWriter(socket.getOutputStream(), Charsets.UTF_8))
            val reader = BufferedReader(InputStreamReader(socket.getInputStream(), Charsets.UTF_8))

            // Attempting to bypass auth with unauthenticated pair_request
            val bypassReq = SnowMessage.createRequest(
                action = "pair_request",
                data = mapOf("device_id" to "attacker-peer")
            )
            writer.write(JsonSerialization.toJson(bypassReq) + "\n")
            writer.flush()

            val line = reader.readLine()
            assertNotNull(line)
            val resp = JsonSerialization.fromJson(line)
            assertEquals(MessageType.ERROR, resp.type)
            assertEquals(ErrorCode.UNAUTHORIZED, resp.error?.code)
        }
    }

    @Test
    fun testAuthenticationWithValidTokenSucceeds() = runBlocking {
        hostManager.enableHostMode(
            port = testPort,
            tokenStorage = mockTokenStorage,
            dispatcher = dispatcher,
            localDeviceId = "android-node-test-1",
            manifestProvider = { mapOf("manifest_version" to "2.0") },
            parentScope = testScope
        )

        Socket("127.0.0.1", testPort).use { socket ->
            val writer = BufferedWriter(OutputStreamWriter(socket.getOutputStream(), Charsets.UTF_8))
            val reader = BufferedReader(InputStreamReader(socket.getInputStream(), Charsets.UTF_8))

            val authReq = SnowMessage.createRequest(
                action = "auth_request",
                data = mapOf(
                    "auth_token" to "test-token-secret-1234",
                    "device_id" to "remote-peer-99"
                )
            )
            writer.write(JsonSerialization.toJson(authReq) + "\n")
            writer.flush()

            val line = reader.readLine()
            assertNotNull(line)
            val resp = JsonSerialization.fromJson(line)
            assertEquals(MessageType.RESPONSE, resp.type)
            assertEquals("success", resp.payload?.get("status"))
            assertEquals("android-node-test-1", resp.payload?.get("device_id"))
            assertNotNull(resp.payload?.get("session_id"))
        }
    }

    @Test
    fun testAuthenticationWithInvalidTokenRejected() = runBlocking {
        hostManager.enableHostMode(
            port = testPort,
            tokenStorage = mockTokenStorage,
            dispatcher = dispatcher,
            localDeviceId = "android-node-test-1",
            parentScope = testScope
        )

        Socket("127.0.0.1", testPort).use { socket ->
            val writer = BufferedWriter(OutputStreamWriter(socket.getOutputStream(), Charsets.UTF_8))
            val reader = BufferedReader(InputStreamReader(socket.getInputStream(), Charsets.UTF_8))

            val authReq = SnowMessage.createRequest(
                action = "auth_request",
                data = mapOf(
                    "auth_token" to "WRONG-TOKEN-FAIL",
                    "device_id" to "attacker-peer"
                )
            )
            writer.write(JsonSerialization.toJson(authReq) + "\n")
            writer.flush()

            val line = reader.readLine()
            assertNotNull(line)
            val resp = JsonSerialization.fromJson(line)
            assertEquals(MessageType.ERROR, resp.type)
            assertEquals(ErrorCode.UNAUTHORIZED, resp.error?.code)
        }
    }

    @Test
    fun testAuthenticatedCapabilityExecutionThroughDispatcher() = runBlocking {
        hostManager.enableHostMode(
            port = testPort,
            tokenStorage = mockTokenStorage,
            dispatcher = dispatcher,
            localDeviceId = "android-node-test-1",
            parentScope = testScope
        )

        Socket("127.0.0.1", testPort).use { socket ->
            val writer = BufferedWriter(OutputStreamWriter(socket.getOutputStream(), Charsets.UTF_8))
            val reader = BufferedReader(InputStreamReader(socket.getInputStream(), Charsets.UTF_8))

            // 1. Authenticate
            val authReq = SnowMessage.createRequest(
                action = "auth_request",
                data = mapOf("auth_token" to "test-token-secret-1234")
            )
            writer.write(JsonSerialization.toJson(authReq) + "\n")
            writer.flush()
            reader.readLine() // auth response

            // 2. Dispatch battery_status
            val batReq = SnowMessage.createRequest("battery_status")
            writer.write(JsonSerialization.toJson(batReq) + "\n")
            writer.flush()

            val line = reader.readLine()
            assertNotNull(line)
            val resp = JsonSerialization.fromJson(line)
            assertEquals(MessageType.RESPONSE, resp.type)
            assertEquals("success", resp.payload?.get("status"))
        }
    }

    @Test
    fun testExecutionContractEnforcedForForegroundOperation() = runBlocking {
        ClipboardHandler.isAppInForeground = false
        ClipboardHandler.isUserIntentGranted = false

        hostManager.enableHostMode(
            port = testPort,
            tokenStorage = mockTokenStorage,
            dispatcher = dispatcher,
            localDeviceId = "android-node-test-1",
            parentScope = testScope
        )

        Socket("127.0.0.1", testPort).use { socket ->
            val writer = BufferedWriter(OutputStreamWriter(socket.getOutputStream(), Charsets.UTF_8))
            val reader = BufferedReader(InputStreamReader(socket.getInputStream(), Charsets.UTF_8))

            val authReq = SnowMessage.createRequest(
                action = "auth_request",
                data = mapOf("auth_token" to "test-token-secret-1234")
            )
            writer.write(JsonSerialization.toJson(authReq) + "\n")
            writer.flush()
            reader.readLine()

            // Request clipboard_pull which requires foreground
            val clipReq = SnowMessage.createRequest("clipboard_pull")
            writer.write(JsonSerialization.toJson(clipReq) + "\n")
            writer.flush()

            val line = reader.readLine()
            assertNotNull(line)
            val resp = JsonSerialization.fromJson(line)
            assertEquals(MessageType.ERROR, resp.type)
            assertEquals(ErrorCode.UNAUTHORIZED, resp.error?.code)
            assertTrue(resp.error?.message?.contains("foreground") == true)
        }
    }

    @Test
    fun testStopClosesSocketCleanly() = runBlocking {
        hostManager.enableHostMode(
            port = testPort,
            tokenStorage = mockTokenStorage,
            dispatcher = dispatcher,
            localDeviceId = "android-node-test-1",
            parentScope = testScope
        )
        assertTrue(hostManager.isHostModeActive())

        hostManager.disableHostMode()
        assertFalse(hostManager.isHostModeActive())

        var failedToConnect = false
        try {
            Socket("127.0.0.1", testPort).close()
        } catch (_: ConnectException) {
            failedToConnect = true
        } catch (_: Exception) {
            failedToConnect = true
        }
        assertTrue("Port should not accept connections when host mode is disabled", failedToConnect)
    }
}
