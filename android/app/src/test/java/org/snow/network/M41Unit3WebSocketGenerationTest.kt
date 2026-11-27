package org.snow.network

import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.Job
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import okio.ByteString
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.snow.protocol.JsonSerialization
import org.snow.protocol.MessageType
import org.snow.protocol.SnowMessage
import org.snow.security.DeviceIdentity
import org.snow.security.InMemoryCertPinStorage
import org.snow.security.InMemoryTokenStorage
import org.snow.security.UnconfirmedCertificateException
import java.math.BigInteger
import java.security.Principal
import java.security.PublicKey
import java.security.cert.X509Certificate
import java.util.Date
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.CyclicBarrier
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import javax.security.auth.x500.X500Principal

@OptIn(ExperimentalCoroutinesApi::class)
class M41Unit3WebSocketGenerationTest {

    private class CapturingWebSocket(
        private val reqUrl: String = "wss://127.0.0.1:8765",
        var sendResult: Boolean = true
    ) : WebSocket {
        val sentMessages = CopyOnWriteArrayList<String>()
        var cancelled = false
        var closedCode: Int? = null
        var closedReason: String? = null

        override fun request(): Request = Request.Builder().url(reqUrl).build()
        override fun queueSize(): Long = 0L
        override fun send(text: String): Boolean {
            if (!sendResult) return false
            sentMessages.add(text)
            return true
        }
        override fun send(bytes: ByteString): Boolean = sendResult
        override fun close(code: Int, reason: String?): Boolean {
            closedCode = code
            closedReason = reason
            return true
        }
        override fun cancel() {
            cancelled = true
        }
    }

    private data class SocketAttempt(
        val generation: Long,
        val socket: CapturingWebSocket,
        val listener: WebSocketListener
    )

    private class DummyCert(private val encodedBytes: ByteArray) : X509Certificate() {
        override fun getEncoded(): ByteArray = encodedBytes
        override fun checkValidity() {}
        override fun checkValidity(date: Date?) {}
        override fun getVersion(): Int = 3
        override fun getSerialNumber(): BigInteger = BigInteger.ONE
        override fun getIssuerDN(): Principal = X500Principal("CN=Test")
        override fun getSubjectDN(): Principal = X500Principal("CN=Test")
        override fun getNotBefore(): Date = Date(0)
        override fun getNotAfter(): Date = Date(Long.MAX_VALUE)
        override fun getTBSCertificate(): ByteArray = encodedBytes
        override fun getSignature(): ByteArray = byteArrayOf(1)
        override fun getSigAlgName(): String = "SHA256withRSA"
        override fun getSigAlgOID(): String = "1.2.840.113549.1.1.11"
        override fun getSigAlgParams(): ByteArray? = null
        override fun getIssuerUniqueID(): BooleanArray? = null
        override fun getSubjectUniqueID(): BooleanArray? = null
        override fun getKeyUsage(): BooleanArray? = null
        override fun getBasicConstraints(): Int = -1
        override fun verify(key: PublicKey?) {}
        override fun verify(key: PublicKey?, sigProvider: String?) {}
        override fun toString(): String = "DummyCert"
        override fun getPublicKey(): PublicKey = object : PublicKey {
            override fun getAlgorithm(): String = "RSA"
            override fun getFormat(): String = "X.509"
            override fun getEncoded(): ByteArray = byteArrayOf(1)
        }
        override fun hasUnsupportedCriticalExtension(): Boolean = false
        override fun getCriticalExtensionOIDs(): MutableSet<String> = mutableSetOf()
        override fun getNonCriticalExtensionOIDs(): MutableSet<String> = mutableSetOf()
        override fun getExtensionValue(oid: String?): ByteArray? = null
    }

    private val dispatcher = StandardTestDispatcher()
    private val testScope = TestScope(dispatcher)
    private lateinit var client: SnowWebSocketClient
    private val attempts = mutableListOf<SocketAttempt>()

    private fun fakeHttpResponse(url: String = "https://127.0.0.1:8765"): Response =
        Response.Builder()
            .request(Request.Builder().url(url).build())
            .protocol(Protocol.HTTP_1_1)
            .code(101)
            .message("Switching Protocols")
            .build()

    @Before
    fun setUp() {
        attempts.clear()
        client = SnowWebSocketClient(
            scope = testScope,
            backoffPolicy = BackoffPolicy.batterySchedule(maxJitterMs = 0L),
            certPinStorage = InMemoryCertPinStorage("AA".repeat(32)),
            tokenStorage = InMemoryTokenStorage().apply { saveToken("tok-test") },
            identity = DeviceIdentity(
                deviceId = "11111111-2222-4333-8444-555555555555",
                deviceName = "TestPhone",
                createdAt = "2026-11-27T00:00:00Z"
            ),
            useTls = false
        )
        client.webSocketFactory = { req, listener ->
            val ws = CapturingWebSocket(req.url.toString())
            attempts.add(SocketAttempt(client.currentGeneration, ws, listener))
            ws
        }
    }

    @After
    fun tearDown() {
        client.teardown()
    }

    @Test
    fun `1 old-generation onOpen cannot mark a newer connection connected`() = testScope.runTest {
        client.connect("192.168.1.10", 8765)
        val gen1 = attempts.last()
        client.connect("192.168.1.20", 8765)
        val gen2 = attempts.last()

        assertEquals(ConnectionState.CONNECTING, client.connectionState.value)
        assertTrue(gen2.generation > gen1.generation)

        // Fire obsolete gen1 onOpen while gen2 is CONNECTING
        gen1.listener.onOpen(gen1.socket, fakeHttpResponse())
        runCurrent()

        assertEquals(ConnectionState.CONNECTING, client.connectionState.value)
        assertEquals(AuthState.Connecting, client.authState.value)
        assertNotNull(gen1.socket.closedCode)
        assertTrue(gen2.socket.sentMessages.isEmpty())
    }

    @Test
    fun `2 old-generation onFailure cannot disconnect a newer connection`() = testScope.runTest {
        client.connect("192.168.1.10", 8765)
        val gen1 = attempts.last()
        gen1.listener.onOpen(gen1.socket, fakeHttpResponse())

        client.connect("192.168.1.20", 8765)
        val gen2 = attempts.last()
        gen2.listener.onOpen(gen2.socket, fakeHttpResponse())
        assertEquals(ConnectionState.CONNECTED, client.connectionState.value)

        // Authenticate gen2 cleanly
        val authReq2 = JsonSerialization.fromJson(gen2.socket.sentMessages.first { it.contains("auth_request") })
        gen2.listener.onMessage(
            gen2.socket,
            JsonSerialization.toJson(
                SnowMessage.createResponse(authReq2.id, mapOf("status" to "success", "data" to mapOf("session_id" to "s2")))
            )
        )
        assertTrue(client.authState.value is AuthState.Authenticated)

        // Obsolete gen1 failure arrives late -> must NOT disconnect or reset gen2
        gen1.listener.onFailure(gen1.socket, RuntimeException("stale socket reset"), null)
        runCurrent()

        assertEquals(ConnectionState.CONNECTED, client.connectionState.value)
        assertEquals("s2", (client.authState.value as AuthState.Authenticated).sessionId)
    }

    @Test
    fun `3 old-generation onClosed cannot clear the active socket or change state`() = testScope.runTest {
        client.connect("192.168.1.10", 8765)
        val gen1 = attempts.last()
        gen1.listener.onOpen(gen1.socket, fakeHttpResponse())

        client.connect("192.168.1.20", 8765)
        val gen2 = attempts.last()
        gen2.listener.onOpen(gen2.socket, fakeHttpResponse())

        gen1.listener.onClosed(gen1.socket, 1000, "old closed")
        runCurrent()

        assertEquals(ConnectionState.CONNECTED, client.connectionState.value)
        assertEquals(AuthState.Connecting, client.authState.value)

        // Active gen2 can still send requests cleanly (active socket wasn't cleared)
        client.sendRequest("ping", onResponse = {})
        assertTrue(gen2.socket.sentMessages.any { it.contains("\"ping\"") })
    }

    @Test
    fun `4 old-generation messages cannot mutate current state or reach dispatcher`() = testScope.runTest {
        val dispatched = CopyOnWriteArrayList<String>()
        var revokedCalled = false
        client.onDeviceRevoked = { revokedCalled = true }
        client.requestDispatcher = { action, _ ->
            dispatched.add(action)
            mapOf("ok" to true) to null
        }

        client.connect("192.168.1.10", 8765)
        val gen1 = attempts.last()
        gen1.listener.onOpen(gen1.socket, fakeHttpResponse())

        client.connect("192.168.1.20", 8765)
        val gen2 = attempts.last()
        gen2.listener.onOpen(gen2.socket, fakeHttpResponse())

        val staleRevoke = SnowMessage.createRequest("device_revoked", mapOf("reason" to "stale"))
        val staleAction = SnowMessage.createRequest("android_battery", emptyMap())
        gen1.listener.onMessage(gen1.socket, JsonSerialization.toJson(staleRevoke))
        gen1.listener.onMessage(gen1.socket, JsonSerialization.toJson(staleAction))
        runCurrent()

        assertFalse(revokedCalled)
        assertTrue(dispatched.isEmpty())
        assertEquals(ConnectionState.CONNECTED, client.connectionState.value)
    }

    @Test
    fun `5 old heartbeat failure cannot close newer socket`() = testScope.runTest {
        client.heartbeatIntervalMs = 100L
        client.heartbeatTimeoutMs = 150L
        client.connect("192.168.1.10", 8765)
        val gen1 = attempts.last()
        gen1.listener.onOpen(gen1.socket, fakeHttpResponse())

        // Rotate to gen2
        client.connect("192.168.1.20", 8765)
        val gen2 = attempts.last()
        gen2.listener.onOpen(gen2.socket, fakeHttpResponse())

        // Simulate stale heartbeat failure belonging to gen1
        client.handleHeartbeatFailure(
            reason = "stale heartbeat missed",
            expectedSocket = gen1.socket,
            expectedGeneration = gen1.generation
        )
        runCurrent()

        assertEquals(ConnectionState.CONNECTED, client.connectionState.value)
        assertFalse(gen2.socket.cancelled)
        assertNull(gen2.socket.closedCode)
    }

    @Test
    fun `6 old handshake completion cannot overwrite current authentication state`() = testScope.runTest {
        client.connect("192.168.1.10", 8765)
        val gen1 = attempts.last()
        gen1.listener.onOpen(gen1.socket, fakeHttpResponse())
        val authReq1 = JsonSerialization.fromJson(gen1.socket.sentMessages.first { it.contains("auth_request") })

        // Switch to gen2 (unpaired -> ConnectedUnauthenticated or fresh Connecting)
        client.tokenStorage = InMemoryTokenStorage() // unpaired on gen2
        client.connect("192.168.1.20", 8765)
        val gen2 = attempts.last()
        gen2.listener.onOpen(gen2.socket, fakeHttpResponse())
        assertEquals(AuthState.ConnectedUnauthenticated, client.authState.value)

        // Deliver late gen1 auth_request response directly to gen1 OR spoof on gen2 -> must be ignored
        val lateGen1AuthResp = SnowMessage.createResponse(
            correlationId = authReq1.id,
            payload = mapOf("status" to "success", "data" to mapOf("session_id" to "stale-session"))
        )
        gen1.listener.onMessage(gen1.socket, JsonSerialization.toJson(lateGen1AuthResp))
        gen2.listener.onMessage(gen2.socket, JsonSerialization.toJson(lateGen1AuthResp))
        runCurrent()

        assertEquals(AuthState.ConnectedUnauthenticated, client.authState.value)
    }

    @Test
    fun `7 old trust-manager callback cannot mutate current trust state`() = testScope.runTest {
        client.useTls = true
        client.certPinStorage = InMemoryCertPinStorage(null)
        val notifiedFps = CopyOnWriteArrayList<String>()
        client.onUnconfirmedFingerprint = { fp -> notifiedFps.add(fp) }

        client.connect("192.168.1.10", 8765)
        val gen1TrustMgr = client.getTrustManagerForTest()!!
        val gen1 = attempts.last()

        // Rotate to gen2 and authenticate it
        client.certPinStorage = InMemoryCertPinStorage("CC".repeat(32))
        client.connect("192.168.1.20", 8765)
        val gen2 = attempts.last()
        gen2.listener.onOpen(gen2.socket, fakeHttpResponse())
        client.setAuthenticated("sess-gen2")
        assertTrue(client.authState.value is AuthState.Authenticated)

        // Obsolete gen1 TrustManager receives an unconfirmed cert late -> throws UnconfirmedCertificateException,
        // but its callback MUST NOT overwrite gen2's Authenticated state or notify UI!
        var threw = false
        try {
            gen1TrustMgr.checkServerTrusted(arrayOf(DummyCert(byteArrayOf(7, 8, 9))), "RSA")
        } catch (_: UnconfirmedCertificateException) {
            threw = true
        }
        assertTrue(threw)
        assertTrue(notifiedFps.isEmpty())
        assertTrue(client.authState.value is AuthState.Authenticated)
        assertNotEquals(gen1.generation, gen2.generation)
    }

    @Test
    fun `8 old reconnect job cannot replace current reconnect attempt`() = testScope.runTest {
        client.connect("192.168.1.10", 8765)
        val gen1 = attempts.last()
        // Fail gen1 -> schedules reconnect attempt 1 in 2000ms
        gen1.listener.onFailure(gen1.socket, RuntimeException("drop 1"), null)
        runCurrent()
        assertEquals(ConnectionState.RECONNECTING, client.connectionState.value)

        // Before 2000ms elapses, user updates endpoint / connects cleanly -> creates gen2
        advanceTimeBy(1000L)
        client.connect("192.168.1.99", 8765)
        val gen2 = attempts.last()
        assertEquals(2, attempts.size)
        gen2.listener.onOpen(gen2.socket, fakeHttpResponse())
        assertEquals(ConnectionState.CONNECTED, client.connectionState.value)

        // Advance well past old 2000ms reconnect delay -> gen1 reconnectJob must NOT spawn a 3rd attempt
        advanceTimeBy(5000L)
        runCurrent()
        assertEquals(2, attempts.size)
        assertEquals("192.168.1.99", client.currentTargetHost)
    }

    @Test
    fun `9 concurrent connect reconnect disconnect preserve one active monotonic generation`() = testScope.runTest {
        val threads = 6
        val barrier = CyclicBarrier(threads)
        val errors = CopyOnWriteArrayList<Throwable>()
        val jobs = (0 until threads).map { idx ->
            Thread {
                try {
                    barrier.await(3, TimeUnit.SECONDS)
                    when (idx % 3) {
                        0 -> client.connect("192.168.1.${10 + idx}", 8765)
                        1 -> client.onNetworkRestored("192.168.1.${20 + idx}", 8765)
                        else -> {
                            client.updateTargetEndpoint("192.168.1.${30 + idx}", 8765)
                            client.connect("192.168.1.200", 8765)
                        }
                    }
                } catch (t: Throwable) {
                    errors.add(t)
                }
            }.apply { start() }
        }
        jobs.forEach { it.join(5000) }
        assertTrue("Unexpected concurrency errors: $errors", errors.isEmpty())

        // Final explicit connect settles to single highest active generation
        client.connect("192.168.1.250", 8765)
        val finalAttempt = synchronized(attempts) { attempts.last() }
        assertEquals(finalAttempt.generation, client.currentGeneration)
        finalAttempt.listener.onOpen(finalAttempt.socket, fakeHttpResponse())
        assertEquals(ConnectionState.CONNECTED, client.connectionState.value)

        // All earlier attempts are strictly obsolete
        val prior = attempts.dropLast(1)
        assertTrue(prior.all { it.generation < client.currentGeneration })
    }

    @Test
    fun `10 sendRequest returns false invokes failure callback exactly once and cancels timeout`() = testScope.runTest {
        client.requestTimeoutMs = 40L
        client.connect("192.168.1.10", 8765)
        val attempt = attempts.last()
        attempt.listener.onOpen(attempt.socket, fakeHttpResponse())

        attempt.socket.sendResult = false
        val callbacks = AtomicInteger(0)
        val lastReply = CopyOnWriteArrayList<SnowMessage>()
        client.sendRequest("windows_system_info") { msg ->
            callbacks.incrementAndGet()
            lastReply.add(msg)
        }

        // Wait past 40ms timeout window -> timeout must NOT trigger second callback
        Thread.sleep(150L)
        assertEquals(1, callbacks.get())
        assertEquals(MessageType.ERROR, lastReply.single().type)
        assertTrue(lastReply.single().error?.message?.contains("Failed to send") == true)
    }

    @Test
    fun `11 timeout and response race completes request exactly once`() = testScope.runTest {
        client.connect("192.168.1.10", 8765)
        val attempt = attempts.last()
        attempt.listener.onOpen(attempt.socket, fakeHttpResponse())
        attempt.socket.sentMessages.clear()

        repeat(20) { iter ->
            client.requestTimeoutMs = 15L
            val callbacks = AtomicInteger(0)
            client.sendRequest("ping") {
                callbacks.incrementAndGet()
            }
            val req = JsonSerialization.fromJson(attempt.socket.sentMessages.last())
            val startLatch = CountDownLatch(1)
            val racer = Thread {
                startLatch.await(2, TimeUnit.SECONDS)
                attempt.listener.onMessage(
                    attempt.socket,
                    JsonSerialization.toJson(SnowMessage.createResponse(req.id, mapOf("iter" to iter)))
                )
            }
            racer.start()
            Thread.sleep(if (iter % 2 == 0) 15L else 10L)
            startLatch.countDown()
            racer.join(2000)
            Thread.sleep(30L)
            assertEquals("Double callback on iteration $iter", 1, callbacks.get())
        }
    }

    @Test
    fun `12 explicit connect resets exhausted backoff after MAX_CONNECT_RETRIES`() = testScope.runTest {
        client.connect("192.168.1.10", 8765)

        // Drive all MAX_CONNECT_RETRIES / schedule retries until retry limit exhausted
        val maxAttempts = maxOf(SnowWebSocketClient.MAX_CONNECT_RETRIES, BackoffPolicy.STAGE6C_BATTERY_SCHEDULE_MS.size)
        repeat(maxAttempts) {
            val latest = attempts.last()
            latest.listener.onFailure(latest.socket, RuntimeException("down #$it"), null)
            advanceTimeBy(70_000L)
            runCurrent()
        }

        // One final failure once attempt count reached maxAttempts stops auto-reconnect
        val terminal = attempts.last()
        terminal.listener.onFailure(terminal.socket, RuntimeException("exhausted"), null)
        runCurrent()

        assertEquals(ConnectionState.DISCONNECTED, client.connectionState.value)
        assertTrue(client.authState.value is AuthState.AuthFailed)
        val attemptsBeforeRecovery = attempts.size

        // Explicit connect() MUST reset backoff and allow fresh connection + retry cycle
        client.connect("192.168.1.10", 8765)
        assertEquals(attemptsBeforeRecovery + 1, attempts.size)
        assertEquals(ConnectionState.CONNECTING, client.connectionState.value)
        val recovered = attempts.last()
        recovered.listener.onFailure(recovered.socket, RuntimeException("transient post-reset"), null)
        runCurrent()
        assertEquals(ConnectionState.RECONNECTING, client.connectionState.value)
    }

    @Test
    fun `13 network restoration resets backoff and permits recovery without resetting internal retries`() = testScope.runTest {
        client.connect("192.168.1.10", 8765)

        // Verify internal retries do NOT reset backoff (2000 -> 5000 -> 15000)
        val a1 = attempts.last()
        a1.listener.onFailure(a1.socket, RuntimeException("drop 1"), null)
        runCurrent()
        advanceTimeBy(1999L); runCurrent(); assertEquals(1, attempts.size)
        advanceTimeBy(1L); runCurrent(); assertEquals(2, attempts.size)

        val a2 = attempts.last()
        a2.listener.onFailure(a2.socket, RuntimeException("drop 2"), null)
        runCurrent()
        advanceTimeBy(4999L); runCurrent(); assertEquals(2, attempts.size)
        advanceTimeBy(1L); runCurrent(); assertEquals(3, attempts.size)

        // Exhaust remaining retries
        repeat(4) {
            val next = attempts.last()
            next.listener.onFailure(next.socket, RuntimeException("drop"), null)
            advanceTimeBy(70_000L)
            runCurrent()
        }
        assertEquals(ConnectionState.DISCONNECTED, client.connectionState.value)
        assertTrue(client.authState.value is AuthState.AuthFailed)

        // OS network restoration resets backoff and reconnects immediately
        val countBefore = attempts.size
        assertTrue(client.onNetworkRestored())
        assertEquals(countBefore + 1, attempts.size)
        assertEquals(ConnectionState.CONNECTING, client.connectionState.value)

        // Subsequent failure uses initial 2000ms backoff again (not 60000ms or exhausted)
        val restored = attempts.last()
        restored.listener.onFailure(restored.socket, RuntimeException("transient"), null)
        runCurrent()
        assertEquals(ConnectionState.RECONNECTING, client.connectionState.value)
        advanceTimeBy(2000L); runCurrent()
        assertEquals(countBefore + 2, attempts.size)
    }

    @Test
    fun `14 disconnect and cancellation leave no orphan heartbeat or reconnect jobs`() = testScope.runTest {
        client.heartbeatIntervalMs = 200L
        val parentJob = testScope.coroutineContext[Job]!!

        client.connect("192.168.1.10", 8765)
        val a1 = attempts.last()
        a1.listener.onOpen(a1.socket, fakeHttpResponse())
        a1.listener.onFailure(a1.socket, RuntimeException("lost"), null)
        runCurrent()
        assertEquals(ConnectionState.RECONNECTING, client.connectionState.value)

        client.disconnect()
        advanceTimeBy(120_000L)
        runCurrent()

        assertEquals(ConnectionState.DISCONNECTED, client.connectionState.value)
        assertEquals(1, attempts.size)
        val activeChildren = parentJob.children.filter { it.isActive }.toList()
        assertTrue("Expected zero active orphan coroutine jobs after disconnect, found $activeChildren", activeChildren.isEmpty())
    }
}
