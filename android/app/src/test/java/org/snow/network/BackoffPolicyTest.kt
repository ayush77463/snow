package org.snow.network

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import kotlin.random.Random

class BackoffPolicyTest {

    @Test
    fun testExponentialProgressionWithoutJitter() {
        val policy = BackoffPolicy(
            initialDelayMs = 1000L,
            maxDelayMs = 30000L,
            multiplier = 2.0,
            maxJitterMs = 0L
        )

        assertEquals(1000L, policy.nextDelayMs())
        assertEquals(2000L, policy.nextDelayMs())
        assertEquals(4000L, policy.nextDelayMs())
        assertEquals(8000L, policy.nextDelayMs())
        assertEquals(16000L, policy.nextDelayMs())
        assertEquals(30000L, policy.nextDelayMs()) // Capped at maxDelayMs
        assertEquals(30000L, policy.nextDelayMs()) // Stays capped
    }

    @Test
    fun testReset() {
        val policy = BackoffPolicy(initialDelayMs = 1000L, maxJitterMs = 0L)
        policy.nextDelayMs() // 1000
        policy.nextDelayMs() // 2000
        assertEquals(2, policy.currentAttempt)

        policy.reset()
        assertEquals(0, policy.currentAttempt)
        assertEquals(1000L, policy.nextDelayMs())
    }

    @Test
    fun testJitterBounds() {
        val policy = BackoffPolicy(
            initialDelayMs = 1000L,
            maxDelayMs = 30000L,
            maxJitterMs = 500L
        )
        val dummyRandom = Random(42)
        val delay = policy.nextDelayMs(dummyRandom)
        assertTrue("Delay $delay should be between 1000 and 1500", delay in 1000L..1500L)
    }
}
