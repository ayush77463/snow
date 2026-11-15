package org.snow.network

import kotlin.math.min
import kotlin.math.pow
import kotlin.random.Random

class BackoffPolicy(
    val initialDelayMs: Long = 1000L,
    val maxDelayMs: Long = 30000L,
    val multiplier: Double = 2.0,
    val maxJitterMs: Long = 500L
) {
    private var attempts: Int = 0

    @Synchronized
    fun nextDelayMs(random: Random = Random.Default): Long {
        val baseDelay = (initialDelayMs * multiplier.pow(attempts.toDouble())).toLong()
        val cappedDelay = min(baseDelay, maxDelayMs)
        val jitter = if (maxJitterMs > 0) random.nextLong(0, maxJitterMs + 1) else 0L
        attempts++
        return cappedDelay + jitter
    }

    @Synchronized
    fun reset() {
        attempts = 0
    }

    val currentAttempt: Int
        @Synchronized get() = attempts
}
