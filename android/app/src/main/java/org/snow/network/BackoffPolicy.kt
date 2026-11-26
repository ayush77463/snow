package org.snow.network

import kotlin.math.min
import kotlin.math.pow
import kotlin.random.Random

class BackoffPolicy(
    val initialDelayMs: Long = 1000L,
    val maxDelayMs: Long = 30000L,
    val multiplier: Double = 2.0,
    val maxJitterMs: Long = 500L,
    val customScheduleMs: LongArray? = null
) {
    companion object {
        val STAGE6C_BATTERY_SCHEDULE_MS = longArrayOf(2000L, 5000L, 15000L, 30000L, 60000L)

        fun batterySchedule(maxJitterMs: Long = 0L): BackoffPolicy = BackoffPolicy(
            initialDelayMs = 2000L,
            maxDelayMs = 60000L,
            multiplier = 2.0,
            maxJitterMs = maxJitterMs,
            customScheduleMs = STAGE6C_BATTERY_SCHEDULE_MS
        )
    }

    private var attempts: Int = 0

    @Synchronized
    fun nextDelayMs(random: Random = Random.Default): Long {
        val schedule = customScheduleMs
        val cappedDelay = if (schedule != null && schedule.isNotEmpty()) {
            schedule[min(attempts, schedule.lastIndex)]
        } else {
            val baseDelay = (initialDelayMs * multiplier.pow(attempts.toDouble())).toLong()
            min(baseDelay, maxDelayMs)
        }
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

    fun scheduleStepCount(): Int = customScheduleMs?.size ?: 0
}
