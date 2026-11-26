package org.snow.network

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class Stage6CWs2BatteryTest {

    @Test
    fun testBatteryScheduleMatchesStage6CCappedSteps() {
        assertArrayEquals(
            longArrayOf(2000L, 5000L, 15000L, 30000L, 60000L),
            BackoffPolicy.STAGE6C_BATTERY_SCHEDULE_MS
        )
        val policy = BackoffPolicy.batterySchedule(maxJitterMs = 0L)
        assertEquals(2000L, policy.nextDelayMs())
        assertEquals(5000L, policy.nextDelayMs())
        assertEquals(15000L, policy.nextDelayMs())
        assertEquals(30000L, policy.nextDelayMs())
        assertEquals(60000L, policy.nextDelayMs())
        assertEquals(60000L, policy.nextDelayMs())

        policy.reset()
        assertEquals(2000L, policy.nextDelayMs())
    }

    @Test
    fun testDiscoveryPausePolicyRespectsAuthAndRelayState() {
        val authed = AuthState.Authenticated(sessionId = "sess-ws2")
        // Must NOT pause while disconnected or merely unauthenticated during pairing
        assertFalse(
            DiscoveryManager.shouldPauseDiscovery(
                connectionState = ConnectionState.DISCONNECTED,
                authState = AuthState.Disconnected,
                targetHost = "192.168.1.10"
            )
        )
        assertFalse(
            DiscoveryManager.shouldPauseDiscovery(
                connectionState = ConnectionState.CONNECTED,
                authState = AuthState.ConnectedUnauthenticated,
                targetHost = "192.168.1.10"
            )
        )
        // Must NOT pause when only remote relay is active
        assertFalse(
            DiscoveryManager.shouldPauseDiscovery(
                connectionState = ConnectionState.CONNECTED,
                authState = authed,
                targetHost = "snow-relay.onrender.com"
            )
        )
        // Must pause once local USB or Wi-Fi LAN session is authenticated
        assertTrue(
            DiscoveryManager.shouldPauseDiscovery(
                connectionState = ConnectionState.CONNECTED,
                authState = authed,
                targetHost = "127.0.0.1"
            )
        )
        assertTrue(
            DiscoveryManager.shouldPauseDiscovery(
                connectionState = ConnectionState.CONNECTED,
                authState = authed,
                targetHost = "192.168.1.44"
            )
        )
    }

    @Test
    fun testSnowWebSocketRetryConstantPreserved() {
        assertEquals(3, SnowWebSocketClient.MAX_CONNECT_RETRIES)
    }
}
