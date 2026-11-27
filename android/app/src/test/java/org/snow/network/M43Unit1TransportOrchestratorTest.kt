package org.snow.network

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.snow.service.SnowForegroundService

/**
 * Stage 2 & 5 unit tests for SNOW TransportOrchestrator:
 * - Strict priority order: USB (0) > Hotspot (1) > Wi-Fi LAN (2) > Remote Relay (3)
 * - Hotspot subnet & interface detection
 * - Verification TTL expiry and cooldown handling
 * - Fail-closed manual selection & error redaction
 */
class M43Unit1TransportOrchestratorTest {

    @Test
    fun canonicalPriorityOrderAndHotspotClassification() {
        assertEquals(0, TransportClassifier.classifyRoutePriority(transport = "usb", host = "127.0.0.1"))
        assertEquals(1, TransportClassifier.classifyRoutePriority(host = "192.168.43.1"))
        assertEquals(2, TransportClassifier.classifyRoutePriority(host = "192.168.1.42"))
        assertEquals(3, TransportClassifier.classifyRoutePriority(transport = "remote_relay", host = "relay.onrender.com"))

        assertEquals("USB • Zero Data", TransportClassifier.classifyTransportBadge(host = "127.0.0.1"))
        assertEquals("Hotspot • Zero Data", TransportClassifier.classifyTransportBadge(host = "192.168.43.1"))
        assertEquals("Hotspot • Zero Data", TransportClassifier.classifyTransportBadge(host = "10.0.0.2", interfaceName = "swlan0"))
        assertEquals("Wi-Fi • Zero Data", TransportClassifier.classifyTransportBadge(host = "192.168.1.25"))
        assertEquals("Remote • Uses Data", TransportClassifier.classifyTransportBadge(transport = "remote_relay"))

        // Hotspot beats Wi-Fi LAN when evaluating candidates
        val candidates = listOf(
            RouteCandidateEntry(deviceId = "d1", route = TransportRoute.WIFI_LAN, host = "192.168.1.25", state = RouteState.VERIFIED_AVAILABLE, verified = true),
            RouteCandidateEntry(deviceId = "d1", route = TransportRoute.HOTSPOT, host = "192.168.43.1", state = RouteState.VERIFIED_AVAILABLE, verified = true),
            RouteCandidateEntry(deviceId = "d1", route = TransportRoute.REMOTE_RELAY, host = "relay", state = RouteState.VERIFIED_AVAILABLE, verified = true)
        )
        val best = TransportOrchestrator.evaluatePreferredCandidate(candidates, TransportMode.AUTO)
        assertNotNull(best)
        assertEquals(TransportRoute.HOTSPOT, best!!.route)
    }

    @Test
    fun verificationTtlExpiryAndManualFailClosed() {
        var fakeClockMs = 10_000L
        val orch = TransportOrchestrator(
            verificationTtlMs = 5_000L,
            probeCooldownMs = 3_000L,
            clockMs = { fakeClockMs }
        )
        orch.markVerified("pc-1", TransportRoute.WIFI_LAN, host = "192.168.1.10", isActive = true)
        assertTrue(orch.snapshotFor("pc-1").routes.first { it.route == TransportRoute.WIFI_LAN }.verified)

        // Manual switch to unverified Hotspot MUST fail closed and leave Wi-Fi active
        val (badOk, _) = orch.setMode("pc-1", TransportMode.HOTSPOT)
        assertFalse(badOk)
        assertEquals(TransportMode.AUTO, orch.getMode("pc-1"))
        assertEquals(TransportRoute.WIFI_LAN, orch.snapshotFor("pc-1").activeRoute)

        // Advance past verification TTL -> Wi-Fi expires and is marked unavailable
        fakeClockMs += 6_000L
        val wifiAfterExpiry = orch.snapshotFor("pc-1").routes.first { it.route == TransportRoute.WIFI_LAN }
        assertFalse(wifiAfterExpiry.verified)
        assertTrue(wifiAfterExpiry.expired)
        assertNull(orch.snapshotFor("pc-1").activeRoute)
    }

    @Test
    fun usbAutoProbeBlockedWhenManualNonUsbModeSetAndErrorsRedacted() {
        assertFalse(
            SnowForegroundService.shouldProbeUsbPromotion(
                connectionMode = "hotspot",
                userDisconnected = false,
                isConnected = true,
                isAuthenticated = true,
                currentHost = "192.168.43.1",
                nowMs = 10_000L,
                lastAttemptMs = 0L
            )
        )
        assertFalse(
            SnowForegroundService.shouldProbeUsbPromotion(
                connectionMode = "wifi_lan",
                userDisconnected = false,
                isConnected = true,
                isAuthenticated = true,
                currentHost = "192.168.1.5",
                nowMs = 10_000L,
                lastAttemptMs = 0L
            )
        )
        assertTrue(
            SnowForegroundService.shouldProbeUsbPromotion(
                connectionMode = "auto",
                userDisconnected = false,
                isConnected = true,
                isAuthenticated = true,
                currentHost = "192.168.43.1",
                nowMs = 10_000L,
                lastAttemptMs = 0L
            )
        )

        val clean = TransportClassifier.sanitizeTransportError("Authorization Bearer tok12345 failed")
        assertFalse(clean.contains("tok12345"))
    }
}
