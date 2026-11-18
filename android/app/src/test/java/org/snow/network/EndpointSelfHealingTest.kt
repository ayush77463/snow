package org.snow.network

import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.snow.protocol.Constants
import org.snow.security.InMemoryCertPinStorage

@OptIn(ExperimentalCoroutinesApi::class)
class EndpointSelfHealingTest {

    private val testDispatcher = StandardTestDispatcher()
    private val testScope = TestScope(testDispatcher)

    private val validSha256FingerprintDesktop = "A".repeat(64)
    private val validSha256FingerprintOther = "B".repeat(64)
    private val desktopDeviceId = "550e8400-e29b-41d4-a716-446655440000"

    private lateinit var certPinStorage: InMemoryCertPinStorage
    private lateinit var discoveryManager: DiscoveryManager
    private lateinit var client: SnowWebSocketClient

    @Before
    fun setUp() {
        certPinStorage = InMemoryCertPinStorage(validSha256FingerprintDesktop)
        discoveryManager = DiscoveryManager(
            scope = testScope,
            certPinStorage = certPinStorage
        )
        client = SnowWebSocketClient(
            scope = testScope,
            certPinStorage = certPinStorage,
            useTls = false
        )
    }

    @Test
    fun testUpdateTargetEndpointWithNewIpTriggersReconnection() {
        // Initial setup
        client.connect("192.168.1.50", 8765)
        assertEquals("192.168.1.50", client.currentTargetHost)
        assertEquals(8765, client.currentTargetPort)

        // When a new IP is detected from discovery
        val updated = client.updateTargetEndpoint("192.168.1.60", 8765)
        assertTrue("Endpoint update with new IP must initiate reconnect", updated)
        assertEquals("192.168.1.60", client.currentTargetHost)
        assertEquals(8765, client.currentTargetPort)
    }

    @Test
    fun testUpdateTargetEndpointSameIpWhileConnectingOrConnectedIsNoOp() {
        client.connect("192.168.1.50", 8765)
        // Client state is CONNECTING immediately after connect()
        assertEquals(ConnectionState.CONNECTING, client.connectionState.value)

        val updated = client.updateTargetEndpoint("192.168.1.50", 8765)
        assertFalse("Same IP while CONNECTING must be a no-op to prevent connection storms", updated)
    }

    @Test
    fun testUpdateTargetEndpointBlankHostIsRejected() {
        client.connect("192.168.1.50", 8765)
        val updated = client.updateTargetEndpoint("   ", 8765)
        assertFalse("Blank host must be rejected", updated)
        assertEquals("192.168.1.50", client.currentTargetHost)
    }

    @Test
    fun testUpdateTargetEndpointSuppressedAfterUserDisconnect() {
        client.connect("192.168.1.50", 8765)
        client.disconnect()
        assertEquals(ConnectionState.DISCONNECTED, client.connectionState.value)

        // Calling updateTargetEndpoint with same endpoint while user disconnected
        val updated = client.updateTargetEndpoint("192.168.1.50", 8765)
        assertFalse("Same endpoint must not reconnect after explicit user disconnect", updated)
    }

    @Test
    fun testDiscoveryCandidateMatchesPinnedFingerprint() {
        val peerMatching = DiscoveredPeer(
            deviceId = desktopDeviceId,
            deviceName = "Ayush-Desktop",
            deviceType = "windows",
            ipAddress = "192.168.1.75",
            port = 8765,
            transferPort = 8766,
            certFingerprint = validSha256FingerprintDesktop,
            lastSeenTimestamp = System.currentTimeMillis()
        )
        discoveryManager.handleDiscoveredPeer(peerMatching)

        val candidate = discoveryManager.getCandidateForPairedDesktop(desktopDeviceId)
        assertNotNull("Matching beacon must resolve to candidate", candidate)
        assertEquals("192.168.1.75", candidate?.ipAddress)
        assertEquals(8765, candidate?.port)
        assertTrue(candidate?.isPaired == true)
    }

    @Test
    fun testDiscoveryRejectsWrongFingerprintAndWrongDeviceId() {
        val untrustedPeer = DiscoveredPeer(
            deviceId = "unpaired-foreign-id",
            deviceName = "Rogue-Desktop",
            deviceType = "windows",
            ipAddress = "192.168.1.99",
            port = 8765,
            transferPort = 8766,
            certFingerprint = validSha256FingerprintOther,
            lastSeenTimestamp = System.currentTimeMillis()
        )
        discoveryManager.handleDiscoveredPeer(untrustedPeer)

        val candidate = discoveryManager.getCandidateForPairedDesktop(desktopDeviceId)
        assertNull("Beacon with mismatching fingerprint and id must not resolve", candidate)
    }

    @Test
    fun testDiscoveryRejectsStaleBeacon() {
        val stalePeer = DiscoveredPeer(
            deviceId = desktopDeviceId,
            deviceName = "Ayush-Desktop",
            deviceType = "windows",
            ipAddress = "192.168.1.75",
            port = 8765,
            transferPort = 8766,
            certFingerprint = validSha256FingerprintDesktop,
            lastSeenTimestamp = System.currentTimeMillis() - 15_000L // 15 seconds ago (> 10s stale timeout)
        )
        discoveryManager.handleDiscoveredPeer(stalePeer)

        val candidate = discoveryManager.getCandidateForPairedDesktop(desktopDeviceId)
        assertNull("Stale beacon must be ignored", candidate)
    }

    @Test
    fun testDiscoveryMatchesDeviceIdWhenFingerprintStorageEmpty() {
        // In unpinned / legacy or first discovery stage
        val emptyStorage = InMemoryCertPinStorage(null)
        val mgr = DiscoveryManager(scope = testScope, certPinStorage = emptyStorage)

        val peer = DiscoveredPeer(
            deviceId = desktopDeviceId,
            deviceName = "Ayush-Desktop",
            deviceType = "windows",
            ipAddress = "192.168.1.80",
            port = 8765,
            transferPort = 8766,
            certFingerprint = validSha256FingerprintDesktop,
            lastSeenTimestamp = System.currentTimeMillis()
        )
        mgr.handleDiscoveredPeer(peer)

        val candidate = mgr.getCandidateForPairedDesktop(desktopDeviceId)
        assertNotNull("Candidate should match on paired device ID even if cert pin storage is empty", candidate)
        assertEquals("192.168.1.80", candidate?.ipAddress)
    }
}
