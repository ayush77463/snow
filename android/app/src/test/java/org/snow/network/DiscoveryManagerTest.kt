package org.snow.network

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.snow.security.InMemoryCertPinStorage

class DiscoveryManagerTest {

    private val validSha256FingerprintA = "A".repeat(64)
    private val validSha256FingerprintB = "B".repeat(64)

    private fun createBeaconJson(
        proto: String = "snow-discovery",
        version: Int = 1,
        deviceId: String = "test-desktop-uuid-1234",
        deviceName: String = "Ayush-Legion",
        port: Int = 8765,
        transferPort: Int = 8766,
        certFingerprint: String = validSha256FingerprintA,
        timestamp: Double = System.currentTimeMillis() / 1000.0
    ): String {
        return JSONObject().apply {
            put("proto", proto)
            put("v", version)
            put("device_id", deviceId)
            put("device_name", deviceName)
            put("device_type", "windows")
            put("port", port)
            put("transfer_port", transferPort)
            put("cert_fingerprint", certFingerprint)
            put("timestamp", timestamp)
            put("nonce", "0123456789abcdef")
        }.toString()
    }

    @Test
    fun testValidBeaconParsing() {
        val nowMs = System.currentTimeMillis()
        val raw = createBeaconJson(timestamp = nowMs / 1000.0).toByteArray(Charsets.UTF_8)
        val peer = DiscoveryManager.parseBeacon(raw, raw.size, "192.168.1.150", nowMs)

        assertNotNull("Expected valid peer from correct beacon", peer)
        assertEquals("test-desktop-uuid-1234", peer?.deviceId)
        assertEquals("Ayush-Legion", peer?.deviceName)
        assertEquals("windows", peer?.deviceType)
        assertEquals("192.168.1.150", peer?.ipAddress)
        assertEquals(8765, peer?.port)
        assertEquals(8766, peer?.transferPort)
        assertEquals(validSha256FingerprintA, peer?.certFingerprint)
        assertFalse(peer?.isStale ?: true)
    }

    @Test
    fun testMalformedJsonRejected() {
        val raw = "NOT_JSON_DATA".toByteArray(Charsets.UTF_8)
        val peer = DiscoveryManager.parseBeacon(raw, raw.size, "192.168.1.150")
        assertNull("Malformed JSON should be rejected", peer)
    }

    @Test
    fun testOversizedBeaconRejected() {
        val hugeJson = JSONObject().apply {
            put("proto", "snow-discovery")
            put("v", 1)
            put("device_id", "id")
            put("port", 8765)
            put("timestamp", 1740000000.0)
            put("padding", "x".repeat(3000))
        }.toString().toByteArray(Charsets.UTF_8)

        val peer = DiscoveryManager.parseBeacon(hugeJson, hugeJson.size, "192.168.1.150")
        assertNull("Beacon exceeding MAX_BEACON_SIZE must be rejected", peer)
    }

    @Test
    fun testInvalidProtocolOrVersionRejected() {
        val badProto = createBeaconJson(proto = "other-protocol").toByteArray(Charsets.UTF_8)
        assertNull(DiscoveryManager.parseBeacon(badProto, badProto.size, "192.168.1.150"))

        val badVersion = createBeaconJson(version = 2).toByteArray(Charsets.UTF_8)
        assertNull(DiscoveryManager.parseBeacon(badVersion, badVersion.size, "192.168.1.150"))
    }

    @Test
    fun testPortBoundsValidation() {
        val zeroPort = createBeaconJson(port = 0).toByteArray(Charsets.UTF_8)
        assertNull(DiscoveryManager.parseBeacon(zeroPort, zeroPort.size, "192.168.1.150"))

        val highPort = createBeaconJson(port = 70000).toByteArray(Charsets.UTF_8)
        assertNull(DiscoveryManager.parseBeacon(highPort, highPort.size, "192.168.1.150"))
    }

    @Test
    fun testTimestampDriftValidation() {
        val nowMs = 1740000000000L

        // Past drift > 30s
        val staleTs = createBeaconJson(timestamp = 1739999900.0).toByteArray(Charsets.UTF_8)
        assertNull(DiscoveryManager.parseBeacon(staleTs, staleTs.size, "192.168.1.150", nowMs))

        // Future drift > 30s
        val futureTs = createBeaconJson(timestamp = 1740000100.0).toByteArray(Charsets.UTF_8)
        assertNull(DiscoveryManager.parseBeacon(futureTs, futureTs.size, "192.168.1.150", nowMs))

        // Acceptable drift (10s)
        val validTs = createBeaconJson(timestamp = 1740000010.0).toByteArray(Charsets.UTF_8)
        assertNotNull(DiscoveryManager.parseBeacon(validTs, validTs.size, "192.168.1.150", nowMs))
    }

    @Test
    fun testCandidateResolutionWithPinnedFingerprint() {
        val pinStorage = InMemoryCertPinStorage(validSha256FingerprintB)
        val mgr = DiscoveryManager(certPinStorage = pinStorage)

        val peerA = DiscoveredPeer(
            deviceId = "dev-a",
            deviceName = "Host-A",
            deviceType = "windows",
            ipAddress = "192.168.1.10",
            port = 8765,
            transferPort = 8766,
            certFingerprint = validSha256FingerprintA,
            lastSeenTimestamp = System.currentTimeMillis()
        )

        val peerB = DiscoveredPeer(
            deviceId = "dev-b",
            deviceName = "Host-B",
            deviceType = "windows",
            ipAddress = "192.168.1.20",
            port = 8765,
            transferPort = 8766,
            certFingerprint = validSha256FingerprintB,
            lastSeenTimestamp = System.currentTimeMillis()
        )

        mgr.handleDiscoveredPeer(peerA)
        mgr.handleDiscoveredPeer(peerB)

        val candidate = mgr.getCandidateForPairedDesktop()
        assertNotNull("Candidate matching pinned cert should be found", candidate)
        assertEquals("dev-b", candidate?.deviceId)
        assertEquals("192.168.1.20", candidate?.ipAddress)
        assertTrue(candidate?.isPaired == true)
    }

    @Test
    fun testStalePeerDetection() {
        val oldPeer = DiscoveredPeer(
            deviceId = "dev-old",
            deviceName = "Old-Host",
            deviceType = "windows",
            ipAddress = "192.168.1.99",
            port = 8765,
            transferPort = 8766,
            certFingerprint = validSha256FingerprintA,
            lastSeenTimestamp = System.currentTimeMillis() - 15_000L
        )
        assertTrue("Peer unseen for > 10s should be marked stale", oldPeer.isStale)
    }
}
