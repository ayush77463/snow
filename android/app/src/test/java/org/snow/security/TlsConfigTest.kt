package org.snow.security

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.ByteArrayInputStream
import java.security.KeyPairGenerator
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Date

/**
 * Unit tests for TLS configuration, SHA-256 fingerprinting, certificate pinning,
 * and Trust-On-First-Use (TOFU) verification.
 */
class TlsConfigTest {

    private fun generateTestCertificate(): X509Certificate {
        val certPem = """
            -----BEGIN CERTIFICATE-----
            MIIDRjCCAi6gAwIBAgIUc3UI/KzVMYkBGp2fRmeKEO7TWfYwDQYJKoZIhvcNAQEL
            BQAwPTEaMBgGA1UEAwwRU05PVy1EZXNrdG9wLUNvcmUxHzAdBgNVBAoMFlNOT1cg
            Q2FwYWJpbGl0eSBCcmlkZ2UwHhcNMjYxMTE2MDcwNjE1WhcNMjcxMTE2MDcxMTE1
            WjA9MRowGAYDVQQDDBFTTk9XLURlc2t0b3AtQ29yZTEfMB0GA1UECgwWU05PVyBD
            YXBhYmlsaXR5IEJyaWRnZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
            AI7cs9xflAIpq7iakymlJkoOm44PXtQcZ2hMAJenr0W3AtXZxYTwJfG/IpnAS8X5
            Py3PSxCatrXLwQZL7rHx5oeS5eqm0csCTXlksGE0UuOAdE3kLqiKc3lYNd0M3YK1
            4VcnRKKZUPnygPO9iTdJCjbIu8TjMZj1OWg3lapsBRjeHYSEYFY8Fzz8J1Qp01ez
            pgXG8t38qGKhlv7UpIi5m9ZNycM5rMPj8QQI/Mp9J6SWV+0ifk0BOzTFDXkL1iOK
            Xh4xIVwni6MjHtdm2iSnH6HcJTUW4QINiMLzRvxXUH4ey4J6neRmYZ/C24gX8i5e
            OO7rRkKEwqx4WllRCKmB7MMCAwEAAaM+MDwwLAYDVR0RBCUwI4IJbG9jYWxob3N0
            hwR/AAABhwQAAAAAggpMZW5vdm9fVjE1MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcN
            AQELBQADggEBAFbwWd6aXMwmQOWmegnmuVNmhBZuGlVtpBhH3ZEMnKoHcWFKMG67
            D7CR5rCjmIKNUPoe0YNVky700SgzvF3q93ug7A/PjeZE0uP03mMzSYriY8yw7mPa
            e1vitkvMo0oKO042WGPWspACQ5oi2DAcwum/j2fU/hhprfJFpuKx9PyLAmOO9SmI
            iu2BSL4XhR9sWnjgfQwAnILenBkq7CQ8IfaBHjz5B5f+lTHGLXd+bMhgGpqMt35S
            vJCnnKujkwtdwMChd/Bo5u7+FV8KZ7QO64JGqh7BipHJ1B/izGbQyoDz5kIgzWNd
            wtzm/Ume+xLFe7gM1Ah5bSQtHtW2Gzhbc8I=
            -----END CERTIFICATE-----
        """.trimIndent()
        val cf = CertificateFactory.getInstance("X.509")
        return cf.generateCertificate(ByteArrayInputStream(certPem.toByteArray(Charsets.UTF_8))) as X509Certificate
    }

    @Test
    fun testFingerprintCalculationAndFormatting() {
        val cert = generateTestCertificate()
        val fp = TlsConfig.computeSha256Fingerprint(cert)

        assertNotNull(fp)
        assertEquals(32 * 3 - 1, fp.length) // 32 hex bytes with colons = 95 characters
        assertTrue(fp.contains(":"))
        assertEquals(fp.uppercase(), fp)
    }

    @Test
    fun testFingerprintNormalization() {
        val raw = "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99"
        val noColons = "AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899"
        val lowerWithSpaces = "aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99"

        assertEquals(raw, TlsConfig.formatFingerprint(noColons))
        assertTrue(TlsConfig.fingerprintsMatch(raw, lowerWithSpaces))
        assertTrue(TlsConfig.fingerprintsMatch(noColons, raw))
    }

    @Test
    fun testInvalidFingerprintLengthThrows() {
        try {
            TlsConfig.formatFingerprint("TOO_SHORT")
            fail("Expected IllegalArgumentException for invalid length")
        } catch (_: IllegalArgumentException) {
            // Success
        }
    }

    @Test
    fun testInMemoryPinStorageLifecycle() {
        val storage = InMemoryCertPinStorage()
        assertNull(storage.getPinnedFingerprint())

        val fp = "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99"
        storage.pinFingerprint(fp)
        assertEquals(fp, storage.getPinnedFingerprint())

        storage.clearPinnedFingerprint()
        assertNull(storage.getPinnedFingerprint())
    }

    @Test
    fun testTrustManagerAllowsMatchingPinnedCertificate() {
        val cert = generateTestCertificate()
        val fp = TlsConfig.computeSha256Fingerprint(cert)

        val storage = InMemoryCertPinStorage(fp)
        val trustManager = SnowTrustManager(storage)

        // Must succeed without throwing
        trustManager.checkServerTrusted(arrayOf(cert), "RSA")
        assertEquals(fp, trustManager.lastPresentedFingerprint)
    }

    @Test
    fun testTrustManagerRejectsMismatchedCertificate() {
        val cert = generateTestCertificate()
        val correctFp = TlsConfig.computeSha256Fingerprint(cert)
        val wrongFp = "00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF"

        val storage = InMemoryCertPinStorage(wrongFp)
        val trustManager = SnowTrustManager(storage)

        try {
            trustManager.checkServerTrusted(arrayOf(cert), "RSA")
            fail("Expected CertificateMismatchException")
        } catch (e: CertificateMismatchException) {
            assertEquals(wrongFp, e.pinnedFingerprint)
            assertEquals(correctFp, e.presentedFingerprint)
        }
    }

    @Test
    fun testTrustManagerUnpinnedRequiresFirstUseConfirmation() {
        val cert = generateTestCertificate()
        val expectedFp = TlsConfig.computeSha256Fingerprint(cert)

        val storage = InMemoryCertPinStorage(null) // Unpinned
        var capturedFp: String? = null
        val trustManager = SnowTrustManager(storage) { presented ->
            capturedFp = presented
        }

        try {
            trustManager.checkServerTrusted(arrayOf(cert), "RSA")
            fail("Expected UnconfirmedCertificateException")
        } catch (e: UnconfirmedCertificateException) {
            assertEquals(expectedFp, e.presentedFingerprint)
            assertEquals(expectedFp, capturedFp)
        }
    }
}
