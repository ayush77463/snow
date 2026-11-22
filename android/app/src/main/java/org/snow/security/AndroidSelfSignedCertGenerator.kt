package org.snow.security

import java.io.ByteArrayInputStream
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.security.auth.x500.X500Principal

/**
 * Pure standard Java/Android generator for self-signed TLS certificates and SSLContext.
 *
 * Guarantees:
 * - Operates without external BouncyCastle or third-party dependencies.
 * - Generates standard 2048-bit RSA key pairs.
 * - Encodes standard X.509 v1 ASN.1 DER certificates valid for 365 days.
 * - Produces normalized colon-delimited SHA-256 certificate fingerprints.
 * - Configures TLS 1.2+ server [SSLContext] with in-memory PKCS12/BKS keystore.
 */
object AndroidSelfSignedCertGenerator {

    private const val TAG = "AndroidSelfSignedCertGenerator"

    data class GeneratedCertResult(
        val sslContext: SSLContext,
        val certificate: X509Certificate,
        val keyPair: KeyPair,
        val fingerprint: String
    )

    /**
     * Generate an RSA 2048 keypair, self-signed X.509 certificate, and initialized SSLContext.
     */
    fun generate(
        alias: String = "snow-peer-host",
        commonName: String = "SNOW-Android-PeerHost"
    ): GeneratedCertResult {
        // 1. Generate RSA 2048 KeyPair
        val kpg = KeyPairGenerator.getInstance("RSA")
        kpg.initialize(2048, SecureRandom())
        val keyPair = kpg.generateKeyPair()

        // 2. Generate self-signed X.509 Certificate in DER format
        val cert = generateSelfSignedCertificate(keyPair, commonName)

        // 3. Compute SHA-256 Fingerprint
        val md = MessageDigest.getInstance("SHA-256")
        val rawFp = md.digest(cert.encoded)
        val formattedFp = TlsConfig.formatFingerprint(rawFp)

        // 4. Initialize in-memory KeyStore and SSLContext
        val password = "snow-internal-keystore".toCharArray()
        val keyStore = try {
            KeyStore.getInstance("PKCS12")
        } catch (_: Exception) {
            KeyStore.getInstance(KeyStore.getDefaultType())
        }
        keyStore.load(null, null)
        keyStore.setKeyEntry(alias, keyPair.private, password, arrayOf(cert))

        val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
        kmf.init(keyStore, password)

        val sslContext = SSLContext.getInstance("TLS")
        sslContext.init(kmf.keyManagers, null, SecureRandom())

        SafeLog.i(TAG, "Generated self-signed TLS cert [CN=$commonName, SHA-256=$formattedFp]")
        return GeneratedCertResult(
            sslContext = sslContext,
            certificate = cert,
            keyPair = keyPair,
            fingerprint = formattedFp
        )
    }

    private fun derLength(length: Int): ByteArray {
        return when {
            length < 128 -> byteArrayOf(length.toByte())
            length < 256 -> byteArrayOf(0x81.toByte(), length.toByte())
            length < 65536 -> byteArrayOf(0x82.toByte(), (length shr 8).toByte(), (length and 0xFF).toByte())
            else -> byteArrayOf(
                0x83.toByte(),
                (length shr 16).toByte(),
                ((length shr 8) and 0xFF).toByte(),
                (length and 0xFF).toByte()
            )
        }
    }

    private fun derSequence(content: ByteArray): ByteArray {
        val len = derLength(content.size)
        return byteArrayOf(0x30) + len + content
    }

    private fun generateSelfSignedCertificate(keyPair: KeyPair, commonName: String): X509Certificate {
        // Serial Number: BigInteger from current timestamp
        val serialBytes = BigInteger.valueOf(System.currentTimeMillis()).toByteArray()
        val derSerial = byteArrayOf(0x02) + derLength(serialBytes.size) + serialBytes

        // Signature Algorithm Identifier: SHA256withRSA (OID 1.2.840.113549.1.1.11, NULL parameters)
        val sha256WithRsaOid = byteArrayOf(
            0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86.toByte(), 0x48,
            0x86.toByte(), 0xF7.toByte(), 0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00
        )

        // Issuer & Subject: X500Principal Name DER
        val nameDer = X500Principal("CN=$commonName").encoded

        // Validity: 1 day past to 365 days future
        val sdf = SimpleDateFormat("yyMMddHHmmss'Z'", Locale.US).apply {
            timeZone = TimeZone.getTimeZone("UTC")
        }
        val notBeforeStr = sdf.format(Date(System.currentTimeMillis() - 86400000L))
        val notAfterStr = sdf.format(Date(System.currentTimeMillis() + 365L * 86400000L))

        val notBeforeBytes = notBeforeStr.toByteArray(Charsets.US_ASCII)
        val notAfterBytes = notAfterStr.toByteArray(Charsets.US_ASCII)
        val notBeforeDer = byteArrayOf(0x17) + derLength(notBeforeBytes.size) + notBeforeBytes
        val notAfterDer = byteArrayOf(0x17) + derLength(notAfterBytes.size) + notAfterBytes
        val validityDer = derSequence(notBeforeDer + notAfterDer)

        // SubjectPublicKeyInfo: Already standard X.509 DER encoded in PublicKey
        val spkiDer = keyPair.public.encoded

        // Assemble TBSCertificate SEQUENCE
        val tbsBytes = derSequence(derSerial + sha256WithRsaOid + nameDer + validityDer + nameDer + spkiDer)

        // Sign TBSCertificate with RSA private key
        val signer = Signature.getInstance("SHA256withRSA")
        signer.initSign(keyPair.private)
        signer.update(tbsBytes)
        val sigValue = signer.sign()

        // BIT STRING wrapper for signature (0 unused bits prefix)
        val bitStringSig = byteArrayOf(0x03) + derLength(sigValue.size + 1) + byteArrayOf(0x00) + sigValue

        // Final Certificate SEQUENCE
        val certDer = derSequence(tbsBytes + sha256WithRsaOid + bitStringSig)

        val certFactory = CertificateFactory.getInstance("X.509")
        return certFactory.generateCertificate(ByteArrayInputStream(certDer)) as X509Certificate
    }
}
