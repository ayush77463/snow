package org.snow.security

import android.content.Context
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.math.BigInteger
import java.security.GeneralSecurityException
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.text.SimpleDateFormat
import java.util.Base64
import java.util.Date
import java.util.Locale
import java.util.TimeZone
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.security.auth.x500.X500Principal

/**
 * Abstract persistence backend for Android Peer Host PKCS#12 identity material.
 * Allows both AES-GCM encrypted on-device storage and deterministic JVM unit test storage.
 */
interface PeerHostCertStorage {
    /** Load serialized PKCS#12 keystore bytes and its char-array password, or null if absent. Throws on corruption. */
    fun loadKeyStoreMaterial(): Pair<ByteArray, CharArray>?

    /** Persist serialized PKCS#12 keystore bytes and its char-array password atomically. */
    fun saveKeyStoreMaterial(pkcs12Bytes: ByteArray, password: CharArray)

    /** Remove any persisted keystore material cleanly (used on fail-closed reset or trust wipe). */
    fun clear()
}

/**
 * In-memory PeerHostCertStorage for JVM unit tests across simulated host restarts.
 */
class InMemoryPeerHostCertStorage : PeerHostCertStorage {
    private var bytes: ByteArray? = null
    private var password: CharArray? = null
    var corrupted: Boolean = false

    override fun loadKeyStoreMaterial(): Pair<ByteArray, CharArray>? {
        if (corrupted) {
            throw GeneralSecurityException("Simulated corrupted persisted keystore")
        }
        val b = bytes ?: return null
        val p = password ?: return null
        return b.copyOf() to p.copyOf()
    }

    override fun saveKeyStoreMaterial(pkcs12Bytes: ByteArray, password: CharArray) {
        corrupted = false
        bytes = pkcs12Bytes.copyOf()
        this.password = password.copyOf()
    }

    override fun clear() {
        bytes = null
        password = null
        corrupted = false
    }
}

/**
 * Android Keystore AES-256-GCM backed persistence for Peer Host TLS identity.
 * Encrypts both the PKCS#12 keystore blob and its random password at rest.
 */
class EncryptedFilePeerHostCertStorage(
    private val context: Context,
    private val keyStoreManager: KeyStoreManager = KeyStoreManager(AndroidKeyStoreKeyProvider()),
    private val keyStoreFileName: String = "snow_peer_host_tls.p12.enc"
) : PeerHostCertStorage {

    companion object {
        private const val PREFS_NAME = "snow_peer_host_security"
        private const val KEY_PASS_CIPHER = "peer_host_p12_pass_cipher_b64"
        private const val KEY_PASS_IV = "peer_host_p12_pass_iv_b64"
        private const val KEY_BLOB_IV = "peer_host_p12_blob_iv_b64"
        private const val TAG = "PeerHostCertStorage"
    }

    private fun targetFile(): File = File(context.filesDir, keyStoreFileName)
    private fun prefs() = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    override fun loadKeyStoreMaterial(): Pair<ByteArray, CharArray>? {
        val file = targetFile()
        val sp = prefs()
        val passCipherB64 = sp.getString(KEY_PASS_CIPHER, null)
        val passIvB64 = sp.getString(KEY_PASS_IV, null)
        val blobIvB64 = sp.getString(KEY_BLOB_IV, null)

        if (!file.exists() && passCipherB64 == null && blobIvB64 == null) {
            return null
        }
        if (!file.exists() || passCipherB64.isNullOrBlank() || passIvB64.isNullOrBlank() || blobIvB64.isNullOrBlank()) {
            throw GeneralSecurityException("Incomplete persisted Peer Host keystore material.")
        }

        val passIv = Base64.getDecoder().decode(passIvB64)
        val passCipher = Base64.getDecoder().decode(passCipherB64)
        val passwordStr = String(keyStoreManager.decrypt(EncryptedPayload(passIv, passCipher)), Charsets.UTF_8)

        val blobIv = Base64.getDecoder().decode(blobIvB64)
        val blobCipher = file.readBytes()
        val pkcs12Bytes = keyStoreManager.decrypt(EncryptedPayload(blobIv, blobCipher))
        return pkcs12Bytes to passwordStr.toCharArray()
    }

    override fun saveKeyStoreMaterial(pkcs12Bytes: ByteArray, password: CharArray) {
        val passBytes = String(password).toByteArray(Charsets.UTF_8)
        val encPass = keyStoreManager.encrypt(passBytes)
        val encBlob = keyStoreManager.encrypt(pkcs12Bytes)

        val file = targetFile()
        file.parentFile?.mkdirs()
        val tmpFile = File(file.parentFile, "${file.name}.tmp")
        tmpFile.writeBytes(encBlob.ciphertext)
        if (!tmpFile.renameTo(file)) {
            tmpFile.copyTo(file, overwrite = true)
            tmpFile.delete()
        }

        val committed = prefs().edit()
            .putString(KEY_PASS_CIPHER, Base64.getEncoder().encodeToString(encPass.ciphertext))
            .putString(KEY_PASS_IV, Base64.getEncoder().encodeToString(encPass.iv))
            .putString(KEY_BLOB_IV, Base64.getEncoder().encodeToString(encBlob.iv))
            .commit()
        if (!committed) {
            SafeLog.w(TAG, "Failed committing encrypted Peer Host keystore metadata.")
        }
    }

    override fun clear() {
        try {
            targetFile().delete()
        } catch (_: Exception) {}
        prefs().edit()
            .remove(KEY_PASS_CIPHER)
            .remove(KEY_PASS_IV)
            .remove(KEY_BLOB_IV)
            .commit()
    }
}

/**
 * Pure standard Java/Android generator & persistent loader for self-signed TLS certificates and SSLContext.
 *
 * Guarantees:
 * - Operates without external BouncyCastle or third-party dependencies.
 * - Generates standard 2048-bit RSA key pairs.
 * - Encodes standard X.509 v1 ASN.1 DER certificates valid for 365 days.
 * - Persists keystore encrypted at rest via [PeerHostCertStorage] so host restarts keep the same fingerprint.
 * - Fails closed on corrupt persisted keystore (never silently reuses invalid material).
 */
object AndroidSelfSignedCertGenerator {

    private const val TAG = "AndroidSelfSignedCertGenerator"

    data class GeneratedCertResult(
        val sslContext: SSLContext,
        val certificate: X509Certificate,
        val keyPair: KeyPair,
        val fingerprint: String
    )

    private fun openPkcs12KeyStore(): KeyStore {
        return try {
            KeyStore.getInstance("PKCS12")
        } catch (_: Exception) {
            KeyStore.getInstance(KeyStore.getDefaultType())
        }
    }

    private fun buildCertResultFromKeyStore(
        keyStore: KeyStore,
        alias: String,
        password: CharArray
    ): GeneratedCertResult {
        val cert = keyStore.getCertificate(alias) as? X509Certificate
            ?: throw GeneralSecurityException("Missing X509Certificate for alias '$alias'")
        val privKey = keyStore.getKey(alias, password) as? PrivateKey
            ?: throw GeneralSecurityException("Missing PrivateKey for alias '$alias'")
        val keyPair = KeyPair(cert.publicKey, privKey)
        val formattedFp = TlsConfig.computeSha256Fingerprint(cert)

        val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
        kmf.init(keyStore, password)
        val sslContext = SSLContext.getInstance("TLS")
        sslContext.init(kmf.keyManagers, null, SecureRandom())

        return GeneratedCertResult(
            sslContext = sslContext,
            certificate = cert,
            keyPair = keyPair,
            fingerprint = formattedFp
        )
    }

    /**
     * Load existing persisted Peer Host identity when valid, or fail closed if corrupt.
     * Returns null only when no identity has been persisted yet.
     */
    fun loadExistingOrThrow(
        storage: PeerHostCertStorage,
        alias: String = "snow-peer-host"
    ): GeneratedCertResult? {
        val material = storage.loadKeyStoreMaterial() ?: return null
        val (pkcs12Bytes, password) = material
        val keyStore = openPkcs12KeyStore()
        keyStore.load(ByteArrayInputStream(pkcs12Bytes), password)
        val loaded = buildCertResultFromKeyStore(keyStore, alias, password)
        if (loaded.certificate.notAfter.before(Date())) {
            throw GeneralSecurityException("Persisted Peer Host certificate has expired.")
        }
        SafeLog.i(TAG, "Loaded persisted Peer Host TLS cert [SHA-256=${loaded.fingerprint}]")
        return loaded
    }

    /**
     * Load persisted TLS identity across restarts, generating and saving one only on first start
     * (or if [regenerateOnCorruption] is explicitly enabled after wiping corrupted state).
     */
    fun loadOrCreate(
        storage: PeerHostCertStorage?,
        alias: String = "snow-peer-host",
        commonName: String = "SNOW-Android-PeerHost",
        regenerateOnCorruption: Boolean = false
    ): GeneratedCertResult {
        if (storage != null) {
            try {
                loadExistingOrThrow(storage, alias)?.let { return it }
            } catch (e: Exception) {
                storage.clear()
                if (!regenerateOnCorruption) {
                    throw GeneralSecurityException("Persisted Peer Host TLS keystore failed verification: ${e.message}", e)
                }
                SafeLog.w(TAG, "Cleared corrupted persisted Peer Host keystore and generating fresh identity: ${e.message}")
            }
        }

        val generated = generate(alias = alias, commonName = commonName)
        if (storage != null) {
            val randomBytes = ByteArray(24)
            SecureRandom().nextBytes(randomBytes)
            val password = Base64.getEncoder().encodeToString(randomBytes).toCharArray()
            val keyStore = openPkcs12KeyStore()
            keyStore.load(null, null)
            keyStore.setKeyEntry(alias, generated.keyPair.private, password, arrayOf(generated.certificate))
            val baos = ByteArrayOutputStream()
            keyStore.store(baos, password)
            storage.saveKeyStoreMaterial(baos.toByteArray(), password)
            SafeLog.i(TAG, "Persisted new Peer Host TLS cert [SHA-256=${generated.fingerprint}]")
        }
        return generated
    }

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
