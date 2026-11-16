package org.snow.security

import android.content.Context
import android.util.Base64
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSession
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.X509TrustManager
import okhttp3.internal.tls.OkHostnameVerifier

/**
 * Thrown when a server presents a valid certificate whose SHA-256 fingerprint
 * has not yet been explicitly approved and pinned by the user (First-Use verification).
 */
class UnconfirmedCertificateException(
    val presentedFingerprint: String,
    message: String = "Server certificate is not yet trusted. User verification required."
) : CertificateException(message)

/**
 * Thrown when the presented certificate fingerprint does not match the stored pin.
 */
class CertificateMismatchException(
    val pinnedFingerprint: String,
    val presentedFingerprint: String,
    message: String = "Certificate fingerprint mismatch! Pinned: $pinnedFingerprint, Presented: $presentedFingerprint"
) : CertificateException(message)

/**
 * Interface defining persistence for the pinned desktop TLS server certificate fingerprint.
 */
interface CertPinStorage {
    /** Return the currently pinned SHA-256 fingerprint, or null if unpinned. */
    fun getPinnedFingerprint(): String?

    /** Store the user-confirmed SHA-256 certificate fingerprint. */
    fun pinFingerprint(fingerprint: String)

    /** Clear the pinned certificate fingerprint (trust reset). */
    fun clearPinnedFingerprint()
}

/**
 * In-memory certificate pin storage for JVM unit testing.
 */
class InMemoryCertPinStorage(initialPin: String? = null) : CertPinStorage {
    private var pin: String? = initialPin?.let { TlsConfig.formatFingerprint(it) }

    override fun getPinnedFingerprint(): String? = pin

    override fun pinFingerprint(fingerprint: String) {
        pin = TlsConfig.formatFingerprint(fingerprint)
    }

    override fun clearPinnedFingerprint() {
        pin = null
    }
}

/**
 * Authenticated certificate pin storage using Keystore AES-GCM encryption at rest.
 *
 * Saves encrypted fingerprint in 'snow_security' SharedPreferences so the pin
 * cannot be tampered with on disk.
 */
class EncryptedCertPinStorage(
    private val context: Context,
    private val keyStoreManager: KeyStoreManager = KeyStoreManager(AndroidKeyStoreKeyProvider())
) : CertPinStorage {

    companion object {
        private const val PREFS_NAME = "snow_security"
        private const val KEY_PIN_CIPHER = "cert_pin_cipher_b64"
        private const val KEY_PIN_IV = "cert_pin_iv_b64"
        private const val TAG = "EncryptedCertPinStorage"
    }

    override fun getPinnedFingerprint(): String? {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val cipherB64 = prefs.getString(KEY_PIN_CIPHER, null)
        val ivB64 = prefs.getString(KEY_PIN_IV, null)

        if (cipherB64.isNullOrBlank() || ivB64.isNullOrBlank()) {
            return null
        }

        return try {
            val iv = Base64.decode(ivB64, Base64.NO_WRAP)
            val cipherBytes = Base64.decode(cipherB64, Base64.NO_WRAP)
            val payload = EncryptedPayload(iv = iv, ciphertext = cipherBytes)
            val rawBytes = keyStoreManager.decrypt(payload)
            String(rawBytes, Charsets.UTF_8).trim()
        } catch (e: Exception) {
            SafeLog.e(TAG, "Failed to decrypt pinned certificate fingerprint: ${e.message}", e)
            null
        }
    }

    override fun pinFingerprint(fingerprint: String) {
        val normalized = TlsConfig.formatFingerprint(fingerprint)
        val encrypted = keyStoreManager.encrypt(normalized.toByteArray(Charsets.UTF_8))
        val cipherB64 = Base64.encodeToString(encrypted.ciphertext, Base64.NO_WRAP)
        val ivB64 = Base64.encodeToString(encrypted.iv, Base64.NO_WRAP)

        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .edit()
            .putString(KEY_PIN_CIPHER, cipherB64)
            .putString(KEY_PIN_IV, ivB64)
            .commit()
    }

    override fun clearPinnedFingerprint() {
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .edit()
            .remove(KEY_PIN_CIPHER)
            .remove(KEY_PIN_IV)
            .commit()
    }
}

/**
 * X509TrustManager enforcing explicit SHA-256 certificate fingerprint pinning.
 *
 * Implements strict Trust-On-First-Use:
 * 1. If a pin is present and matches: handshake succeeds.
 * 2. If a pin is present and mismatches: throws CertificateMismatchException.
 * 3. If unpinned: records presented fingerprint and throws UnconfirmedCertificateException
 *    so the UI can prompt the user for explicit confirmation before saving.
 */
class SnowTrustManager(
    private val pinStorage: CertPinStorage,
    private val onUnconfirmedFingerprint: ((String) -> Unit)? = null
) : X509TrustManager {

    @Volatile
    var lastPresentedFingerprint: String? = null
        private set

    override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {
        // Client certificates are not used in SNOW Protocol v1
    }

    override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {
        if (chain.isNullOrEmpty()) {
            throw CertificateException("Server certificate chain is empty or null.")
        }

        val serverCert = chain[0]
        val presented = TlsConfig.computeSha256Fingerprint(serverCert)
        lastPresentedFingerprint = presented

        val pinned = pinStorage.getPinnedFingerprint()
        if (pinned == null) {
            onUnconfirmedFingerprint?.invoke(presented)
            throw UnconfirmedCertificateException(
                presentedFingerprint = presented,
                message = "Server certificate is not yet trusted. Present this fingerprint to the user for confirmation: $presented"
            )
        }

        if (!TlsConfig.fingerprintsMatch(pinned, presented)) {
            throw CertificateMismatchException(
                pinnedFingerprint = pinned,
                presentedFingerprint = presented
            )
        }
    }

    override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()

    fun resetLastPresentedFingerprint() {
        lastPresentedFingerprint = null
    }
}

/**
 * TLS security configuration, fingerprint utilities, and SSLSocketFactory creation.
 */
object TlsConfig {

    private const val TAG = "TlsConfig"

    /**
     * Compute colon-separated uppercase SHA-256 fingerprint over certificate DER encoding.
     */
    fun computeSha256Fingerprint(cert: X509Certificate): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val derBytes = cert.encoded
        val hash = digest.digest(derBytes)
        return formatFingerprint(hash)
    }

    /**
     * Format a 32-byte digest or raw hex string into standard colon-separated uppercase hex.
     */
    fun formatFingerprint(raw: ByteArray): String {
        return raw.joinToString(":") { "%02X".format(it) }
    }

    /**
     * Format a raw hex or colon-delimited string into standard colon-separated uppercase hex.
     */
    fun formatFingerprint(hexOrColonStr: String): String {
        val clean = hexOrColonStr.replace(":", "").replace(" ", "").trim().uppercase()
        require(clean.length == 64) {
            "Invalid SHA-256 fingerprint length: expected 64 hex characters, got ${clean.length}"
        }
        return clean.chunked(2).joinToString(":")
    }

    /**
     * Compare two SHA-256 fingerprints in normalized form.
     */
    fun fingerprintsMatch(a: String, b: String): Boolean {
        return try {
            val cleanA = a.replace(":", "").replace(" ", "").trim()
            val cleanB = b.replace(":", "").replace(" ", "").trim()
            cleanA.equals(cleanB, ignoreCase = true)
        } catch (_: Exception) {
            false
        }
    }

    /**
     * Create an SSLContext configured with the given SnowTrustManager.
     */
    fun createSslContext(trustManager: X509TrustManager): SSLContext {
        val sslContext = SSLContext.getInstance("TLS")
        sslContext.init(null, arrayOf(trustManager), SecureRandom())
        return sslContext
    }

    /**
     * Strict HostnameVerifier that delegates to OkHttp's built-in OkHostnameVerifier,
     * ensuring that Subject Alternative Name (SAN) IP and DNS entries are strictly validated.
     */
    val strictHostnameVerifier: HostnameVerifier = HostnameVerifier { hostname, session ->
        try {
            OkHostnameVerifier.verify(hostname, session)
        } catch (e: Exception) {
            SafeLog.w(TAG, "Hostname verification failed for $hostname: ${e.message}")
            false
        }
    }

    /**
     * HostnameVerifier that validates Subject Alternative Names (SAN) via OkHostnameVerifier,
     * with fallback to checking whether the presented certificate exactly matches the
     * user-verified pinned SHA-256 fingerprint.
     */
    fun createHostnameVerifier(pinStorage: CertPinStorage): HostnameVerifier = HostnameVerifier { hostname, session ->
        try {
            if (OkHostnameVerifier.verify(hostname, session)) {
                return@HostnameVerifier true
            }
            val peerCerts = session.peerCertificates
            if (peerCerts.isNotEmpty() && peerCerts[0] is X509Certificate) {
                val presented = computeSha256Fingerprint(peerCerts[0] as X509Certificate)
                val pinned = pinStorage.getPinnedFingerprint()
                if (pinned != null && fingerprintsMatch(pinned, presented)) {
                    return@HostnameVerifier true
                }
            }
            SafeLog.w(TAG, "Hostname verification failed for $hostname")
            false
        } catch (e: Exception) {
            SafeLog.w(TAG, "Hostname verification exception for $hostname: ${e.message}")
            false
        }
    }
}
