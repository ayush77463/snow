package org.snow.security

import android.content.Context
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import java.util.Base64
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
 * Interface defining persistence for pinned TLS server certificate fingerprints.
 */
interface CertPinStorage {
    /** Return the currently pinned SHA-256 fingerprint in the default/legacy slot, or null if unpinned. */
    fun getPinnedFingerprint(): String?

    /** Store the user-confirmed SHA-256 certificate fingerprint in the default/legacy slot. */
    fun pinFingerprint(fingerprint: String)

    /** Clear the default/legacy pinned certificate fingerprint. */
    fun clearPinnedFingerprint()

    /** Return the pinned SHA-256 fingerprint scoped to [deviceId], or null if unpinned. */
    fun getPinnedFingerprintForDevice(deviceId: String): String? = null

    /** Store a pinned SHA-256 fingerprint isolated to canonical [deviceId]. */
    fun pinFingerprintForDevice(deviceId: String, fingerprint: String) {}

    /** Clear the pinned SHA-256 fingerprint scoped to [deviceId]. */
    fun clearPinnedFingerprintForDevice(deviceId: String) {}

    /** Return all canonical device IDs that currently have a pinned certificate. */
    fun listPinnedDeviceIds(): Set<String> = emptySet()

    /** Find a canonical device ID whose pinned certificate matches [fingerprint], or null if none match. */
    fun findDeviceIdByFingerprint(fingerprint: String): String? = null

    /** Clear all per-device pins and legacy single-slot pin. */
    fun clearAllPinnedFingerprints() {
        clearPinnedFingerprint()
    }
}

/**
 * In-memory certificate pin storage for JVM unit testing.
 */
class InMemoryCertPinStorage(initialPin: String? = null) : CertPinStorage {
    private var pin: String? = initialPin?.let { TlsConfig.formatFingerprint(it) }
    private val perDevicePins = java.util.concurrent.ConcurrentHashMap<String, String>()

    private fun normId(deviceId: String): String? =
        deviceId.trim().lowercase().takeIf { it.isNotEmpty() }

    override fun getPinnedFingerprint(): String? = pin

    override fun pinFingerprint(fingerprint: String) {
        pin = TlsConfig.formatFingerprint(fingerprint)
    }

    override fun clearPinnedFingerprint() {
        pin = null
    }

    override fun getPinnedFingerprintForDevice(deviceId: String): String? {
        val key = normId(deviceId) ?: return null
        return perDevicePins[key]
    }

    override fun pinFingerprintForDevice(deviceId: String, fingerprint: String) {
        val key = normId(deviceId) ?: return
        perDevicePins[key] = TlsConfig.formatFingerprint(fingerprint)
    }

    override fun clearPinnedFingerprintForDevice(deviceId: String) {
        val key = normId(deviceId) ?: return
        perDevicePins.remove(key)
    }

    override fun listPinnedDeviceIds(): Set<String> = perDevicePins.keys.toSet()

    override fun findDeviceIdByFingerprint(fingerprint: String): String? {
        return perDevicePins.entries.firstOrNull { TlsConfig.fingerprintsMatch(it.value, fingerprint) }?.key
    }

    override fun clearAllPinnedFingerprints() {
        pin = null
        perDevicePins.clear()
    }
}

/**
 * Authenticated certificate pin storage using Keystore AES-GCM encryption at rest.
 *
 * Stores isolated per-device pins under canonical device ID keys plus backward-compatible
 * legacy default slot in 'snow_security' SharedPreferences.
 */
class EncryptedCertPinStorage(
    private val context: Context,
    private val keyStoreManager: KeyStoreManager = KeyStoreManager(AndroidKeyStoreKeyProvider())
) : CertPinStorage {

    companion object {
        private const val PREFS_NAME = "snow_security"
        private const val KEY_PIN_CIPHER = "cert_pin_cipher_b64"
        private const val KEY_PIN_IV = "cert_pin_iv_b64"
        private const val KEY_DEVICE_PIN_INDEX = "cert_pin_v2_device_ids"
        private const val PREFIX_DEVICE_CIPHER = "cert_pin_v2_cipher_"
        private const val PREFIX_DEVICE_IV = "cert_pin_v2_iv_"
        private const val TAG = "EncryptedCertPinStorage"

        internal fun normalizeDeviceKey(deviceId: String?): String? {
            return deviceId?.trim()?.lowercase()?.takeIf { it.isNotEmpty() }
        }

        private fun hashSlotKey(normalizedDeviceId: String): String {
            val digest = MessageDigest.getInstance("SHA-256")
                .digest(normalizedDeviceId.toByteArray(Charsets.UTF_8))
            return digest.joinToString("") { "%02x".format(it) }
        }
    }

    private fun prefs() = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    private fun readDeviceIndex(): Set<String> {
        val raw = prefs().getStringSet(KEY_DEVICE_PIN_INDEX, null) ?: return emptySet()
        return raw.mapNotNull { normalizeDeviceKey(it) }.toSet()
    }

    private fun writeDeviceIndex(updated: Set<String>) {
        prefs().edit().putStringSet(KEY_DEVICE_PIN_INDEX, updated.toSet()).commit()
    }

    override fun getPinnedFingerprint(): String? {
        val sp = prefs()
        val cipherB64 = sp.getString(KEY_PIN_CIPHER, null)
        val ivB64 = sp.getString(KEY_PIN_IV, null)

        if (cipherB64.isNullOrBlank() || ivB64.isNullOrBlank()) {
            return null
        }

        return try {
            val iv = Base64.getDecoder().decode(ivB64)
            val cipherBytes = Base64.getDecoder().decode(cipherB64)
            val payload = EncryptedPayload(iv = iv, ciphertext = cipherBytes)
            val rawBytes = keyStoreManager.decrypt(payload)
            TlsConfig.formatFingerprint(String(rawBytes, Charsets.UTF_8).trim())
        } catch (e: Exception) {
            SafeLog.e(TAG, "Failed to decrypt pinned certificate fingerprint; clearing corrupted entry: ${e.message}", e)
            clearPinnedFingerprint()
            null
        }
    }

    override fun pinFingerprint(fingerprint: String) {
        val normalized = TlsConfig.formatFingerprint(fingerprint)
        val encrypted = keyStoreManager.encrypt(normalized.toByteArray(Charsets.UTF_8))
        val cipherB64 = Base64.getEncoder().encodeToString(encrypted.ciphertext)
        val ivB64 = Base64.getEncoder().encodeToString(encrypted.iv)

        prefs()
            .edit()
            .putString(KEY_PIN_CIPHER, cipherB64)
            .putString(KEY_PIN_IV, ivB64)
            .commit()
    }

    override fun clearPinnedFingerprint() {
        prefs()
            .edit()
            .remove(KEY_PIN_CIPHER)
            .remove(KEY_PIN_IV)
            .commit()
    }

    override fun getPinnedFingerprintForDevice(deviceId: String): String? {
        val norm = normalizeDeviceKey(deviceId) ?: return null
        val slot = hashSlotKey(norm)
        val sp = prefs()
        val cipherB64 = sp.getString("$PREFIX_DEVICE_CIPHER$slot", null)
        val ivB64 = sp.getString("$PREFIX_DEVICE_IV$slot", null)
        if (cipherB64.isNullOrBlank() || ivB64.isNullOrBlank()) {
            return null
        }
        return try {
            val iv = Base64.getDecoder().decode(ivB64)
            val cipherBytes = Base64.getDecoder().decode(cipherB64)
            val rawBytes = keyStoreManager.decrypt(EncryptedPayload(iv = iv, ciphertext = cipherBytes))
            TlsConfig.formatFingerprint(String(rawBytes, Charsets.UTF_8).trim())
        } catch (e: Exception) {
            SafeLog.w(TAG, "Failed decrypting per-device pin for [$norm]; failing closed and clearing: ${e.message}")
            clearPinnedFingerprintForDevice(norm)
            null
        }
    }

    override fun pinFingerprintForDevice(deviceId: String, fingerprint: String) {
        val norm = normalizeDeviceKey(deviceId) ?: return
        val normalizedFp = TlsConfig.formatFingerprint(fingerprint)
        val slot = hashSlotKey(norm)
        try {
            val encrypted = keyStoreManager.encrypt(normalizedFp.toByteArray(Charsets.UTF_8))
            val cipherB64 = Base64.getEncoder().encodeToString(encrypted.ciphertext)
            val ivB64 = Base64.getEncoder().encodeToString(encrypted.iv)
            val nextIdx = readDeviceIndex().toMutableSet().apply { add(norm) }
            prefs()
                .edit()
                .putString("$PREFIX_DEVICE_CIPHER$slot", cipherB64)
                .putString("$PREFIX_DEVICE_IV$slot", ivB64)
                .putStringSet(KEY_DEVICE_PIN_INDEX, nextIdx)
                .commit()
        } catch (e: Exception) {
            SafeLog.e(TAG, "Failed encrypting per-device pin for [$norm]: ${e.message}", e)
            clearPinnedFingerprintForDevice(norm)
        }
    }

    override fun clearPinnedFingerprintForDevice(deviceId: String) {
        val norm = normalizeDeviceKey(deviceId) ?: return
        val slot = hashSlotKey(norm)
        val nextIdx = readDeviceIndex().toMutableSet().apply { remove(norm) }
        prefs()
            .edit()
            .remove("$PREFIX_DEVICE_CIPHER$slot")
            .remove("$PREFIX_DEVICE_IV$slot")
            .putStringSet(KEY_DEVICE_PIN_INDEX, nextIdx)
            .commit()
    }

    override fun listPinnedDeviceIds(): Set<String> = readDeviceIndex()

    override fun findDeviceIdByFingerprint(fingerprint: String): String? {
        for (devId in readDeviceIndex()) {
            val pinned = getPinnedFingerprintForDevice(devId) ?: continue
            if (TlsConfig.fingerprintsMatch(pinned, fingerprint)) {
                return devId
            }
        }
        return null
    }

    override fun clearAllPinnedFingerprints() {
        val sp = prefs()
        val editor = sp.edit()
            .remove(KEY_PIN_CIPHER)
            .remove(KEY_PIN_IV)
            .remove(KEY_DEVICE_PIN_INDEX)
        for (k in sp.all.keys) {
            if (k.startsWith(PREFIX_DEVICE_CIPHER) || k.startsWith(PREFIX_DEVICE_IV)) {
                editor.remove(k)
            }
        }
        val committed = editor.commit()
        if (!committed) {
            throw IllegalStateException("Failed committing cleared encrypted certificate pins in snow_security.")
        }
    }

    /**
     * Safely migrate legacy single-slot fingerprint into [deviceId] ONLY when canonical identity is known.
     * Clears corrupted legacy data and never guesses or overwrites existing per-device pins.
     */
    fun migrateLegacyPinToDeviceIfKnown(deviceId: String?): Boolean {
        val norm = normalizeDeviceKey(deviceId) ?: return false
        val existingForDevice = getPinnedFingerprintForDevice(norm)
        val legacyFp = getPinnedFingerprint() ?: return (existingForDevice != null)
        if (existingForDevice == null) {
            pinFingerprintForDevice(norm, legacyFp)
            if (getPinnedFingerprintForDevice(norm) == null) {
                return false
            }
        }
        clearPinnedFingerprint()
        return true
    }
}

/**
 * X509TrustManager enforcing explicit SHA-256 certificate fingerprint pinning.
 *
 * Supports isolated per-device pin lookup via [targetDeviceIdProvider] and optional
 * loopback/USB auto-probe matching across pinned devices via [allowAnyPinnedMatchProvider].
 */
class SnowTrustManager(
    private val pinStorage: CertPinStorage,
    private val onUnconfirmedFingerprint: ((String) -> Unit)? = null,
    private val targetDeviceIdProvider: (() -> String?)? = null,
    private val allowAnyPinnedMatchProvider: (() -> Boolean)? = null
) : X509TrustManager {

    constructor(
        pinStorage: CertPinStorage,
        onUnconfirmedFingerprint: ((String) -> Unit)?
    ) : this(
        pinStorage = pinStorage,
        onUnconfirmedFingerprint = onUnconfirmedFingerprint,
        targetDeviceIdProvider = null,
        allowAnyPinnedMatchProvider = null
    )

    @Volatile
    var lastPresentedFingerprint: String? = null
        private set

    @Volatile
    var lastMatchedDeviceId: String? = null
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
        lastMatchedDeviceId = null

        val explicitTargetId = targetDeviceIdProvider?.invoke()?.trim()?.takeIf { it.isNotEmpty() }
        val pinned: String? = if (explicitTargetId != null) {
            pinStorage.getPinnedFingerprintForDevice(explicitTargetId) ?: run {
                // Allow legacy single-slot migration match ONLY if no per-device pins exist yet
                if (pinStorage.listPinnedDeviceIds().isEmpty()) pinStorage.getPinnedFingerprint() else null
            }
        } else if (allowAnyPinnedMatchProvider?.invoke() == true) {
            val matchedDev = pinStorage.findDeviceIdByFingerprint(presented)
            if (matchedDev != null) {
                lastMatchedDeviceId = matchedDev
                pinStorage.getPinnedFingerprintForDevice(matchedDev)
            } else if (pinStorage.listPinnedDeviceIds().isEmpty()) {
                pinStorage.getPinnedFingerprint()
            } else {
                // Loopback/USB probe against multiple pinned devices: do not claim mismatch with an arbitrary peer;
                // match any pinned device if found, otherwise treat as unconfirmed.
                null
            }
        } else {
            pinStorage.getPinnedFingerprint()
        }

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
        if (explicitTargetId != null) {
            lastMatchedDeviceId = explicitTargetId
        }
    }

    override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()

    fun resetLastPresentedFingerprint() {
        lastPresentedFingerprint = null
        lastMatchedDeviceId = null
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
     * user-verified pinned SHA-256 fingerprint for the active target device (or matched loopback peer).
     */
    fun createHostnameVerifier(
        pinStorage: CertPinStorage,
        targetDeviceIdProvider: (() -> String?)? = null,
        allowAnyPinnedMatchProvider: (() -> Boolean)? = null
    ): HostnameVerifier = HostnameVerifier { hostname, session ->
        try {
            if (OkHostnameVerifier.verify(hostname, session)) {
                return@HostnameVerifier true
            }
            val peerCerts = session.peerCertificates
            if (peerCerts.isNotEmpty() && peerCerts[0] is X509Certificate) {
                val presented = computeSha256Fingerprint(peerCerts[0] as X509Certificate)
                val targetDev = targetDeviceIdProvider?.invoke()?.trim()?.takeIf { it.isNotEmpty() }
                val scopedPin = if (targetDev != null) {
                    pinStorage.getPinnedFingerprintForDevice(targetDev)
                        ?: if (pinStorage.listPinnedDeviceIds().isEmpty()) pinStorage.getPinnedFingerprint() else null
                } else if (allowAnyPinnedMatchProvider?.invoke() == true) {
                    val matchedDev = pinStorage.findDeviceIdByFingerprint(presented)
                    if (matchedDev != null) pinStorage.getPinnedFingerprintForDevice(matchedDev)
                    else if (pinStorage.listPinnedDeviceIds().isEmpty()) pinStorage.getPinnedFingerprint()
                    else null
                } else {
                    pinStorage.getPinnedFingerprint()
                }
                if (scopedPin != null && fingerprintsMatch(scopedPin, presented)) {
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
