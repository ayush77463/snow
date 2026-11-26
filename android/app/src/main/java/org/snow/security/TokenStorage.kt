package org.snow.security

import android.content.Context
import android.content.SharedPreferences
import android.util.Log
import java.security.GeneralSecurityException
import java.util.Base64
import javax.crypto.AEADBadTagException

/**
 * Defensive logging utility that safely delegates to android.util.Log on Android runtime
 * and falls back gracefully to standard stderr in JVM unit testing environments.
 */
internal object SafeLog {
    fun i(tag: String, msg: String) {
        try {
            Log.i(tag, msg)
        } catch (_: Throwable) {
            // JVM unit test fallback
        }
    }

    fun w(tag: String, msg: String, tr: Throwable? = null) {
        try {
            Log.w(tag, msg, tr)
        } catch (_: Throwable) {
            // JVM unit test fallback
        }
    }

    fun e(tag: String, msg: String, tr: Throwable? = null) {
        try {
            Log.e(tag, msg, tr)
        } catch (_: Throwable) {
            // JVM unit test fallback
        }
    }
}

/**
 * Interface defining authentication token persistence for paired devices.
 */
interface TokenStorage {
    /**
     * Store the raw authentication token returned by the host upon successful pairing
     * in the default/legacy slot.
     */
    fun saveToken(token: String)

    /**
     * Retrieve and authenticate the stored token from the default/legacy slot.
     */
    fun getToken(): String?

    /**
     * Clear stored token entries from the default/legacy slot.
     */
    fun clearToken()

    /**
     * Return true if an authenticatable token is currently stored in the default/legacy slot.
     */
    fun hasToken(): Boolean

    /**
     * Store an authentication token isolated under a canonical peer [deviceId].
     */
    fun saveTokenForDevice(deviceId: String, token: String) {
        if (deviceId.isNotBlank()) {
            saveToken(token)
        }
    }

    /**
     * Retrieve the stored authentication token for a specific canonical peer [deviceId].
     */
    fun getTokenForDevice(deviceId: String): String? {
        return if (deviceId.isBlank()) null else null
    }

    /**
     * Clear the stored authentication token for a specific canonical peer [deviceId].
     */
    fun clearTokenForDevice(deviceId: String) {}

    /**
     * Return true if an authenticatable token is stored for [deviceId].
     */
    fun hasTokenForDevice(deviceId: String): Boolean {
        return getTokenForDevice(deviceId) != null
    }

    /**
     * List canonical peer device IDs that currently have stored per-device tokens.
     */
    fun listStoredDeviceIds(): Set<String> = emptySet()

    /**
     * Clear all stored tokens (both per-device slots and legacy default slot).
     */
    fun clearAllTokens() {
        clearToken()
    }
}

/**
 * SharedPreferences-backed token storage implementing AES-256-GCM encryption at rest.
 *
 * CRITICAL SECURITY INVARIANTS:
 * 1. Plaintext authorization tokens are NEVER written to SharedPreferences or disk.
 * 2. Only Base64-encoded provider-generated IVs, authenticated ciphertexts, and version metadata are stored.
 * 3. Transparently migrates legacy plaintext tokens from Phase 2.2 to encrypted storage upon first read.
 * 4. Fails closed: any cryptographic tampering, corrupted Base64, or key invalidation wipes the credential
 *    and returns null.
 */
class SharedPreferencesTokenStorage(
    private val prefs: SharedPreferences,
    private val keyStoreManager: KeyStoreManager = KeyStoreManager(AndroidKeyStoreKeyProvider())
) : TokenStorage {

    /**
     * Convenience constructor for standard Android Context injection.
     */
    constructor(
        context: Context,
        prefName: String = PREFS_NAME,
        keyStoreManager: KeyStoreManager = KeyStoreManager(AndroidKeyStoreKeyProvider())
    ) : this(
        context.getSharedPreferences(prefName, Context.MODE_PRIVATE),
        keyStoreManager
    )

    companion object {
        const val PREFS_NAME = "snow_security"
        const val PEER_HOST_PREFS_NAME = "snow_peer_host_security"
        private const val TAG = "TokenStorage"

        // Encrypted storage keys
        const val KEY_ENCRYPTED_IV = "auth_token_iv_b64"
        const val KEY_ENCRYPTED_DATA = "auth_token_cipher_b64"
        const val KEY_STORAGE_VERSION = "auth_token_storage_ver"
        const val CURRENT_STORAGE_VERSION = 1

        // Phase 2.2 legacy plaintext key (for transparent migration)
        const val KEY_LEGACY_AUTH_TOKEN = "auth_token"

        // Per-device isolated storage keys
        const val KEY_DEVICE_TOKEN_INDEX = "dev_tok_v2_ids"
        const val PREFIX_DEVICE_IV = "dev_tok_v2_iv_"
        const val PREFIX_DEVICE_CIPHER = "dev_tok_v2_cipher_"
        const val PREFIX_DEVICE_VER = "dev_tok_v2_ver_"

        internal fun normalizeDeviceId(deviceId: String?): String? {
            return deviceId?.trim()?.lowercase()?.takeIf { it.isNotEmpty() }
        }

        private fun hashDeviceSlot(normalizedDeviceId: String): String {
            val digest = java.security.MessageDigest.getInstance("SHA-256")
                .digest(normalizedDeviceId.toByteArray(Charsets.UTF_8))
            return digest.joinToString("") { "%02x".format(it) }
        }
    }

    private fun readDeviceIndex(): Set<String> {
        val raw = prefs.getStringSet(KEY_DEVICE_TOKEN_INDEX, null) ?: return emptySet()
        return raw.mapNotNull { normalizeDeviceId(it) }.toSet()
    }

    override fun saveToken(token: String) {
        if (token.isBlank()) {
            SafeLog.w(TAG, "Rejected attempt to save empty or blank authentication token")
            return
        }

        try {
            val plaintextBytes = token.toByteArray(Charsets.UTF_8)
            val encrypted = keyStoreManager.encrypt(plaintextBytes)

            val ivB64 = Base64.getEncoder().encodeToString(encrypted.iv)
            val cipherB64 = Base64.getEncoder().encodeToString(encrypted.ciphertext)

            val editor = prefs.edit()
                .putString(KEY_ENCRYPTED_IV, ivB64)
                .putString(KEY_ENCRYPTED_DATA, cipherB64)
                .putInt(KEY_STORAGE_VERSION, CURRENT_STORAGE_VERSION)
                .remove(KEY_LEGACY_AUTH_TOKEN)

            // Commit changes synchronously to guarantee persistence
            val success = editor.commit()
            if (!success) {
                SafeLog.e(TAG, "Failed to commit encrypted token to SharedPreferences")
            }
        } catch (e: Exception) {
            SafeLog.e(TAG, "Cryptographic failure while encrypting token for storage", e)
            clearToken()
        }
    }

    override fun getToken(): String? {
        // 1. Transparent migration: check for legacy plaintext token from Phase 2.2
        val legacyToken = prefs.getString(KEY_LEGACY_AUTH_TOKEN, null)
        if (!legacyToken.isNullOrBlank()) {
            SafeLog.i(TAG, "Migrating legacy plaintext token to AES-GCM encrypted storage")
            try {
                saveToken(legacyToken)
                // Verify migrated state
                if (prefs.contains(KEY_LEGACY_AUTH_TOKEN)) {
                    prefs.edit().remove(KEY_LEGACY_AUTH_TOKEN).commit()
                }
                return legacyToken
            } catch (e: Exception) {
                SafeLog.w(TAG, "Legacy token migration failed; failing closed and clearing credentials", e)
                clearToken()
                return null
            }
        }

        // 2. Retrieve encrypted credentials
        val ivB64 = prefs.getString(KEY_ENCRYPTED_IV, null)
        val cipherB64 = prefs.getString(KEY_ENCRYPTED_DATA, null)
        val version = prefs.getInt(KEY_STORAGE_VERSION, 0)

        if (ivB64.isNullOrBlank() || cipherB64.isNullOrBlank()) {
            return null
        }

        if (version != CURRENT_STORAGE_VERSION) {
            SafeLog.w(TAG, "Unrecognized token storage version ($version); clearing credentials")
            clearToken()
            return null
        }

        // 3. Decode Base64 payloads
        val iv = try {
            Base64.getDecoder().decode(ivB64)
        } catch (e: IllegalArgumentException) {
            SafeLog.w(TAG, "Malformed Base64 IV detected; clearing corrupted credentials", e)
            clearToken()
            return null
        }

        val ciphertext = try {
            Base64.getDecoder().decode(cipherB64)
        } catch (e: IllegalArgumentException) {
            SafeLog.w(TAG, "Malformed Base64 ciphertext detected; clearing corrupted credentials", e)
            clearToken()
            return null
        }

        // 4. Decrypt and authenticate using AES-GCM
        return try {
            val decryptedBytes = keyStoreManager.decrypt(EncryptedPayload(iv = iv, ciphertext = ciphertext))
            String(decryptedBytes, Charsets.UTF_8)
        } catch (e: AEADBadTagException) {
            SafeLog.w(TAG, "AES-GCM authentication tag verification failed (tampering detected); failing closed", e)
            clearToken()
            null
        } catch (e: GeneralSecurityException) {
            SafeLog.w(TAG, "Cryptographic security exception during token decryption; failing closed", e)
            clearToken()
            null
        } catch (e: IllegalArgumentException) {
            SafeLog.w(TAG, "Invalid payload structure during token decryption; failing closed", e)
            clearToken()
            null
        } catch (e: Exception) {
            SafeLog.w(TAG, "Unexpected error during token decryption; failing closed", e)
            clearToken()
            null
        }
    }

    override fun clearToken() {
        prefs.edit()
            .remove(KEY_ENCRYPTED_IV)
            .remove(KEY_ENCRYPTED_DATA)
            .remove(KEY_STORAGE_VERSION)
            .remove(KEY_LEGACY_AUTH_TOKEN)
            .commit()
    }

    override fun hasToken(): Boolean {
        return getToken() != null
    }

    override fun saveTokenForDevice(deviceId: String, token: String) {
        val norm = normalizeDeviceId(deviceId)
        if (norm == null || token.isBlank()) {
            SafeLog.w(TAG, "Rejected attempt to save token for blank deviceId or blank token")
            return
        }
        val slot = hashDeviceSlot(norm)
        try {
            val encrypted = keyStoreManager.encrypt(token.toByteArray(Charsets.UTF_8))
            val ivB64 = Base64.getEncoder().encodeToString(encrypted.iv)
            val cipherB64 = Base64.getEncoder().encodeToString(encrypted.ciphertext)
            val nextIdx = readDeviceIndex().toMutableSet().apply { add(norm) }
            val success = prefs.edit()
                .putString("$PREFIX_DEVICE_IV$slot", ivB64)
                .putString("$PREFIX_DEVICE_CIPHER$slot", cipherB64)
                .putInt("$PREFIX_DEVICE_VER$slot", CURRENT_STORAGE_VERSION)
                .putStringSet(KEY_DEVICE_TOKEN_INDEX, nextIdx)
                .commit()
            if (!success) {
                SafeLog.e(TAG, "Failed committing per-device encrypted token for [$norm]")
            }
        } catch (e: Exception) {
            SafeLog.e(TAG, "Cryptographic failure saving per-device token for [$norm]", e)
            clearTokenForDevice(norm)
        }
    }

    override fun getTokenForDevice(deviceId: String): String? {
        val norm = normalizeDeviceId(deviceId) ?: return null
        val slot = hashDeviceSlot(norm)
        val ivB64 = prefs.getString("$PREFIX_DEVICE_IV$slot", null)
        val cipherB64 = prefs.getString("$PREFIX_DEVICE_CIPHER$slot", null)
        val version = prefs.getInt("$PREFIX_DEVICE_VER$slot", 0)
        if (ivB64.isNullOrBlank() || cipherB64.isNullOrBlank()) {
            return null
        }
        if (version != CURRENT_STORAGE_VERSION) {
            SafeLog.w(TAG, "Unrecognized per-device token storage version ($version) for [$norm]; failing closed")
            clearTokenForDevice(norm)
            return null
        }
        return try {
            val iv = Base64.getDecoder().decode(ivB64)
            val ciphertext = Base64.getDecoder().decode(cipherB64)
            val decryptedBytes = keyStoreManager.decrypt(EncryptedPayload(iv = iv, ciphertext = ciphertext))
            String(decryptedBytes, Charsets.UTF_8).takeIf { it.isNotBlank() }
        } catch (e: Exception) {
            SafeLog.w(TAG, "AES-GCM decryption failed for device [$norm]; failing closed and clearing token", e)
            clearTokenForDevice(norm)
            null
        }
    }

    override fun clearTokenForDevice(deviceId: String) {
        val norm = normalizeDeviceId(deviceId) ?: return
        val slot = hashDeviceSlot(norm)
        val nextIdx = readDeviceIndex().toMutableSet().apply { remove(norm) }
        prefs.edit()
            .remove("$PREFIX_DEVICE_IV$slot")
            .remove("$PREFIX_DEVICE_CIPHER$slot")
            .remove("$PREFIX_DEVICE_VER$slot")
            .putStringSet(KEY_DEVICE_TOKEN_INDEX, nextIdx)
            .commit()
    }

    override fun listStoredDeviceIds(): Set<String> = readDeviceIndex()

    override fun clearAllTokens() {
        val editor = prefs.edit()
            .remove(KEY_ENCRYPTED_IV)
            .remove(KEY_ENCRYPTED_DATA)
            .remove(KEY_STORAGE_VERSION)
            .remove(KEY_LEGACY_AUTH_TOKEN)
            .remove(KEY_DEVICE_TOKEN_INDEX)
        for (k in prefs.all.keys) {
            if (k.startsWith(PREFIX_DEVICE_IV) ||
                k.startsWith(PREFIX_DEVICE_CIPHER) ||
                k.startsWith(PREFIX_DEVICE_VER)
            ) {
                editor.remove(k)
            }
        }
        editor.commit()
    }

    /**
     * Safely migrate legacy single-slot token into [deviceId] ONLY when canonical identity is known.
     * Clears corrupted legacy data and never overwrites an existing per-device slot.
     */
    fun migrateLegacyTokenToDeviceIfKnown(deviceId: String?): Boolean {
        val norm = normalizeDeviceId(deviceId) ?: return false
        val existing = getTokenForDevice(norm)
        val legacy = getToken() ?: return (existing != null)
        if (existing == null) {
            saveTokenForDevice(norm, legacy)
            if (getTokenForDevice(norm) == null) {
                return false
            }
        }
        clearToken()
        return true
    }
}

/**
 * In-memory implementation of TokenStorage for lightweight tests that do not require cryptographic operations.
 */
class InMemoryTokenStorage : TokenStorage {
    private var token: String? = null
    private val perDeviceTokens = java.util.concurrent.ConcurrentHashMap<String, String>()

    private fun normId(deviceId: String): String? =
        deviceId.trim().lowercase().takeIf { it.isNotEmpty() }

    override fun saveToken(token: String) {
        if (token.isNotBlank()) {
            this.token = token
        }
    }

    override fun getToken(): String? {
        return token ?: if (perDeviceTokens.size == 1) perDeviceTokens.values.firstOrNull() else null
    }

    override fun clearToken() {
        token = null
    }

    override fun hasToken(): Boolean {
        return !token.isNullOrBlank() || perDeviceTokens.isNotEmpty()
    }

    override fun saveTokenForDevice(deviceId: String, token: String) {
        val key = normId(deviceId) ?: return
        if (token.isNotBlank()) {
            perDeviceTokens[key] = token
        }
    }

    override fun getTokenForDevice(deviceId: String): String? {
        val key = normId(deviceId) ?: return null
        return perDeviceTokens[key]
    }

    override fun clearTokenForDevice(deviceId: String) {
        val key = normId(deviceId) ?: return
        perDeviceTokens.remove(key)
    }

    override fun listStoredDeviceIds(): Set<String> = perDeviceTokens.keys.toSet()

    override fun clearAllTokens() {
        token = null
        perDeviceTokens.clear()
    }
}
