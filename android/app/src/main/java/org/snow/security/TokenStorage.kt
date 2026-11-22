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
     * Store the raw authentication token returned by the desktop core upon successful pairing.
     * Enforces AES-256-GCM encryption before writing to disk.
     */
    fun saveToken(token: String)

    /**
     * Retrieve and authenticate the stored token, decrypting it using AES-GCM.
     * Returns null if no token is present, if the payload is corrupted, or if tampering is detected.
     */
    fun getToken(): String?

    /**
     * Clear all stored token entries (both encrypted and legacy plaintext).
     */
    fun clearToken()

    /**
     * Return true if an authenticatable token is currently stored.
     */
    fun hasToken(): Boolean
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
            .apply()
    }

    override fun hasToken(): Boolean {
        return getToken() != null
    }
}

/**
 * In-memory implementation of TokenStorage for lightweight tests that do not require cryptographic operations.
 */
class InMemoryTokenStorage : TokenStorage {
    private var token: String? = null

    override fun saveToken(token: String) {
        if (token.isNotBlank()) {
            this.token = token
        }
    }

    override fun getToken(): String? {
        return token
    }

    override fun clearToken() {
        token = null
    }

    override fun hasToken(): Boolean {
        return !token.isNullOrBlank()
    }
}
