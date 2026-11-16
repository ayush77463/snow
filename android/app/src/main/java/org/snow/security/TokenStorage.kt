package org.snow.security

import android.content.Context
import android.content.SharedPreferences

/**
 * Interface defining authentication token persistence for paired devices.
 *
 * In Phase 2.2, tokens are persisted in private SharedPreferences.
 * Hardware-backed Android Keystore and AES-GCM encryption will be added in Phase 2.3.
 */
interface TokenStorage {
    /**
     * Store the raw authentication token returned by the desktop core upon successful pairing.
     */
    fun saveToken(token: String)

    /**
     * Retrieve the stored authentication token, or null if no token exists.
     */
    fun getToken(): String?

    /**
     * Clear and delete the stored authentication token (e.g. upon unpairing).
     */
    fun clearToken()

    /**
     * Return true if a non-blank token is currently stored.
     */
    fun hasToken(): Boolean
}

/**
 * Default SharedPreferences-backed token storage using application-private storage mode.
 */
class SharedPreferencesTokenStorage(
    context: Context,
    prefName: String = PREFS_NAME
) : TokenStorage {

    companion object {
        const val PREFS_NAME = "snow_security"
        private const val KEY_AUTH_TOKEN = "auth_token"
    }

    private val prefs: SharedPreferences =
        context.getSharedPreferences(prefName, Context.MODE_PRIVATE)

    override fun saveToken(token: String) {
        prefs.edit().putString(KEY_AUTH_TOKEN, token).apply()
    }

    override fun getToken(): String? {
        return prefs.getString(KEY_AUTH_TOKEN, null)
    }

    override fun clearToken() {
        prefs.edit().remove(KEY_AUTH_TOKEN).apply()
    }

    override fun hasToken(): Boolean {
        return !prefs.getString(KEY_AUTH_TOKEN, null).isNullOrBlank()
    }
}

/**
 * In-memory implementation of TokenStorage for JVM unit tests.
 */
class InMemoryTokenStorage : TokenStorage {
    private var token: String? = null

    override fun saveToken(token: String) {
        this.token = token
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
