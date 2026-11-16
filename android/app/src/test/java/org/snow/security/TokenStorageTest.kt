package org.snow.security

import android.content.SharedPreferences
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.util.Base64
import javax.crypto.KeyGenerator

class TokenStorageTest {

    private lateinit var mockPrefs: MockSharedPreferences
    private lateinit var keyProvider: InMemoryAesKeyProvider
    private lateinit var keyStoreManager: KeyStoreManager
    private lateinit var storage: SharedPreferencesTokenStorage

    @Before
    fun setUp() {
        mockPrefs = MockSharedPreferences()
        keyProvider = InMemoryAesKeyProvider()
        keyStoreManager = KeyStoreManager(keyProvider)
        storage = SharedPreferencesTokenStorage(mockPrefs, keyStoreManager)
    }

    @Test
    fun testInMemoryTokenStorageLifecycle() {
        val inMemory = InMemoryTokenStorage()

        assertFalse("Initially should have no token", inMemory.hasToken())
        assertNull("getToken should return null initially", inMemory.getToken())

        val testToken = "test-token-abcdef1234567890"
        inMemory.saveToken(testToken)

        assertTrue("Should have token after save", inMemory.hasToken())
        assertEquals(testToken, inMemory.getToken())

        inMemory.clearToken()

        assertFalse("Should not have token after clear", inMemory.hasToken())
        assertNull("getToken should return null after clear", inMemory.getToken())
    }

    @Test
    fun testBlankTokensAreNotStored() {
        storage.saveToken("   ")
        assertFalse("Blank token should not be stored", storage.hasToken())
        assertNull(storage.getToken())

        storage.saveToken("")
        assertFalse("Empty token should not be stored", storage.hasToken())
        assertNull(storage.getToken())
    }

    @Test
    fun testStoredSharedPreferencesValuesDoNotContainPlaintextToken() {
        val secretToken = "super-confidential-auth-token-9876543210"
        storage.saveToken(secretToken)

        // Verify that the secret token never appears as a raw value in SharedPreferences
        for ((key, value) in mockPrefs.getAll()) {
            val stringVal = value?.toString() ?: ""
            assertFalse(
                "Plaintext token must never be stored in SharedPreferences (found in key $key)",
                stringVal.contains(secretToken)
            )
        }

        // Verify encrypted fields exist
        assertTrue(mockPrefs.contains(SharedPreferencesTokenStorage.KEY_ENCRYPTED_IV))
        assertTrue(mockPrefs.contains(SharedPreferencesTokenStorage.KEY_ENCRYPTED_DATA))
        assertTrue(mockPrefs.contains(SharedPreferencesTokenStorage.KEY_STORAGE_VERSION))
        assertFalse(mockPrefs.contains(SharedPreferencesTokenStorage.KEY_LEGACY_AUTH_TOKEN))
    }

    @Test
    fun testGetTokenReturnsOriginalTokenAfterSuccessfulSave() {
        val secretToken = "snow-device-auth-token-sample-value-42"
        storage.saveToken(secretToken)

        assertTrue(storage.hasToken())
        assertEquals(secretToken, storage.getToken())
    }

    @Test
    fun testTamperedCiphertextIsClearedAndGetTokenReturnsNull() {
        val token = "tamper-test-token"
        storage.saveToken(token)

        val cipherB64 = mockPrefs.getString(SharedPreferencesTokenStorage.KEY_ENCRYPTED_DATA, null)
        assertNotNull(cipherB64)
        val ciphertext = Base64.getDecoder().decode(cipherB64)

        // Flip bit in ciphertext
        ciphertext[0] = (ciphertext[0].toInt() xor 0x01).toByte()
        val tamperedCipherB64 = Base64.getEncoder().encodeToString(ciphertext)
        mockPrefs.edit().putString(SharedPreferencesTokenStorage.KEY_ENCRYPTED_DATA, tamperedCipherB64).commit()

        // getToken() must detect tampering, wipe storage, and return null
        assertNull("Tampered ciphertext must fail authentication and return null", storage.getToken())
        assertFalse("Storage must be wiped after tampering", storage.hasToken())
        assertNull(mockPrefs.getString(SharedPreferencesTokenStorage.KEY_ENCRYPTED_DATA, null))
    }

    @Test
    fun testTamperedIvIsClearedAndGetTokenReturnsNull() {
        val token = "tamper-iv-test-token"
        storage.saveToken(token)

        val ivB64 = mockPrefs.getString(SharedPreferencesTokenStorage.KEY_ENCRYPTED_IV, null)
        assertNotNull(ivB64)
        val iv = Base64.getDecoder().decode(ivB64)

        // Preserve 12-byte length, flip bit in IV
        iv[0] = (iv[0].toInt() xor 0x01).toByte()
        val tamperedIvB64 = Base64.getEncoder().encodeToString(iv)
        mockPrefs.edit().putString(SharedPreferencesTokenStorage.KEY_ENCRYPTED_IV, tamperedIvB64).commit()

        assertNull("Tampered IV must fail authentication and return null", storage.getToken())
        assertFalse("Storage must be wiped after IV tampering", storage.hasToken())
    }

    @Test
    fun testInvalidOrInvalidatedKeyFailsClosed() {
        val token = "key-invalidation-test"
        storage.saveToken(token)

        // Change the underlying key (simulating key deletion or hardware keystore invalidation)
        val newKey = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
        keyProvider.setSecretKey(newKey)

        assertNull("Decryption with invalidated key must fail and return null", storage.getToken())
        assertFalse("Credentials must be cleared when key fails", storage.hasToken())
    }

    @Test
    fun testClearTokenRemovesAllTokenRelatedEntries() {
        storage.saveToken("to-be-cleared-token")
        assertTrue(storage.hasToken())

        storage.clearToken()

        assertFalse(storage.hasToken())
        assertNull(storage.getToken())
        assertFalse(mockPrefs.contains(SharedPreferencesTokenStorage.KEY_ENCRYPTED_IV))
        assertFalse(mockPrefs.contains(SharedPreferencesTokenStorage.KEY_ENCRYPTED_DATA))
        assertFalse(mockPrefs.contains(SharedPreferencesTokenStorage.KEY_STORAGE_VERSION))
        assertFalse(mockPrefs.contains(SharedPreferencesTokenStorage.KEY_LEGACY_AUTH_TOKEN))
    }

    @Test
    fun testLegacyPlaintextTokenMigrationEncryptsTokenAndRemovesOldEntry() {
        val legacyPlaintextToken = "legacy-phase-2-2-plaintext-token"

        // Simulate existing Phase 2.2 unencrypted state
        mockPrefs.edit().putString(SharedPreferencesTokenStorage.KEY_LEGACY_AUTH_TOKEN, legacyPlaintextToken).commit()

        assertTrue(mockPrefs.contains(SharedPreferencesTokenStorage.KEY_LEGACY_AUTH_TOKEN))
        assertFalse(mockPrefs.contains(SharedPreferencesTokenStorage.KEY_ENCRYPTED_DATA))

        // Read token: triggers transparent migration
        val retrieved = storage.getToken()
        assertEquals(legacyPlaintextToken, retrieved)

        // Verify that old plaintext key has been removed
        assertFalse(
            "Legacy plaintext key must be removed after migration",
            mockPrefs.contains(SharedPreferencesTokenStorage.KEY_LEGACY_AUTH_TOKEN)
        )

        // Verify that encrypted entries are now stored
        assertTrue(mockPrefs.contains(SharedPreferencesTokenStorage.KEY_ENCRYPTED_IV))
        assertTrue(mockPrefs.contains(SharedPreferencesTokenStorage.KEY_ENCRYPTED_DATA))
        assertTrue(mockPrefs.contains(SharedPreferencesTokenStorage.KEY_STORAGE_VERSION))

        // Re-read token from encrypted representation
        assertEquals(legacyPlaintextToken, storage.getToken())
    }

    @Test
    fun testMalformedBase64PayloadFailsClosed() {
        mockPrefs.edit()
            .putString(SharedPreferencesTokenStorage.KEY_ENCRYPTED_IV, "not-valid-base64-!@#$%")
            .putString(SharedPreferencesTokenStorage.KEY_ENCRYPTED_DATA, "also-invalid-base64-!@#$%")
            .putInt(SharedPreferencesTokenStorage.KEY_STORAGE_VERSION, 1)
            .commit()

        assertNull("Malformed Base64 must fail closed and return null", storage.getToken())
        assertFalse(storage.hasToken())
    }
}

/**
 * Lightweight in-memory implementation of SharedPreferences for JVM unit testing.
 */
class MockSharedPreferences : SharedPreferences {

    private val data = mutableMapOf<String, Any?>()

    override fun getAll(): MutableMap<String, *> = HashMap(data)

    override fun getString(key: String?, defValue: String?): String? =
        (data[key] as? String) ?: defValue

    override fun getStringSet(key: String?, defValues: MutableSet<String>?): MutableSet<String>? =
        @Suppress("UNCHECKED_CAST") (data[key] as? MutableSet<String>) ?: defValues

    override fun getInt(key: String?, defValue: Int): Int =
        (data[key] as? Int) ?: defValue

    override fun getLong(key: String?, defValue: Long): Long =
        (data[key] as? Long) ?: defValue

    override fun getFloat(key: String?, defValue: Float): Float =
        (data[key] as? Float) ?: defValue

    override fun getBoolean(key: String?, defValue: Boolean): Boolean =
        (data[key] as? Boolean) ?: defValue

    override fun contains(key: String?): Boolean = data.containsKey(key)

    override fun edit(): SharedPreferences.Editor = EditorImpl(this)

    override fun registerOnSharedPreferenceChangeListener(listener: SharedPreferences.OnSharedPreferenceChangeListener?) {}

    override fun unregisterOnSharedPreferenceChangeListener(listener: SharedPreferences.OnSharedPreferenceChangeListener?) {}

    private class EditorImpl(private val prefs: MockSharedPreferences) : SharedPreferences.Editor {
        private val modifications = mutableMapOf<String, Any?>()
        private val removals = mutableSetOf<String>()
        private var clear = false

        override fun putString(key: String?, value: String?): SharedPreferences.Editor {
            if (key != null) modifications[key] = value
            return this
        }

        override fun putStringSet(key: String?, values: MutableSet<String>?): SharedPreferences.Editor {
            if (key != null) modifications[key] = values
            return this
        }

        override fun putInt(key: String?, value: Int): SharedPreferences.Editor {
            if (key != null) modifications[key] = value
            return this
        }

        override fun putLong(key: String?, value: Long): SharedPreferences.Editor {
            if (key != null) modifications[key] = value
            return this
        }

        override fun putFloat(key: String?, value: Float): SharedPreferences.Editor {
            if (key != null) modifications[key] = value
            return this
        }

        override fun putBoolean(key: String?, value: Boolean): SharedPreferences.Editor {
            if (key != null) modifications[key] = value
            return this
        }

        override fun remove(key: String?): SharedPreferences.Editor {
            if (key != null) removals.add(key)
            return this
        }

        override fun clear(): SharedPreferences.Editor {
            clear = true
            return this
        }

        override fun commit(): Boolean {
            apply()
            return true
        }

        override fun apply() {
            synchronized(prefs.data) {
                if (clear) {
                    prefs.data.clear()
                }
                for (key in removals) {
                    prefs.data.remove(key)
                }
                prefs.data.putAll(modifications)
            }
        }
    }
}
