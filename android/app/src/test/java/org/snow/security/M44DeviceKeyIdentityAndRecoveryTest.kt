package org.snow.security

import android.content.Context
import android.content.ContextWrapper
import android.content.SharedPreferences
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.security.MessageDigest
import java.util.Base64
import java.util.UUID
import javax.crypto.KeyGenerator

/**
 * M4.4 Stage 2 Android Cryptographic Identity & Recovery tests:
 * - Ed25519 key generation and RFC 8032 / canonical SHA-256 SNW-XXXX-XXXX parity with Python
 * - AES-256-GCM encryption at rest (no raw seed stored in SharedPreferences)
 * - Fail-closed corruption checks (ciphertext tampering, IV corruption, wrong tag, missing Keystore key)
 * - Recovery key export/restore + PBKDF2-SHA256 / AES-GCM backup round-trip
 * - Trust separation: recovery wipes old pairing tokens, cert pins, relay creds, and OAuth state
 * - Legacy UUID DeviceIdentity.deviceId remains intact
 */
class M44DeviceKeyIdentityAndRecoveryTest {

    private class MemPrefs : SharedPreferences {
        val map = mutableMapOf<String, Any?>()
        override fun getAll(): MutableMap<String, *> = HashMap(map)
        override fun getString(key: String?, defValue: String?): String? = map[key] as? String ?: defValue
        override fun getStringSet(key: String?, defValues: MutableSet<String>?): MutableSet<String>? = defValues
        override fun getInt(key: String?, defValue: Int): Int = (map[key] as? Int) ?: defValue
        override fun getLong(key: String?, defValue: Long): Long = (map[key] as? Long) ?: defValue
        override fun getFloat(key: String?, defValue: Float): Float = (map[key] as? Float) ?: defValue
        override fun getBoolean(key: String?, defValue: Boolean): Boolean = (map[key] as? Boolean) ?: defValue
        override fun contains(key: String?): Boolean = map.containsKey(key)
        override fun edit(): SharedPreferences.Editor = object : SharedPreferences.Editor {
            private val pending = mutableMapOf<String, Any?>()
            private val removals = mutableSetOf<String>()
            private var clearAll = false
            override fun putString(key: String?, value: String?) = apply { if (key != null) pending[key] = value }
            override fun putStringSet(key: String?, values: MutableSet<String>?) = apply {}
            override fun putInt(key: String?, value: Int) = apply { if (key != null) pending[key] = value }
            override fun putLong(key: String?, value: Long) = apply { if (key != null) pending[key] = value }
            override fun putFloat(key: String?, value: Float) = apply { if (key != null) pending[key] = value }
            override fun putBoolean(key: String?, value: Boolean) = apply { if (key != null) pending[key] = value }
            override fun remove(key: String?) = apply { if (key != null) removals.add(key) }
            override fun clear() = apply { clearAll = true }
            override fun commit(): Boolean {
                if (clearAll) map.clear()
                for (r in removals) map.remove(r)
                for ((k, v) in pending) if (v == null) map.remove(k) else map[k] = v
                return true
            }
            override fun apply() { commit() }
        }
        override fun registerOnSharedPreferenceChangeListener(listener: SharedPreferences.OnSharedPreferenceChangeListener?) {}
        override fun unregisterOnSharedPreferenceChangeListener(listener: SharedPreferences.OnSharedPreferenceChangeListener?) {}
    }

    private fun newStubContext(): Pair<Context, MutableMap<String, MemPrefs>> {
        val prefsMap = mutableMapOf<String, MemPrefs>()
        val dir = java.nio.file.Files.createTempDirectory("m44_devkey_test_").toFile()
        val ctx = object : ContextWrapper(null) {
            override fun getApplicationContext(): Context = this
            override fun getFilesDir(): File = dir
            override fun getCacheDir(): File = dir
            override fun getPackageName(): String = "org.snow"
            override fun getSharedPreferences(name: String?, mode: Int): SharedPreferences =
                prefsMap.getOrPut(name ?: "default") { MemPrefs() }
        }
        return ctx to prefsMap
    }

    @Test
    fun ed25519KeypairGenerationCanonicalSnowIdAndRestartPersistence() {
        val (ctx, prefsMap) = newStubContext()
        try {
            // Preserve legacy DeviceIdentity.deviceId across permanent key creation
            val legacy = DeviceIdentity.getOrCreate(ctx, customDeviceName = "PixelTest")
            val keyProvider = InMemoryAesKeyProvider()
            val mgr1 = DeviceKeyManager(ctx, keyProvider = keyProvider)
            val id1 = mgr1.getOrCreate()

            assertTrue(DeviceKeyIdentity.SNOW_ID_REGEX.matches(id1.snowId))
            val rawPub = DeviceKeyIdentity.decodeEd25519Pubkey(id1.publicKeyB64)
            assertEquals(32, rawPub.size)
            val shaHex = MessageDigest.getInstance("SHA-256").digest(rawPub)
                .take(4).joinToString("") { "%02X".format(it) }
            assertEquals("SNW-${shaHex.substring(0, 4)}-${shaHex.substring(4, 8)}", id1.snowId)

            // Verify raw private seed never appears in prefs or toString()/toPublicMap()
            val seedBytes = id1.copySeedForProtectedPersistence()
            val seedB64Url = Base64.getUrlEncoder().withoutPadding().encodeToString(seedBytes)
            val seedB64Std = Base64.getEncoder().encodeToString(seedBytes)
            val keyPrefsDump = prefsMap[DeviceKeyManager.PREFS_NAME]!!.getAll().toString()
            assertFalse(keyPrefsDump.contains(seedB64Url))
            assertFalse(keyPrefsDump.contains(seedB64Std))
            assertFalse(id1.toString().contains(seedB64Url))
            assertFalse(id1.toPublicMap().values.any { it.contains(seedB64Url) })

            // RFC 8032 Vector 1 cross-language parity with Python
            val vecSeed = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
                .chunked(2).map { it.toInt(16).toByte() }.toByteArray()
            val vecIdent = DeviceKeyIdentity.fromSeed(vecSeed)
            val vecExpectedPub = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
                .chunked(2).map { it.toInt(16).toByte() }.toByteArray()
            assertEquals(
                Base64.getUrlEncoder().withoutPadding().encodeToString(vecExpectedPub),
                vecIdent.publicKeyB64
            )
            assertEquals(DeviceKeyIdentity.deriveSnowIdFromPublicKey(vecExpectedPub), vecIdent.snowId)

            // Restart simulation with fresh DeviceKeyManager over same prefs & Keystore key
            val mgr2 = DeviceKeyManager(ctx, keyProvider = keyProvider)
            val id2 = mgr2.getOrCreate()
            assertEquals(id1.snowId, id2.snowId)
            assertEquals(id1.publicKeyB64, id2.publicKeyB64)

            // Challenge sign/verify check
            val msg = DeviceKeyIdentity.canonicalDeviceHubChallengeMessage(
                challengeId = "ch-1",
                nonce = "nonce-xyz",
                expiresAt = 1999999999L,
                snowId = id2.snowId,
                publicKeyB64 = id2.publicKeyB64,
                deviceId = legacy.deviceId,
                networkId = ""
            )
            val sig = id2.signMessage(msg)
            assertTrue(DeviceKeyIdentity.verifyEd25519Signature(id1.publicKeyB64, msg, sig))
            assertEquals(legacy.deviceId, DeviceIdentity.getOrCreate(ctx).deviceId)
        } finally {
            ctx.filesDir.deleteRecursively()
        }
    }

    @Test
    fun corruptCiphertextInvalidNonceWrongTagAndMissingKeystoreFailClosed() {
        val (ctx, prefsMap) = newStubContext()
        try {
            val keyProvider = InMemoryAesKeyProvider()
            val mgr = DeviceKeyManager(ctx, keyProvider = keyProvider)
            val orig = mgr.getOrCreate()
            val keyPrefs = prefsMap[DeviceKeyManager.PREFS_NAME]!!
            val origMap = HashMap(keyPrefs.getAll())

            // 1. Tampered ciphertext -> AEADBadTagException wrapped in DeviceKeyCorruptException (no regeneration)
            val ctBytes = Base64.getDecoder().decode(keyPrefs.getString("encrypted_seed_b64", "")!!)
            ctBytes[0] = (ctBytes[0].toInt() xor 0xFF).toByte()
            keyPrefs.edit().putString("encrypted_seed_b64", Base64.getEncoder().encodeToString(ctBytes)).commit()
            assertThrowsCorrupt { DeviceKeyManager(ctx, keyProvider = keyProvider).getOrCreate() }

            // 2. Invalid nonce length
            origMap.forEach { (k, v) ->
                when (v) {
                    is Int -> keyPrefs.edit().putInt(k, v).commit()
                    is String -> keyPrefs.edit().putString(k, v).commit()
                }
            }
            val badIv = ByteArray(8)
            keyPrefs.edit().putString("seed_iv_b64", Base64.getEncoder().encodeToString(badIv)).commit()
            assertThrowsCorrupt { DeviceKeyManager(ctx, keyProvider = keyProvider).getOrCreate() }

            // 3. Swapped / missing Keystore AES key -> fails closed
            origMap.forEach { (k, v) ->
                when (v) {
                    is Int -> keyPrefs.edit().putInt(k, v).commit()
                    is String -> keyPrefs.edit().putString(k, v).commit()
                }
            }
            val swappedKey = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
            assertThrowsCorrupt { DeviceKeyManager(ctx, keyProvider = InMemoryAesKeyProvider(swappedKey)).getOrCreate() }

            // Intact key provider still loads exact original identity without silent replacement
            val intact = DeviceKeyManager(ctx, keyProvider = keyProvider).getOrCreate()
            assertEquals(orig.snowId, intact.snowId)
            assertEquals(orig.publicKeyB64, intact.publicKeyB64)
        } finally {
            ctx.filesDir.deleteRecursively()
        }
    }

    @Test
    fun recoveryKeyAndEncryptedBackupRestoreExactIdentityAndWipePriorTrust() {
        val (ctx1, _) = newStubContext()
        val (ctx2, prefsMap2) = newStubContext()
        try {
            val kp1 = InMemoryAesKeyProvider()
            val mgr1 = DeviceKeyManager(ctx1, keyProvider = kp1)
            val orig = mgr1.getOrCreate()
            val legacyBefore = DeviceIdentity.getOrCreate(ctx2, customDeviceName = "Phone2")

            val recoveryKey = DeviceKeyManager.exportRecoveryKey(orig)
            assertTrue(recoveryKey.startsWith("SNW-REC-V1-"))

            // Invalid checksum / ambiguous alphabet must fail cleanly
            var badRec = false
            try {
                DeviceKeyManager.parseRecoveryKey(recoveryKey.dropLast(1) + if (recoveryKey.last() == 'A') 'B' else 'A')
            } catch (_: DeviceRecoveryFormatException) {
                badRec = true
            }
            assertTrue(badRec)

            // Seed old peer trust, TLS pins, relay creds, adopted network, and OAuth state on target device
            val kp2 = InMemoryAesKeyProvider()
            val tokStorage2 = SharedPreferencesTokenStorage(ctx2, keyStoreManager = KeyStoreManager(kp2))
            tokStorage2.saveToken("legacy-pair-token")
            tokStorage2.saveTokenForDevice("old-pc", "per-device-token")
            prefsMap2.getOrPut("snow_cert_pins") { MemPrefs() }
                .edit().putString("pin_old", "AA:BB").commit()
            prefsMap2.getOrPut("snow_paired_devices_v2") { MemPrefs() }
                .edit().putString("devices_json", """[{"deviceId":"old-pc"}]""").commit()
            prefsMap2.getOrPut("snow_relay_security") { MemPrefs() }
                .edit().putString("relay_hub_token", "hub-tok").commit()
            prefsMap2.getOrPut("snow_android_oauth_prefs") { MemPrefs() }
                .edit().putString("clients", """["cli_old"]""").commit()
            prefsMap2.getOrPut(org.snow.ui.SnowUiRepository.PREFS_SETTINGS) { MemPrefs() }
                .edit().putString(org.snow.ui.SnowUiRepository.PREF_KEY_ADOPTED_NETWORK_ID, "SNW-NET-AABBCCDD").commit()

            // Encrypted backup round-trip check
            val backupJson = DeviceKeyManager.exportEncryptedBackup(orig, "StrongBackupPass!99")
            var wrongPass = false
            try {
                DeviceKeyManager.importEncryptedBackup(backupJson, "WrongPass123")
            } catch (_: DeviceRecoveryFormatException) {
                wrongPass = true
            }
            assertTrue(wrongPass)

            val mgr2 = DeviceKeyManager(ctx2, keyProvider = kp2)
            val restored = mgr2.restoreFromEncryptedBackup(backupJson, "StrongBackupPass!99")
            assertEquals(orig.snowId, restored.snowId)
            assertEquals(orig.publicKeyB64, restored.publicKeyB64)
            assertEquals(
                DeviceKeyManager.formatPermanentMcpUrl("https://snow-relay.onrender.com", orig.snowId),
                DeviceKeyManager.formatPermanentMcpUrl("https://snow-relay.onrender.com", restored.snowId)
            )

            // Critical trust separation assertions
            assertNull(prefsMap2["snow_paired_devices_v2"]?.getString("devices_json", null))
            assertNull(prefsMap2["snow_relay_security"]?.getString("relay_hub_token", null))
            assertNull(prefsMap2["snow_android_oauth_prefs"]?.getString("clients", null))
            assertNull(prefsMap2["snow_cert_pins"]?.getString("pin_old", null))
            assertNull(prefsMap2[org.snow.ui.SnowUiRepository.PREFS_SETTINGS]?.getString(org.snow.ui.SnowUiRepository.PREF_KEY_ADOPTED_NETWORK_ID, null))
            assertFalse(tokStorage2.hasToken())
            assertNull(tokStorage2.getTokenForDevice("old-pc"))

            // Legacy UUID deviceId remains untouched
            assertEquals(legacyBefore.deviceId, DeviceIdentity.getOrCreate(ctx2).deviceId)
        } finally {
            ctx1.filesDir.deleteRecursively()
            ctx2.filesDir.deleteRecursively()
        }
    }

    private fun assertThrowsCorrupt(block: () -> Unit) {
        var threw = false
        try {
            block()
        } catch (_: DeviceKeyCorruptException) {
            threw = true
        }
        assertTrue("Expected DeviceKeyCorruptException fail-closed", threw)
    }
}
