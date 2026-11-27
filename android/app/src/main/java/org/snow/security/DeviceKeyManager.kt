package org.snow.security

import android.content.Context
import android.content.SharedPreferences
import org.json.JSONObject
import org.snow.ui.SnowUiRepository
import java.math.BigInteger
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import java.util.Locale
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/**
 * Manages persistence, fail-closed integrity checking, checksummed recovery export/restore,
 * and strict post-recovery trust separation for Android's permanent Ed25519 [DeviceKeyIdentity].
 *
 * Security invariants:
 * - Private seed bytes (32 bytes) are NEVER stored in plaintext preferences, files, or logs.
 * - Private seed is encrypted using AES-256-GCM backed by an AndroidKeyStore non-exportable AES key
 *   (or injectable [SecretKeyProvider] in JVM tests).
 * - Deprecated EncryptedSharedPreferences is NOT used.
 * - Any corruption, auth-tag mismatch, missing Keystore key, schema mismatch, or public/seed
 *   inconsistency fails CLOSED with [DeviceKeyCorruptException] without silent regeneration.
 * - Restoring a device identity wipes old pairing tokens, pinned TLS certificates, relay credentials,
 *   adopted network ownership/membership, and Android OAuth tokens/clients/codes.
 */
class DeviceKeyManager(
    private val appContext: Context,
    keyProvider: SecretKeyProvider = AndroidKeyStoreKeyProvider(DEFAULT_KEYSTORE_ALIAS),
    private val prefs: SharedPreferences = appContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE),
    private val keyStoreManager: KeyStoreManager = KeyStoreManager(keyProvider)
) {
    private val lock = Any()

    companion object {
        private const val TAG = "DeviceKeyManager"
        const val PREFS_NAME = "snow_device_key_prefs"
        const val DEFAULT_KEYSTORE_ALIAS = "snow_device_identity_key"

        private const val KEY_SCHEMA_VERSION = "schema_version"
        private const val KEY_ALGORITHM = "algorithm"
        private const val KEY_SNOW_ID = "snow_id"
        private const val KEY_PUBLIC_KEY_B64 = "public_key_b64"
        private const val KEY_ENCRYPTED_SEED_B64 = "encrypted_seed_b64"
        private const val KEY_SEED_IV_B64 = "seed_iv_b64"
        private const val KEY_CREATED_AT = "created_at"

        const val SCHEMA_VERSION = 1
        private const val RECOVERY_VERSION = 1
        const val RECOVERY_PREFIX = "SNW-REC-V1-"
        private const val RECOVERY_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
        private val RECOVERY_DOMAIN = "snow-recovery-v1|".toByteArray(Charsets.UTF_8)
        private val BACKUP_DOMAIN_PREFIX = "snow-device-backup-v1|".toByteArray(Charsets.UTF_8)
        const val BACKUP_PBKDF2_ITERATIONS = 310_000
        const val MIN_BACKUP_PASSPHRASE_LEN = 10

        @Volatile
        private var cachedInMemory: DeviceKeyIdentity? = null

        private val secureRandom = SecureRandom()

        fun formatPermanentMcpUrl(hubBaseUrl: String, snowId: String): String {
            val cleanHub = hubBaseUrl.trim().trimEnd('/')
            val cleanId = snowId.trim().uppercase(Locale.ROOT)
            if (cleanHub.isBlank() || cleanId.isBlank()) return ""
            return "$cleanHub/u/$cleanId/mcp"
        }

        fun exportRecoveryKey(identity: DeviceKeyIdentity): String {
            val seed = identity.copySeedForProtectedPersistence()
            try {
                val versioned = ByteArray(1 + seed.size)
                versioned[0] = RECOVERY_VERSION.toByte()
                System.arraycopy(seed, 0, versioned, 1, seed.size)
                val digest = MessageDigest.getInstance("SHA-256").apply {
                    update(RECOVERY_DOMAIN)
                    update(versioned)
                }.digest()
                val full = ByteArray(37)
                System.arraycopy(versioned, 0, full, 0, 33)
                System.arraycopy(digest, 0, full, 33, 4)

                // Pack big-endian 296 bits << 4 = 300 bits -> 60 Crockford Base32 chars
                val bigInt = BigInteger(1, full).shiftLeft(4)
                val chars = CharArray(60)
                for (i in 0 until 60) {
                    val shift = 295 - (i * 5)
                    val idx = bigInt.shiftRight(shift).and(BigInteger.valueOf(31L)).toInt()
                    chars[i] = RECOVERY_ALPHABET[idx]
                }
                val rawBody = String(chars)
                val grouped = (0 until 60 step 5).joinToString("-") { rawBody.substring(it, it + 5) }
                return "$RECOVERY_PREFIX$grouped"
            } finally {
                seed.fill(0)
            }
        }

        fun parseRecoveryKey(recoveryKey: String): DeviceKeyIdentity {
            val clean = recoveryKey.trim().uppercase(Locale.ROOT)
            if (!clean.startsWith(RECOVERY_PREFIX)) {
                throw DeviceRecoveryFormatException("Recovery key must start with '$RECOVERY_PREFIX'.")
            }
            val bodyWithDashes = clean.substring(RECOVERY_PREFIX.length)
            if (bodyWithDashes.isEmpty() || bodyWithDashes.any { it != '-' && RECOVERY_ALPHABET.indexOf(it) < 0 }) {
                throw DeviceRecoveryFormatException(
                    "Recovery key contains invalid or ambiguous characters (I, L, O, U are disallowed)."
                )
            }
            val body = bodyWithDashes.replace("-", "")
            if (body.length != 60) {
                throw DeviceRecoveryFormatException("Recovery key must contain 60 encoded characters, got ${body.length}.")
            }

            var acc = BigInteger.ZERO
            val radix = BigInteger.valueOf(32L)
            for (ch in body) {
                val idx = RECOVERY_ALPHABET.indexOf(ch)
                if (idx < 0) throw DeviceRecoveryFormatException("Invalid alphabet character in recovery key.")
                acc = acc.multiply(radix).add(BigInteger.valueOf(idx.toLong()))
            }
            if (acc.and(BigInteger.valueOf(0x0FL)) != BigInteger.ZERO) {
                throw DeviceRecoveryFormatException("Recovery key has corrupted trailing padding bits.")
            }
            val unpadded = acc.shiftRight(4).toByteArray()
            val payload = ByteArray(37)
            if (unpadded.size > 38 || (unpadded.size == 38 && unpadded[0] != 0.toByte())) {
                throw DeviceRecoveryFormatException("Recovery key overflow.")
            }
            val srcOffset = maxOf(0, unpadded.size - 37)
            val dstOffset = maxOf(0, 37 - unpadded.size)
            val copyLen = minOf(37, unpadded.size)
            System.arraycopy(unpadded, srcOffset, payload, dstOffset, copyLen)

            if ((payload[0].toInt() and 0xFF) != RECOVERY_VERSION) {
                throw DeviceRecoveryFormatException("Unsupported recovery key version: ${payload[0].toInt() and 0xFF}.")
            }
            val versioned = payload.copyOfRange(0, 33)
            val suppliedChecksum = payload.copyOfRange(33, 37)
            val expectedChecksum = MessageDigest.getInstance("SHA-256").apply {
                update(RECOVERY_DOMAIN)
                update(versioned)
            }.digest().copyOfRange(0, 4)
            if (!MessageDigest.isEqual(suppliedChecksum, expectedChecksum)) {
                throw DeviceRecoveryFormatException("Recovery key checksum verification failed; verify every character.")
            }
            val seed = payload.copyOfRange(1, 33)
            return try {
                DeviceKeyIdentity.fromSeed(seed)
            } finally {
                seed.fill(0)
            }
        }

        fun exportEncryptedBackup(identity: DeviceKeyIdentity, passphrase: String): String {
            if (passphrase.length < MIN_BACKUP_PASSPHRASE_LEN) {
                throw DeviceRecoveryFormatException("Backup passphrase must be at least $MIN_BACKUP_PASSPHRASE_LEN characters.")
            }
            val salt = ByteArray(16).also { secureRandom.nextBytes(it) }
            val iv = ByteArray(12).also { secureRandom.nextBytes(it) }
            val aesKey = derivePbkdf2Key(passphrase, salt, BACKUP_PBKDF2_ITERATIONS)
            val recKey = exportRecoveryKey(identity)
            val innerJson = JSONObject().apply {
                put("version", 1)
                put("snow_id", identity.snowId)
                put("public_key_b64", identity.publicKeyB64)
                put("created_at", identity.createdAt)
                put("recovery_key", recKey)
            }.toString().toByteArray(Charsets.UTF_8)

            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, aesKey, GCMParameterSpec(128, iv))
            cipher.updateAAD(BACKUP_DOMAIN_PREFIX + identity.snowId.toByteArray(Charsets.UTF_8))
            val ct = cipher.doFinal(innerJson)

            val b64 = Base64.getUrlEncoder().withoutPadding()
            return JSONObject().apply {
                put("format", "snow-device-backup-v1")
                put("kdf", "pbkdf2_sha256")
                put("iterations", BACKUP_PBKDF2_ITERATIONS)
                put("cipher", "aes-256-gcm")
                put("snow_id", identity.snowId)
                put("salt_b64", b64.encodeToString(salt))
                put("iv_b64", b64.encodeToString(iv))
                put("ciphertext_b64", b64.encodeToString(ct))
            }.toString(2)
        }

        fun importEncryptedBackup(backupJson: String, passphrase: String): DeviceKeyIdentity {
            if (backupJson.isBlank()) throw DeviceRecoveryFormatException("Backup JSON is empty.")
            if (passphrase.isEmpty()) throw DeviceRecoveryFormatException("Passphrase is required.")
            val env = try {
                JSONObject(backupJson)
            } catch (e: Exception) {
                throw DeviceRecoveryFormatException("Malformed encrypted backup JSON.", e)
            }
            if (env.optString("format") != "snow-device-backup-v1" ||
                env.optString("kdf") != "pbkdf2_sha256" ||
                env.optString("cipher") != "aes-256-gcm"
            ) {
                throw DeviceRecoveryFormatException("Unsupported encrypted backup format or parameters.")
            }
            val iterations = env.optInt("iterations", 0)
            if (iterations < 100_000) {
                throw DeviceRecoveryFormatException("Backup KDF iterations below safe threshold.")
            }
            val expectedSnowId = env.optString("snow_id", "").trim().uppercase(Locale.ROOT)
            if (!DeviceKeyIdentity.SNOW_ID_REGEX.matches(expectedSnowId)) {
                throw DeviceRecoveryFormatException("Invalid snow_id in encrypted backup metadata.")
            }
            val dec = Base64.getUrlDecoder()
            fun decodeField(name: String): ByteArray {
                val raw = env.optString(name, "").trim()
                if (raw.isEmpty()) throw DeviceRecoveryFormatException("Missing encrypted backup field '$name'.")
                val pad = "=".repeat((4 - raw.length % 4) % 4)
                return dec.decode(raw + pad)
            }
            val plaintext = try {
                val salt = decodeField("salt_b64")
                val iv = decodeField("iv_b64")
                val ct = decodeField("ciphertext_b64")
                val aesKey = derivePbkdf2Key(passphrase, salt, iterations)
                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                cipher.init(Cipher.DECRYPT_MODE, aesKey, GCMParameterSpec(128, iv))
                cipher.updateAAD(BACKUP_DOMAIN_PREFIX + expectedSnowId.toByteArray(Charsets.UTF_8))
                cipher.doFinal(ct)
            } catch (e: AEADBadTagException) {
                throw DeviceRecoveryFormatException("Wrong backup passphrase or tampered encrypted backup.", e)
            } catch (e: DeviceRecoveryFormatException) {
                throw e
            } catch (e: Exception) {
                throw DeviceRecoveryFormatException("Failed decrypting device backup: ${e.message}", e)
            }
            val inner = try {
                JSONObject(String(plaintext, Charsets.UTF_8))
            } catch (e: Exception) {
                throw DeviceRecoveryFormatException("Corrupt inner backup JSON.", e)
            }
            val recKey = inner.optString("recovery_key", "")
            val parsed = parseRecoveryKey(recKey)
            if (parsed.snowId != expectedSnowId) {
                throw DeviceRecoveryFormatException("Recovered keypair snowId does not match backup metadata.")
            }
            val seedCopy = parsed.copySeedForProtectedPersistence()
            return try {
                DeviceKeyIdentity.fromSeed(
                    seed = seedCopy,
                    createdAt = inner.optString("created_at", parsed.createdAt).ifBlank { parsed.createdAt }
                )
            } finally {
                seedCopy.fill(0)
            }
        }

        private fun derivePbkdf2Key(passphrase: String, salt: ByteArray, iterations: Int): SecretKeySpec {
            val spec = PBEKeySpec(passphrase.toCharArray(), salt, iterations, 256)
            val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
            val encoded = factory.generateSecret(spec).encoded
            return try {
                SecretKeySpec(encoded, "AES")
            } finally {
                spec.clearPassword()
            }
        }
    }

    private fun hasAnyPersistedEntry(): Boolean =
        prefs.contains(KEY_SCHEMA_VERSION) ||
            prefs.contains(KEY_ALGORITHM) ||
            prefs.contains(KEY_SNOW_ID) ||
            prefs.contains(KEY_PUBLIC_KEY_B64) ||
            prefs.contains(KEY_ENCRYPTED_SEED_B64) ||
            prefs.contains(KEY_SEED_IV_B64)

    fun loadExistingOrThrow(): DeviceKeyIdentity? = synchronized(lock) {
        if (!hasAnyPersistedEntry()) return null

        val version = prefs.getInt(KEY_SCHEMA_VERSION, -1)
        if (version != SCHEMA_VERSION) {
            throw DeviceKeyCorruptException("Unsupported persisted device key schema version: $version.")
        }
        val alg = prefs.getString(KEY_ALGORITHM, null)?.trim()
        if (alg != DeviceKeyIdentity.ALGORITHM) {
            throw DeviceKeyCorruptException("Unsupported persisted device key algorithm: $alg.")
        }
        val storedSnowId = prefs.getString(KEY_SNOW_ID, null)?.trim()?.uppercase(Locale.ROOT).orEmpty()
        val storedPubB64 = prefs.getString(KEY_PUBLIC_KEY_B64, null)?.trim().orEmpty()
        val encSeedB64 = prefs.getString(KEY_ENCRYPTED_SEED_B64, null)?.trim().orEmpty()
        val ivB64 = prefs.getString(KEY_SEED_IV_B64, null)?.trim().orEmpty()
        val createdAt = prefs.getString(KEY_CREATED_AT, null)?.trim().orEmpty()

        if (!DeviceKeyIdentity.SNOW_ID_REGEX.matches(storedSnowId) ||
            storedPubB64.isEmpty() || encSeedB64.isEmpty() || ivB64.isEmpty() || createdAt.isEmpty()
        ) {
            throw DeviceKeyCorruptException(
                "Persisted device key record is incomplete or malformed; explicit recovery required."
            )
        }

        val ivBytes = try {
            Base64.getDecoder().decode(ivB64)
        } catch (e: Exception) {
            throw DeviceKeyCorruptException("Corrupt encrypted seed IV in storage.", e)
        }
        val cipherBytes = try {
            Base64.getDecoder().decode(encSeedB64)
        } catch (e: Exception) {
            throw DeviceKeyCorruptException("Corrupt encrypted seed ciphertext in storage.", e)
        }

        if (ivBytes.size != KeyStoreManager.GCM_IV_LENGTH_BYTES) {
            throw DeviceKeyCorruptException("Invalid AES-GCM IV length: ${ivBytes.size}.")
        }

        val seedBytes = try {
            keyStoreManager.decrypt(EncryptedPayload(iv = ivBytes, ciphertext = cipherBytes))
        } catch (e: AEADBadTagException) {
            throw DeviceKeyCorruptException("AES-GCM authentication tag verification failed; device key data tampered or Keystore key changed.", e)
        } catch (e: Exception) {
            throw DeviceKeyCorruptException("Failed decrypting device Ed25519 seed via AndroidKeyStore: ${e.message}", e)
        }

        return try {
            if (seedBytes.size != DeviceKeyIdentity.SEED_BYTES) {
                throw DeviceKeyCorruptException("Decrypted Ed25519 seed has invalid length: ${seedBytes.size}.")
            }
            val reconstructed = DeviceKeyIdentity.fromSeed(seedBytes, createdAt)
            if (reconstructed.publicKeyB64 != storedPubB64 || reconstructed.snowId != storedSnowId) {
                throw DeviceKeyCorruptException(
                    "Stored device key metadata mismatch (corrupt public key or snowId); refusing silent regeneration."
                )
            }
            reconstructed
        } finally {
            seedBytes.fill(0)
        }
    }

    private fun persistEncrypted(identity: DeviceKeyIdentity) {
        val seed = identity.copySeedForProtectedPersistence()
        try {
            val encrypted = keyStoreManager.encrypt(seed)
            val b64 = Base64.getEncoder()
            val committed = prefs.edit()
                .putInt(KEY_SCHEMA_VERSION, SCHEMA_VERSION)
                .putString(KEY_ALGORITHM, DeviceKeyIdentity.ALGORITHM)
                .putString(KEY_SNOW_ID, identity.snowId)
                .putString(KEY_PUBLIC_KEY_B64, identity.publicKeyB64)
                .putString(KEY_ENCRYPTED_SEED_B64, b64.encodeToString(encrypted.ciphertext))
                .putString(KEY_SEED_IV_B64, b64.encodeToString(encrypted.iv))
                .putString(KEY_CREATED_AT, identity.createdAt)
                .commit()
            if (!committed) {
                throw DeviceKeyCorruptException("Failed committing encrypted device key identity to SharedPreferences.")
            }
        } finally {
            seed.fill(0)
        }
    }

    /**
     * Load existing persistent cryptographic device identity or generate a fresh one when none exists.
     *
     * Fails CLOSED with [DeviceKeyCorruptException] if existing storage is present but invalid/corrupt.
     * Preserves legacy UUID [DeviceIdentity] untouched.
     */
    fun getOrCreate(): DeviceKeyIdentity = synchronized(lock) {
        loadExistingOrThrow()?.let { loaded ->
            cachedInMemory = loaded
            return loaded
        }
        val fresh = DeviceKeyIdentity.generate()
        persistEncrypted(fresh)
        val reloaded = loadExistingOrThrow()
            ?: throw DeviceKeyCorruptException("Device key identity vanished immediately after persistence.")
        cachedInMemory = reloaded
        SafeLog.i(TAG, "Generated permanent Ed25519 device identity [${reloaded.snowId}] protected via Keystore AES-GCM")
        return reloaded
    }

    fun restoreFromRecoveryKey(
        recoveryKey: String,
        trustResetCallback: (() -> Unit)? = null
    ): DeviceKeyIdentity = synchronized(lock) {
        val parsed = parseRecoveryKey(recoveryKey)
        persistAndVerifyRestored(parsed, trustResetCallback)
    }

    fun restoreFromEncryptedBackup(
        backupJson: String,
        passphrase: String,
        trustResetCallback: (() -> Unit)? = null
    ): DeviceKeyIdentity = synchronized(lock) {
        val parsed = importEncryptedBackup(backupJson, passphrase)
        persistAndVerifyRestored(parsed, trustResetCallback)
    }

    private fun persistAndVerifyRestored(
        restored: DeviceKeyIdentity,
        trustResetCallback: (() -> Unit)?
    ): DeviceKeyIdentity {
        persistEncrypted(restored)
        val reloaded = loadExistingOrThrow()
            ?: throw DeviceKeyCorruptException("Restored device key failed post-persistence reload check.")
        val nonce = ByteArray(32).also { secureRandom.nextBytes(it) }
        val sig = reloaded.signMessage(nonce)
        if (!reloaded.verifyOwnSignature(nonce, sig)) {
            throw DeviceKeyCorruptException("Restored device keypair failed cryptographic signature verification.")
        }
        cachedInMemory = reloaded
        clearPeerTrustAndOAuthOnRecovery()
        trustResetCallback?.invoke()
        SafeLog.i(TAG, "Restored permanent Ed25519 device identity [${reloaded.snowId}]; cleared prior peer/OAuth trust")
        return reloaded
    }

    /**
     * Enforce post-recovery trust separation:
     * Wipe pairing tokens, pinned TLS certs, saved peer trust records, relay sessions,
     * adopted network membership, and Android OAuth tokens/clients/codes.
     */
    fun clearPeerTrustAndOAuthOnRecovery() {
        try {
            SharedPreferencesTokenStorage(appContext).clearAllTokens()
        } catch (_: Exception) {}
        try {
            SharedPreferencesTokenStorage(appContext, prefName = SharedPreferencesTokenStorage.PEER_HOST_PREFS_NAME).clearAllTokens()
        } catch (_: Exception) {}
        try {
            appContext.getSharedPreferences("snow_cert_pins", Context.MODE_PRIVATE).edit().clear().commit()
        } catch (_: Exception) {}
        try {
            appContext.getSharedPreferences("snow_cert_pins_v2", Context.MODE_PRIVATE).edit().clear().commit()
        } catch (_: Exception) {}
        try {
            appContext.getSharedPreferences("snow_paired_devices_v2", Context.MODE_PRIVATE).edit().clear().commit()
        } catch (_: Exception) {}
        try {
            appContext.getSharedPreferences("snow_relay_security", Context.MODE_PRIVATE).edit().clear().commit()
        } catch (_: Exception) {}
        try {
            appContext.getSharedPreferences("snow_android_oauth_prefs", Context.MODE_PRIVATE).edit().clear().commit()
        } catch (_: Exception) {}
        try {
            appContext.getSharedPreferences("snow_android_oauth_secrets", Context.MODE_PRIVATE).edit().clear().commit()
        } catch (_: Exception) {}
        try {
            appContext.getSharedPreferences(SnowUiRepository.PREFS_SETTINGS, Context.MODE_PRIVATE).edit()
                .remove(SnowUiRepository.PREF_KEY_ADOPTED_NETWORK_ID)
                .remove("remote_relay_group_id")
                .commit()
        } catch (_: Exception) {}
    }
}
