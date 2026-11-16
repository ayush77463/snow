package org.snow.security

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import javax.crypto.AEADBadTagException
import javax.crypto.KeyGenerator

class KeyStoreManagerTest {

    private lateinit var keyProvider: InMemoryAesKeyProvider
    private lateinit var keyStoreManager: KeyStoreManager

    @Before
    fun setUp() {
        keyProvider = InMemoryAesKeyProvider()
        keyStoreManager = KeyStoreManager(keyProvider)
    }

    @Test
    fun testAesGcmEncryptionDecryptionRoundTrip() {
        val plaintext = "snow-pairing-token-super-secret-xyz-12345".toByteArray(Charsets.UTF_8)
        val encrypted = keyStoreManager.encrypt(plaintext)

        assertNotNull(encrypted.iv)
        assertEquals(KeyStoreManager.GCM_IV_LENGTH_BYTES, encrypted.iv.size)
        assertTrue(encrypted.ciphertext.isNotEmpty())

        val decrypted = keyStoreManager.decrypt(encrypted)
        assertArrayEquals(plaintext, decrypted)
        assertEquals("snow-pairing-token-super-secret-xyz-12345", String(decrypted, Charsets.UTF_8))
    }

    @Test
    fun testIdenticalPlaintextProducesDifferentIvs() {
        val plaintext = "identical-plaintext-sample".toByteArray(Charsets.UTF_8)
        val encrypted1 = keyStoreManager.encrypt(plaintext)
        val encrypted2 = keyStoreManager.encrypt(plaintext)

        assertFalse(
            "Repeated encryptions must never reuse the same IV",
            encrypted1.iv.contentEquals(encrypted2.iv)
        )
        assertFalse(
            "Ciphertexts must differ due to randomized IV",
            encrypted1.ciphertext.contentEquals(encrypted2.ciphertext)
        )
    }

    @Test
    fun testDecryptionWithCorrectIvAndCiphertextSucceeds() {
        val message = "authenticated-token-payload"
        val encrypted = keyStoreManager.encrypt(message.toByteArray(Charsets.UTF_8))

        val decrypted = keyStoreManager.decrypt(
            EncryptedPayload(iv = encrypted.iv.clone(), ciphertext = encrypted.ciphertext.clone())
        )
        assertEquals(message, String(decrypted, Charsets.UTF_8))
    }

    @Test
    fun testFlippingOneBitInCiphertextCausesAuthenticationFailure() {
        val plaintext = "confidential-token-material".toByteArray(Charsets.UTF_8)
        val encrypted = keyStoreManager.encrypt(plaintext)

        // Flip bit in the ciphertext portion (first byte)
        val tamperedCiphertext = encrypted.ciphertext.clone()
        tamperedCiphertext[0] = (tamperedCiphertext[0].toInt() xor 0x01).toByte()

        try {
            keyStoreManager.decrypt(EncryptedPayload(iv = encrypted.iv, ciphertext = tamperedCiphertext))
            fail("Decryption of tampered ciphertext must throw AEADBadTagException")
        } catch (e: Exception) {
            assertTrue(
                "Expected AEADBadTagException or Tag mismatch, got ${e.javaClass.name}: ${e.message}",
                e is AEADBadTagException || e.cause is AEADBadTagException
            )
        }
    }

    @Test
    fun testFlippingOneBitInAuthenticationTagCausesAuthenticationFailure() {
        val plaintext = "confidential-token-material".toByteArray(Charsets.UTF_8)
        val encrypted = keyStoreManager.encrypt(plaintext)

        // Flip bit in the trailing 16-byte authentication tag
        val tamperedCiphertext = encrypted.ciphertext.clone()
        val lastIndex = tamperedCiphertext.size - 1
        tamperedCiphertext[lastIndex] = (tamperedCiphertext[lastIndex].toInt() xor 0x01).toByte()

        try {
            keyStoreManager.decrypt(EncryptedPayload(iv = encrypted.iv, ciphertext = tamperedCiphertext))
            fail("Decryption of tampered authentication tag must throw AEADBadTagException")
        } catch (e: Exception) {
            assertTrue(
                "Expected AEADBadTagException, got ${e.javaClass.name}: ${e.message}",
                e is AEADBadTagException || e.cause is AEADBadTagException
            )
        }
    }

    @Test
    fun testFlippingOneBitInIvCausesAuthenticationFailure() {
        val plaintext = "confidential-token-material".toByteArray(Charsets.UTF_8)
        val encrypted = keyStoreManager.encrypt(plaintext)

        // Preserve valid 12-byte IV length, but flip one bit
        val tamperedIv = encrypted.iv.clone()
        tamperedIv[0] = (tamperedIv[0].toInt() xor 0x01).toByte()

        try {
            keyStoreManager.decrypt(EncryptedPayload(iv = tamperedIv, ciphertext = encrypted.ciphertext))
            fail("Decryption with tampered IV must fail authentication")
        } catch (e: Exception) {
            assertTrue(
                "Expected AEADBadTagException, got ${e.javaClass.name}: ${e.message}",
                e is AEADBadTagException || e.cause is AEADBadTagException
            )
        }
    }

    @Test
    fun testInvalidIvLengthIsRejected() {
        val plaintext = "test-data".toByteArray(Charsets.UTF_8)
        val encrypted = keyStoreManager.encrypt(plaintext)

        // IV with 8 bytes instead of 12
        val shortIv = ByteArray(8) { 1 }
        try {
            keyStoreManager.decrypt(EncryptedPayload(iv = shortIv, ciphertext = encrypted.ciphertext))
            fail("Invalid IV length must throw IllegalArgumentException")
        } catch (e: IllegalArgumentException) {
            assertTrue(e.message?.contains("Invalid GCM IV length") == true)
        }

        // IV with 16 bytes instead of 12
        val longIv = ByteArray(16) { 1 }
        try {
            keyStoreManager.decrypt(EncryptedPayload(iv = longIv, ciphertext = encrypted.ciphertext))
            fail("Invalid IV length must throw IllegalArgumentException")
        } catch (e: IllegalArgumentException) {
            assertTrue(e.message?.contains("Invalid GCM IV length") == true)
        }
    }

    @Test
    fun testEmptyOrMalformedPayloadIsRejected() {
        // Empty plaintext
        try {
            keyStoreManager.encrypt(ByteArray(0))
            fail("Encrypting empty plaintext must throw IllegalArgumentException")
        } catch (e: IllegalArgumentException) {
            assertTrue(e.message?.contains("Plaintext cannot be empty") == true)
        }

        // Empty IV
        try {
            keyStoreManager.decrypt(EncryptedPayload(iv = ByteArray(0), ciphertext = ByteArray(16)))
            fail("Decrypting with empty IV must throw IllegalArgumentException")
        } catch (e: IllegalArgumentException) {
            assertTrue(e.message?.contains("IV cannot be empty") == true)
        }

        // Empty ciphertext
        try {
            keyStoreManager.decrypt(EncryptedPayload(iv = ByteArray(12), ciphertext = ByteArray(0)))
            fail("Decrypting with empty ciphertext must throw IllegalArgumentException")
        } catch (e: IllegalArgumentException) {
            assertTrue(e.message?.contains("Ciphertext cannot be empty") == true)
        }
    }

    @Test
    fun testDecryptionWithDifferentKeyFailsClosed() {
        val plaintext = "sensitive-device-token".toByteArray(Charsets.UTF_8)
        val encrypted = keyStoreManager.encrypt(plaintext)

        // Switch to an alternate AES-256 key
        val alternateKey = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
        keyProvider.setSecretKey(alternateKey)

        try {
            keyStoreManager.decrypt(encrypted)
            fail("Decryption with wrong key must throw AEADBadTagException")
        } catch (e: Exception) {
            assertTrue(
                "Expected AEADBadTagException, got ${e.javaClass.name}",
                e is AEADBadTagException || e.cause is AEADBadTagException
            )
        }
    }
}
