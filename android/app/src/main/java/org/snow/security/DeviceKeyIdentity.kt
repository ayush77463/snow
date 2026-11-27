package org.snow.security

import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import java.util.Locale

class DeviceKeyCorruptException(message: String, cause: Throwable? = null) : RuntimeException(message, cause)
class DeviceRecoveryFormatException(message: String, cause: Throwable? = null) : IllegalArgumentException(message, cause)

/**
 * Permanent cryptographic per-device identity backed by a 32-byte Ed25519 seed.
 *
 * Distinct from legacy UUID [DeviceIdentity] and network-level identity keys.
 * Canonical `snowId` is derived exclusively from the raw 32-byte Ed25519 public key:
 * `SNW-` + `SHA256(raw_32_byte_ed25519_public_key).hexdigest()[:8].uppercase()`, formatted `SNW-XXXX-XXXX`.
 *
 * Security Note: An 8-hex-character (32-bit) prefix is concise for human/URL addressing
 * and does NOT provide full 256-bit collision resistance. Render Hub and peers MUST verify
 * public-key ownership on every session and reject conflicting registrations.
 */
class DeviceKeyIdentity private constructor(
    val snowId: String,
    val publicKeyB64: String,
    val createdAt: String,
    private val privateSeedBytes: ByteArray
) {
    init {
        require(SNOW_ID_REGEX.matches(snowId)) { "Invalid snowId format: $snowId" }
        val rawPub = decodeEd25519Pubkey(publicKeyB64)
        val expectedId = deriveSnowIdFromPublicKey(rawPub)
        require(expectedId == snowId) {
            "snowId '$snowId' does not match Ed25519 public key digest '$expectedId'."
        }
        require(privateSeedBytes.size == SEED_BYTES) {
            "Ed25519 private seed must be exactly $SEED_BYTES bytes."
        }
        val derivedPub = derivePublicKeyBytesFromSeed(privateSeedBytes)
        require(derivedPub.contentEquals(rawPub)) {
            "Ed25519 private seed does not correspond to public key."
        }
    }

    internal fun copySeedForProtectedPersistence(): ByteArray = privateSeedBytes.copyOf()

    fun signMessage(message: ByteArray): String {
        val privParams = Ed25519PrivateKeyParameters(privateSeedBytes, 0)
        val signer = Ed25519Signer()
        signer.init(true, privParams)
        signer.update(message, 0, message.size)
        val sigBytes = signer.generateSignature()
        return Base64.getUrlEncoder().withoutPadding().encodeToString(sigBytes)
    }

    fun verifyOwnSignature(message: ByteArray, signatureB64: String): Boolean =
        verifyEd25519Signature(publicKeyB64, message, signatureB64)

    fun signDeviceHubChallenge(
        challengeId: String,
        nonce: String,
        expiresAt: Long,
        deviceId: String,
        networkId: String = "",
        audience: String = "render-hub-tunnel"
    ): String {
        val canonicalMsg = canonicalDeviceHubChallengeMessage(
            challengeId = challengeId,
            nonce = nonce,
            expiresAt = expiresAt,
            snowId = snowId,
            publicKeyB64 = publicKeyB64,
            deviceId = deviceId,
            networkId = networkId,
            audience = audience
        )
        return signMessage(canonicalMsg)
    }

    fun toPublicMap(): Map<String, String> = mapOf(
        "snow_id" to snowId,
        "public_key_b64" to publicKeyB64,
        "created_at" to createdAt,
        "algorithm" to ALGORITHM
    )

    override fun toString(): String =
        "DeviceKeyIdentity(snowId='$snowId', publicKeyB64='$publicKeyB64', createdAt='$createdAt')"

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is DeviceKeyIdentity) return false
        return snowId == other.snowId &&
            publicKeyB64 == other.publicKeyB64 &&
            createdAt == other.createdAt
    }

    override fun hashCode(): Int {
        var result = snowId.hashCode()
        result = 31 * result + publicKeyB64.hashCode()
        result = 31 * result + createdAt.hashCode()
        return result
    }

    companion object {
        const val ALGORITHM = "Ed25519"
        const val SEED_BYTES = 32
        const val PUBKEY_BYTES = 32
        val SNOW_ID_REGEX = Regex("^SNW-[A-Z0-9]{4}-[A-Z0-9]{4}$")
        private val secureRandom = SecureRandom()

        fun generate(createdAt: String = org.snow.protocol.SnowMessage.currentIsoTimestamp()): DeviceKeyIdentity {
            val seed = ByteArray(SEED_BYTES)
            secureRandom.nextBytes(seed)
            return fromSeed(seed, createdAt)
        }

        fun fromSeed(
            seed: ByteArray,
            createdAt: String = org.snow.protocol.SnowMessage.currentIsoTimestamp()
        ): DeviceKeyIdentity {
            require(seed.size == SEED_BYTES) { "Ed25519 private seed must be $SEED_BYTES bytes." }
            val seedCopy = seed.copyOf()
            val rawPub = derivePublicKeyBytesFromSeed(seedCopy)
            val pubB64 = encodeEd25519Pubkey(rawPub)
            val derivedSnowId = deriveSnowIdFromPublicKey(rawPub)
            return DeviceKeyIdentity(
                snowId = derivedSnowId,
                publicKeyB64 = pubB64,
                createdAt = createdAt.ifBlank { org.snow.protocol.SnowMessage.currentIsoTimestamp() },
                privateSeedBytes = seedCopy
            )
        }

        fun derivePublicKeyBytesFromSeed(seed: ByteArray): ByteArray {
            require(seed.size == SEED_BYTES) { "Ed25519 seed must be $SEED_BYTES bytes." }
            val priv = Ed25519PrivateKeyParameters(seed, 0)
            return priv.generatePublicKey().encoded
        }

        fun encodeEd25519Pubkey(rawPub: ByteArray): String {
            require(rawPub.size == PUBKEY_BYTES) { "Ed25519 public key must be $PUBKEY_BYTES bytes." }
            Ed25519PublicKeyParameters(rawPub, 0)
            return Base64.getUrlEncoder().withoutPadding().encodeToString(rawPub)
        }

        fun decodeEd25519Pubkey(pubkeyB64: String): ByteArray {
            val clean = pubkeyB64.trim()
            require(clean.isNotEmpty() && clean.length <= 64) { "Malformed Ed25519 public key string." }
            val pad = "=".repeat((4 - clean.length % 4) % 4)
            val decoded = Base64.getUrlDecoder().decode(clean + pad)
            require(decoded.size == PUBKEY_BYTES) {
                "Ed25519 public key must decode to $PUBKEY_BYTES bytes, got ${decoded.size}."
            }
            return Ed25519PublicKeyParameters(decoded, 0).encoded
        }

        fun deriveSnowIdFromPublicKey(rawPub: ByteArray): String {
            require(rawPub.size == PUBKEY_BYTES) { "Ed25519 public key must be $PUBKEY_BYTES bytes." }
            val digest = MessageDigest.getInstance("SHA-256").digest(rawPub)
            val hex8 = digest.take(4).joinToString("") { "%02X".format(Locale.ROOT, it) }
            return "SNW-${hex8.substring(0, 4)}-${hex8.substring(4, 8)}"
        }

        fun deriveSnowIdFromPublicKeyB64(pubkeyB64: String): String =
            deriveSnowIdFromPublicKey(decodeEd25519Pubkey(pubkeyB64))

        fun canonicalDeviceHubChallengeMessage(
            challengeId: String,
            nonce: String,
            expiresAt: Long,
            snowId: String,
            publicKeyB64: String,
            deviceId: String,
            networkId: String = "",
            audience: String = "render-hub-tunnel"
        ): ByteArray {
            val canonicalPub = encodeEd25519Pubkey(decodeEd25519Pubkey(publicKeyB64))
            val fields = listOf(
                "snow-device-hub-v1",
                challengeId.trim(),
                nonce.trim(),
                expiresAt.toString(),
                snowId.trim().uppercase(Locale.ROOT),
                canonicalPub,
                deviceId.trim(),
                networkId.trim().uppercase(Locale.ROOT),
                audience.trim().ifBlank { "render-hub-tunnel" }
            )
            for (f in fields) {
                require(!f.contains('|') && !f.contains('\n') && !f.contains('\r') && !f.contains('\u0000')) {
                    "Challenge message field contains invalid delimiter or control character."
                }
            }
            return fields.joinToString("|").toByteArray(Charsets.UTF_8)
        }

        fun verifyEd25519Signature(pubkeyB64: String, message: ByteArray, signatureB64: String): Boolean {
            val cleanSig = signatureB64.trim()
            if (cleanSig.isEmpty() || cleanSig.length > 128) return false
            return try {
                val pad = "=".repeat((4 - cleanSig.length % 4) % 4)
                val sigBytes = Base64.getUrlDecoder().decode(cleanSig + pad)
                if (sigBytes.size != 64) return false
                val rawPub = decodeEd25519Pubkey(pubkeyB64)
                val pubParams = Ed25519PublicKeyParameters(rawPub, 0)
                val verifier = Ed25519Signer()
                verifier.init(false, pubParams)
                verifier.update(message, 0, message.size)
                verifier.verifySignature(sigBytes)
            } catch (_: Throwable) {
                false
            }
        }
    }
}
