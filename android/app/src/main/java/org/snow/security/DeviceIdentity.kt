package org.snow.security

import android.content.Context
import android.os.Build
import org.snow.protocol.SnowMessage
import java.util.UUID

/**
 * Storage abstraction for device identity persistence, enabling pure unit testing.
 */
interface IdentityStorage {
    fun getString(key: String): String?
    fun putString(key: String, value: String)
}

class SharedPreferencesIdentityStorage(private val context: Context) : IdentityStorage {
    private val prefs = context.getSharedPreferences(DeviceIdentity.PREFS_NAME, Context.MODE_PRIVATE)

    override fun getString(key: String): String? = prefs.getString(key, null)

    override fun putString(key: String, value: String) {
        prefs.edit().putString(key, value).apply()
    }
}

/**
 * Immutable representation of the persistent Android device identity.
 */
data class DeviceIdentity(
    val deviceId: String,
    val deviceName: String,
    val createdAt: String
) {
    init {
        require(isValidUuidV4(deviceId)) {
            "Invalid deviceId: must be a valid RFC 4122 UUIDv4 string, got '$deviceId'"
        }
        require(deviceName.isNotBlank()) { "deviceName must not be blank" }
        require(createdAt.isNotBlank()) { "createdAt must not be blank" }
    }

    companion object {
        const val PREFS_NAME = "snow_identity_prefs"
        const val KEY_DEVICE_ID = "device_id"
        const val KEY_DEVICE_NAME = "device_name"
        const val KEY_CREATED_AT = "created_at"
        const val SNOW_IDENTITY_SALT = "org.snow.identity.salt.v3.e67f0b5a-7b3c-4b3d-9d48-3d84f88e3649"

        fun isValidUuidV4(id: String?): Boolean {
            if (id.isNullOrBlank()) return false
            return try {
                val parsed = UUID.fromString(id.trim())
                parsed.version() == 4
            } catch (e: Exception) {
                false
            }
        }

        /**
         * Derive a deterministic, app-scoped RFC 4122 v4 UUID from Android ID.
         */
        fun deriveDeterministicUuidV4(androidId: String): String {
            val md = java.security.MessageDigest.getInstance("SHA-256")
            val digest = md.digest("$SNOW_IDENTITY_SALT:$androidId".toByteArray(Charsets.UTF_8))
            val bytes = digest.copyOf(16)
            bytes[6] = ((bytes[6].toInt() and 0x0f) or 0x40).toByte() // version 4
            bytes[8] = ((bytes[8].toInt() and 0x3f) or 0x80).toByte() // variant 1 (RFC 4122)
            val bb = java.nio.ByteBuffer.wrap(bytes)
            return UUID(bb.long, bb.long).toString().lowercase()
        }

        private fun resolveDefaultDeviceName(customDeviceName: String?): String {
            if (!customDeviceName.isNullOrBlank()) return customDeviceName
            return try {
                val model = Build.MODEL ?: ""
                val manufacturer = Build.MANUFACTURER ?: ""
                val combined = "$manufacturer $model".trim()
                if (combined.isNotBlank()) combined else "Android Device"
            } catch (t: Throwable) {
                "Android Device"
            }
        }

        /**
         * Load or generate identity using an IdentityStorage implementation.
         * If a valid deviceId is already persisted, it is preserved without modification.
         */
        @Synchronized
        fun getOrCreate(
            storage: IdentityStorage,
            customDeviceName: String? = null,
            androidId: String? = null
        ): DeviceIdentity {
            val storedId = storage.getString(KEY_DEVICE_ID)
            val storedName = storage.getString(KEY_DEVICE_NAME)
            val storedCreated = storage.getString(KEY_CREATED_AT)

            if (isValidUuidV4(storedId) && !storedName.isNullOrBlank() && !storedCreated.isNullOrBlank()) {
                return DeviceIdentity(
                    deviceId = storedId!!,
                    deviceName = storedName,
                    createdAt = storedCreated
                )
            }

            // Derive deterministic UUIDv4 from Android ID if available, else random UUIDv4
            val newId = if (!androidId.isNullOrBlank()) {
                deriveDeterministicUuidV4(androidId)
            } else {
                UUID.randomUUID().toString()
            }
            val name = resolveDefaultDeviceName(customDeviceName)
            val createdAt = SnowMessage.currentIsoTimestamp()

            storage.putString(KEY_DEVICE_ID, newId)
            storage.putString(KEY_DEVICE_NAME, name)
            storage.putString(KEY_CREATED_AT, createdAt)

            return DeviceIdentity(
                deviceId = newId,
                deviceName = name,
                createdAt = createdAt
            )
        }

        /**
         * Convenience factory using Android SharedPreferences and Settings.Secure.ANDROID_ID.
         */
        @Synchronized
        fun getOrCreate(context: Context, customDeviceName: String? = null): DeviceIdentity {
            val androidId = try {
                android.provider.Settings.Secure.getString(
                    context.contentResolver,
                    android.provider.Settings.Secure.ANDROID_ID
                )
            } catch (_: Throwable) {
                null
            }
            return getOrCreate(SharedPreferencesIdentityStorage(context), customDeviceName, androidId)
        }
    }
}
