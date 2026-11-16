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

        fun isValidUuidV4(id: String?): Boolean {
            if (id.isNullOrBlank()) return false
            return try {
                val parsed = UUID.fromString(id.trim())
                parsed.version() == 4
            } catch (e: Exception) {
                false
            }
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
         */
        @Synchronized
        fun getOrCreate(storage: IdentityStorage, customDeviceName: String? = null): DeviceIdentity {
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

            // Generate fresh UUIDv4 identity
            val newId = UUID.randomUUID().toString()
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
         * Convenience factory using Android SharedPreferences.
         */
        @Synchronized
        fun getOrCreate(context: Context, customDeviceName: String? = null): DeviceIdentity {
            return getOrCreate(SharedPreferencesIdentityStorage(context), customDeviceName)
        }
    }
}
