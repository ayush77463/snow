package org.snow.security

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.util.UUID

class DeviceIdentityTest {

    private class InMemoryIdentityStorage : IdentityStorage {
        val map = mutableMapOf<String, String>()
        override fun getString(key: String): String? = map[key]
        override fun putString(key: String, value: String) {
            map[key] = value
        }
    }

    private lateinit var storage: InMemoryIdentityStorage

    @Before
    fun setUp() {
        storage = InMemoryIdentityStorage()
    }

    @Test
    fun testFirstRunIdentityGeneration() {
        val identity = DeviceIdentity.getOrCreate(storage, "Test Phone Pixel 8")

        assertTrue("Generated device ID must be a valid UUIDv4", DeviceIdentity.isValidUuidV4(identity.deviceId))
        assertEquals("Test Phone Pixel 8", identity.deviceName)
        assertTrue("Created timestamp must not be blank", identity.createdAt.isNotBlank())

        // Verify saved to storage
        assertEquals(identity.deviceId, storage.getString(DeviceIdentity.KEY_DEVICE_ID))
        assertEquals(identity.deviceName, storage.getString(DeviceIdentity.KEY_DEVICE_NAME))
    }

    @Test
    fun testIdentityPersistenceAcrossSimulatedRestart() {
        val firstLoad = DeviceIdentity.getOrCreate(storage, "Realme RMX5110")
        val secondLoad = DeviceIdentity.getOrCreate(storage, "Different Name Ignored On Reload")

        assertEquals("Device ID must remain stable across loads", firstLoad.deviceId, secondLoad.deviceId)
        assertEquals("Device name must remain stable across loads", firstLoad.deviceName, secondLoad.deviceName)
        assertEquals("Timestamp must remain stable across loads", firstLoad.createdAt, secondLoad.createdAt)
    }

    @Test
    fun testCorruptedOrInvalidIdentityReplaced() {
        storage.putString(DeviceIdentity.KEY_DEVICE_ID, "not-a-valid-uuid")
        storage.putString(DeviceIdentity.KEY_DEVICE_NAME, "Corrupt Device")
        storage.putString(DeviceIdentity.KEY_CREATED_AT, "2026-01-01T00:00:00Z")

        val recovered = DeviceIdentity.getOrCreate(storage, "Recovered Phone")
        assertTrue("Must replace invalid UUID with valid UUIDv4", DeviceIdentity.isValidUuidV4(recovered.deviceId))
        assertNotEquals("not-a-valid-uuid", recovered.deviceId)
    }

    @Test
    fun testUuidV4Validation() {
        val validV4 = UUID.randomUUID().toString()
        assertTrue(DeviceIdentity.isValidUuidV4(validV4))

        assertFalse(DeviceIdentity.isValidUuidV4("12345"))
        assertFalse(DeviceIdentity.isValidUuidV4(""))
        assertFalse(DeviceIdentity.isValidUuidV4(null))
        assertFalse(DeviceIdentity.isValidUuidV4("00000000-0000-0000-0000-000000000000")) // UUIDv0
    }

    @Test
    fun testDeterministicIdentityFromAndroidId() {
        val storage1 = InMemoryIdentityStorage()
        val storage2 = InMemoryIdentityStorage()
        val testAndroidId = "9a1b2c3d4e5f6071"

        val id1 = DeviceIdentity.getOrCreate(storage1, "Realme RMX5110", testAndroidId)
        val id2 = DeviceIdentity.getOrCreate(storage2, "Realme RMX5110", testAndroidId)

        assertTrue("Deterministic ID must be valid UUIDv4", DeviceIdentity.isValidUuidV4(id1.deviceId))
        assertEquals("Identical Android ID must yield identical Device ID across fresh storages", id1.deviceId, id2.deviceId)
        assertEquals(4, UUID.fromString(id1.deviceId).version())
    }

    @Test
    fun testDifferentAndroidIdsProduceDifferentUuids() {
        val s1 = InMemoryIdentityStorage()
        val s2 = InMemoryIdentityStorage()

        val id1 = DeviceIdentity.getOrCreate(s1, "Phone 1", "android-id-alpha")
        val id2 = DeviceIdentity.getOrCreate(s2, "Phone 2", "android-id-beta")

        assertNotEquals("Different Android IDs must yield different UUIDs", id1.deviceId, id2.deviceId)
    }

    @Test
    fun testStoredIdentityPreservedOverAndroidId() {
        val existingUuid = UUID.randomUUID().toString()
        storage.putString(DeviceIdentity.KEY_DEVICE_ID, existingUuid)
        storage.putString(DeviceIdentity.KEY_DEVICE_NAME, "Original Name")
        storage.putString(DeviceIdentity.KEY_CREATED_AT, "2026-02-01T12:00:00Z")

        val loaded = DeviceIdentity.getOrCreate(storage, "New Name", "android-id-new")

        assertEquals("Valid stored device ID must never be overwritten", existingUuid, loaded.deviceId)
        assertEquals("Original Name", loaded.deviceName)
    }
}
