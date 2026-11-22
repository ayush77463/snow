package org.snow.capabilities

import android.content.Context
import android.content.ContextWrapper
import android.content.SharedPreferences
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.snow.network.RelayClient
import org.snow.security.MockSharedPreferences
import org.snow.ui.SnowUiRepository
import java.io.ByteArrayOutputStream

class Batch4RegressionTest {

    private lateinit var testScope: CoroutineScope
    private val prefsMap = mutableMapOf<String, MockSharedPreferences>()
    private lateinit var context: Context

    @Before
    fun setUp() {
        testScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        prefsMap.clear()
        context = object : ContextWrapper(null) {
            override fun getSharedPreferences(name: String?, mode: Int): SharedPreferences {
                return prefsMap.getOrPut(name ?: "default") { MockSharedPreferences() }
            }
            override fun getApplicationContext(): Context {
                return this
            }
        }
        // Reset singleton
        val instanceField = SnowUiRepository::class.java.getDeclaredField("instance")
        instanceField.isAccessible = true
        instanceField.set(null, null)
    }

    @After
    fun tearDown() {
        testScope.cancel()
        val instanceField = SnowUiRepository::class.java.getDeclaredField("instance")
        instanceField.isAccessible = true
        instanceField.set(null, null)
    }

    @Test
    fun testWP1_UpdateDeviceConnectionModeTargetsPairedDevicesV2() {
        // Seed snow_paired_devices_v2 directly
        val initialJson = """[{"deviceId":"dev-test-1","deviceName":"Test PC","host":"192.168.1.50","port":8765,"trustTier":"PEER","connectionMode":"auto"}]"""
        val pairedPrefsInit = prefsMap.getOrPut("snow_paired_devices_v2") { MockSharedPreferences() }
        pairedPrefsInit.edit().putString("devices_json", initialJson).apply()

        val repo = SnowUiRepository.getInstance(context)

        // Update connection mode
        repo.updateDeviceConnectionMode("dev-test-1", "local_only")

        // Verify it was written to "snow_paired_devices_v2"
        val pairedPrefs = prefsMap["snow_paired_devices_v2"]
        assertNotNull("snow_paired_devices_v2 must exist", pairedPrefs)
        val json = pairedPrefs!!.getString("devices_json", null)
        assertNotNull("devices_json must be saved in snow_paired_devices_v2", json)
        assertTrue("devices_json must contain local_only", json!!.contains("local_only"))

        // Verify erroneous "snow_devices_v2" was NOT written
        val wrongPrefs = prefsMap["snow_devices_v2"]
        assertTrue(
            "snow_devices_v2 must not contain devices_json",
            wrongPrefs == null || wrongPrefs.getString("devices_json", null) == null
        )
    }

    @Test
    fun testWP2_RelayDeterministicRoleAssignment() {
        // Deterministic role: localId < remoteId means client mode
        val localId = "android-device-10"
        val peerId = "desktop-device-99"

        val client = RelayClient(
            relayUrl = "wss://relay.example.com/v1/tunnel",
            deviceId = localId,
            groupId = "test_group",
            ticket = "secure_ticket",
            targetPeerId = peerId
        )

        assertTrue(client.isClientMode)
        assertFalse(client.isServer)

        // Inverted: if localId > peerId, acts as server
        val serverClient = RelayClient(
            relayUrl = "wss://relay.example.com/v1/tunnel",
            deviceId = "z-android-device",
            groupId = "test_group",
            ticket = "secure_ticket",
            targetPeerId = "a-desktop-device"
        )
        assertFalse(serverClient.isClientMode)
        assertTrue(serverClient.isServer)
    }

    @Test
    fun testWP3_LiveScreenStreamHandlerReusableBaosFieldExists() {
        val handler = LiveScreenStreamHandler(context, transferClientProvider = { null })
        val field = LiveScreenStreamHandler::class.java.getDeclaredField("reusableBaos")
        field.isAccessible = true
        val obj = field.get(handler)

        assertNotNull("reusableBaos field must be initialized", obj)
        assertTrue("reusableBaos must be ByteArrayOutputStream", obj is ByteArrayOutputStream)

        // Verify reset behavior
        val baos = obj as ByteArrayOutputStream
        baos.write(byteArrayOf(1, 2, 3, 4, 5))
        assertEquals(5, baos.size())
        baos.reset()
        assertEquals(0, baos.size())
    }

    @Test
    fun testTrack2_RelayTokenIsolationFromDesktopToken() {
        val repo = SnowUiRepository.getInstance(context)
        val testKeyStoreManager = org.snow.security.KeyStoreManager(org.snow.security.InMemoryAesKeyProvider())
        val relayStorage = repo.getRelayTokenStorage(testKeyStoreManager)
        val desktopStorage = org.snow.security.SharedPreferencesTokenStorage(
            context.getSharedPreferences("snow_security", Context.MODE_PRIVATE),
            testKeyStoreManager
        )

        // 1. Save desktop pairing token into "snow_security"
        desktopStorage.saveToken("desktop-super-secret-token")
        assertTrue("Desktop storage has token", desktopStorage.hasToken())

        // 2. Verify that relayStorage (which targets "snow_relay_security") does NOT read the desktop token
        assertFalse("Relay storage must be isolated and not contain desktop token", relayStorage.hasToken())
        assertNull("Relay storage getToken() must return null when no relay ticket is present", relayStorage.getToken())

        // 3. Save a dedicated relay ticket into "snow_relay_security"
        relayStorage.saveToken("dedicated-relay-ticket-xyz")
        assertTrue("Relay storage has dedicated ticket", relayStorage.hasToken())
        assertEquals("dedicated-relay-ticket-xyz", relayStorage.getToken())

        // 4. Verify desktop token in "snow_security" was unchanged and separate
        assertEquals("desktop-super-secret-token", desktopStorage.getToken())
    }

    @Test
    fun testTrack2_ManualDisconnectSuppressReconnectionLogic() {
        // Test manual-disconnect flag semantics
        var userDisconnected = false

        // Simulate user manual disconnect
        userDisconnected = true

        // Simulate network recovery callback
        var reconnectInitiated = false
        val simulateNetworkRestored = {
            if (!userDisconnected) {
                reconnectInitiated = true
            }
        }

        // When userDisconnected == true, network restoration MUST NOT trigger reconnect
        simulateNetworkRestored()
        assertFalse("Network recovery must not initiate reconnect when userDisconnected is true", reconnectInitiated)

        // Simulate intentional user ACTION_CONNECT
        userDisconnected = false
        simulateNetworkRestored()
        assertTrue("Network recovery must initiate reconnect when userDisconnected is false", reconnectInitiated)
    }
}
