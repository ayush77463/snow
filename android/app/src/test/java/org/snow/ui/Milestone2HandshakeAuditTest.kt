package org.snow.ui

import android.content.Context
import android.content.ContextWrapper
import android.content.SharedPreferences
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.snow.network.AuthState
import org.snow.network.ConnectionState
import org.snow.network.SnowWebSocketClient
import org.snow.protocol.MessageType
import org.snow.protocol.SnowMessage
import org.snow.security.InMemoryTokenStorage
import org.snow.security.PairingFlow
import org.snow.security.PairingState

/**
 * Milestone 2 — Stage 1: Unit 1.5 Permission Profile Handshake Audit on Android.
 *
 * Proves that desktop authoritative `permission_profile` is parsed by PairingFlow &
 * SnowWebSocketClient, persisted into SavedDevice via recordSuccessfulConnection(),
 * kept separate from trustTier, fails closed on missing/unknown/OWNER/PEER strings,
 * does not auto-upgrade legacy/unconfigured devices, and drives getEligibleScreenTargets().
 */
@OptIn(ExperimentalCoroutinesApi::class)
class Milestone2HandshakeAuditTest {

    private class MemoryPrefs : SharedPreferences {
        private val map = mutableMapOf<String, Any?>()
        override fun getAll(): MutableMap<String, *> = map
        override fun getString(key: String?, defValue: String?): String? = map[key] as? String ?: defValue
        override fun getStringSet(key: String?, defValues: MutableSet<String>?): MutableSet<String>? = defValues
        override fun getInt(key: String?, defValue: Int): Int = (map[key] as? Int) ?: defValue
        override fun getLong(key: String?, defValue: Long): Long = (map[key] as? Long) ?: defValue
        override fun getFloat(key: String?, defValue: Float): Float = (map[key] as? Float) ?: defValue
        override fun getBoolean(key: String?, defValue: Boolean): Boolean = (map[key] as? Boolean) ?: defValue
        override fun contains(key: String?): Boolean = map.containsKey(key)
        override fun edit(): SharedPreferences.Editor = object : SharedPreferences.Editor {
            override fun putString(key: String?, value: String?) = apply { if (key != null) map[key] = value }
            override fun putStringSet(key: String?, values: MutableSet<String>?) = apply { if (key != null) map[key] = values }
            override fun putInt(key: String?, value: Int) = apply { if (key != null) map[key] = value }
            override fun putLong(key: String?, value: Long) = apply { if (key != null) map[key] = value }
            override fun putFloat(key: String?, value: Float) = apply { if (key != null) map[key] = value }
            override fun putBoolean(key: String?, value: Boolean) = apply { if (key != null) map[key] = value }
            override fun remove(key: String?) = apply { map.remove(key) }
            override fun clear() = apply { map.clear() }
            override fun commit(): Boolean = true
            override fun apply() {}
        }
        override fun registerOnSharedPreferenceChangeListener(listener: SharedPreferences.OnSharedPreferenceChangeListener?) {}
        override fun unregisterOnSharedPreferenceChangeListener(listener: SharedPreferences.OnSharedPreferenceChangeListener?) {}
    }

    private val prefsByName = mutableMapOf<String, MemoryPrefs>()
    private lateinit var context: Context

    private fun resetRepoSingleton() {
        val f = SnowUiRepository::class.java.getDeclaredField("instance")
        f.isAccessible = true
        f.set(null, null)
    }

    @Before
    fun setUp() {
        prefsByName.clear()
        context = object : ContextWrapper(null) {
            override fun getApplicationContext(): Context = this
            override fun getSharedPreferences(name: String?, mode: Int): SharedPreferences {
                return prefsByName.getOrPut(name ?: "default") { MemoryPrefs() }
            }
        }
        resetRepoSingleton()
    }

    @After
    fun tearDown() {
        resetRepoSingleton()
    }

    @Test
    fun testPairingAndAuthHandshakeExtractAuthoritativePermissionProfile() {
        val identity = org.snow.security.DeviceIdentity.getOrCreate(context)
        val flow = PairingFlow(identity, InMemoryTokenStorage())
        val pairMsg = SnowMessage.createResponse(
            correlationId = "p-1",
            payload = mapOf(
                "status" to "success",
                "action" to "pair_request",
                "data" to mapOf(
                    "device_id" to "pc-uuid-1111",
                    "device_name" to "Lenovo V15",
                    "session_id" to "sess-1",
                    "auth_token" to "tok-1234",
                    "trust_tier" to "owner",
                    "permission_profile" to "full_control",
                    "manifest" to mapOf("platform" to "windows")
                )
            )
        )
        val paired = flow.handlePairingResponse(pairMsg) as PairingState.Paired
        assertEquals("owner", paired.trustTier)
        assertEquals("full_control", paired.permissionProfile)

        val authParsed = SnowWebSocketClient.parseAuthenticatedState(
            mapOf(
                "session_id" to "sess-2",
                "trust_tier" to "peer",
                "permission_profile" to "files_and_clipboard",
                "device_name" to "Office PC",
                "server_device_id" to "pc-uuid-2222",
                "snow_id" to "SNW-2222-3333",
                "device_type" to "windows"
            )
        )
        assertEquals("peer", authParsed.trustTier)
        assertEquals("files_and_clipboard", authParsed.permissionProfile)
    }

    @Test
    fun testRecordSuccessfulConnectionPersistsProfileFailClosedAndScreenTargets() {
        val repo = SnowUiRepository.getInstance(context)

        // 1. Newly paired device receiving explicit full_control from desktop persists it cleanly
        repo.recordSuccessfulConnection(
            host = "192.168.1.50",
            port = 8765,
            sessionId = "sess-1",
            tier = "owner",
            peerDeviceName = "Lenovo V15",
            peerDeviceType = "windows",
            peerDeviceId = "pc-1111",
            peerSnowId = "SNW-1111-2222",
            peerPermissionProfile = "full_control"
        )
        val dev1 = repo.savedDevices.value.first { it.snowId == "SNW-1111-2222" }
        assertEquals("owner", dev1.trustTier)
        assertEquals("full_control", dev1.permissionProfile)

        // 2. Newly paired device with missing or OWNER/PEER/corrupt profile remains fail-closed as not_allowed
        repo.recordSuccessfulConnection(
            host = "192.168.1.60",
            port = 8765,
            sessionId = "sess-2",
            tier = "owner",
            peerDeviceName = "Missing Profile PC",
            peerDeviceType = "windows",
            peerDeviceId = "pc-2222",
            peerSnowId = "SNW-2222-3333",
            peerPermissionProfile = null
        )
        repo.recordSuccessfulConnection(
            host = "192.168.1.61",
            port = 8765,
            sessionId = "sess-3",
            tier = "owner",
            peerDeviceName = "Trust As Profile PC",
            peerDeviceType = "windows",
            peerDeviceId = "pc-3333",
            peerSnowId = "SNW-3333-4444",
            peerPermissionProfile = "OWNER"
        )
        val dev2 = repo.savedDevices.value.first { it.snowId == "SNW-2222-3333" }
        val dev3 = repo.savedDevices.value.first { it.snowId == "SNW-3333-4444" }
        assertEquals("owner", dev2.trustTier)
        assertEquals("not_allowed", dev2.permissionProfile)
        assertEquals("owner", dev3.trustTier)
        assertEquals("not_allowed", dev3.permissionProfile)

        // 3. Reconnecting existing device with missing or invalid profile must NOT auto-upgrade not_allowed
        repo.recordSuccessfulConnection(
            host = "192.168.1.60",
            port = 8765,
            sessionId = "sess-2b",
            tier = "owner",
            peerDeviceName = "Missing Profile PC",
            peerDeviceType = "windows",
            peerDeviceId = "pc-2222",
            peerSnowId = "SNW-2222-3333",
            peerPermissionProfile = "superuser_override"
        )
        val dev2After = repo.savedDevices.value.first { it.snowId == "SNW-2222-3333" }
        assertEquals("not_allowed", dev2After.permissionProfile)

        // 4. getEligibleScreenTargets includes ONLY persisted full_control saved devices when connected
        val connField = SnowUiRepository::class.java.getDeclaredField("_connectionState")
        connField.isAccessible = true
        @Suppress("UNCHECKED_CAST")
        (connField.get(repo) as kotlinx.coroutines.flow.MutableStateFlow<ConnectionState>).value = ConnectionState.CONNECTED

        val authField = SnowUiRepository::class.java.getDeclaredField("_authState")
        authField.isAccessible = true
        @Suppress("UNCHECKED_CAST")
        (authField.get(repo) as kotlinx.coroutines.flow.MutableStateFlow<AuthState>).value = AuthState.Authenticated(
            sessionId = "sess-other",
            trustTier = "owner",
            peerDeviceId = "active-other",
            permissionProfile = "files_only"
        )
        repo.setAccessProfile("files_only")

        val targets = repo.getEligibleScreenTargets()
        assertTrue(targets.any { it.deviceId == "pc-1111" || it.deviceId == "SNW-1111-2222" })
        assertFalse(targets.any { it.deviceId == "SNW-2222-3333" || it.deviceId == "pc-2222" })
        assertFalse(targets.any { it.deviceId == "SNW-3333-4444" || it.deviceId == "pc-3333" })
    }
}
