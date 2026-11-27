package org.snow.ui

import android.content.Context
import android.content.ContextWrapper
import android.content.SharedPreferences
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.snow.capabilities.AndroidCapabilityDispatcher
import org.snow.mcp.AndroidOAuthManager
import org.snow.network.AndroidPeerHostManager
import org.snow.security.DeviceKeyIdentity
import org.snow.security.DeviceKeyManager
import org.snow.security.DeviceRecoveryTrustResetException
import org.snow.security.EncryptedCertPinStorage
import org.snow.security.InMemoryAesKeyProvider
import org.snow.security.InMemoryPeerHostCertStorage
import org.snow.security.InMemoryTokenStorage
import org.snow.security.KeyStoreManager
import java.io.File
import java.net.ServerSocket
import java.nio.file.Files

/**
 * M4.5 regression suite:
 * - Item 2.2: DeviceKeyManager recovery clears EncryptedCertPinStorage (`snow_security`) and
 *   propagates wipe failure explicitly without silently succeeding.
 * - Item 4: User-facing Android strings replace "SAF" with "Transfer Folder" while keeping protocol
 *   status codes (`SAF_FOLDER_NOT_CONFIGURED`, `SAF_PERMISSION_REVOKED`) untouched.
 * - Items 5.1 / 5.2 / 6: Zero-PIN live QR v2 host payload, canonical SNOW ID without UUID fallback,
 *   removal of CrossNetworkSharingCard, Cursor card, and duplicate Remote AI Link rows.
 */
class M45ParityAndRecoveryPinTest {

    private class MemPrefs : SharedPreferences {
        val map = mutableMapOf<String, Any?>()
        var failCommits = false
        override fun getAll(): MutableMap<String, *> = HashMap(map)
        override fun getString(key: String?, defValue: String?): String? = map[key] as? String ?: defValue
        override fun getStringSet(key: String?, defValues: MutableSet<String>?): MutableSet<String>? {
            @Suppress("UNCHECKED_CAST")
            return (map[key] as? Set<String>)?.toMutableSet() ?: defValues
        }
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
            override fun putStringSet(key: String?, values: MutableSet<String>?) = apply {
                if (key != null) pending[key] = values?.toSet()
            }
            override fun putInt(key: String?, value: Int) = apply { if (key != null) pending[key] = value }
            override fun putLong(key: String?, value: Long) = apply { if (key != null) pending[key] = value }
            override fun putFloat(key: String?, value: Float) = apply { if (key != null) pending[key] = value }
            override fun putBoolean(key: String?, value: Boolean) = apply { if (key != null) pending[key] = value }
            override fun remove(key: String?) = apply { if (key != null) removals.add(key) }
            override fun clear() = apply { clearAll = true }
            override fun commit(): Boolean {
                if (failCommits) return false
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
        val dir = Files.createTempDirectory("m45_test_").toFile()
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

    private fun resolveModuleFile(relPath: String): File {
        val direct = File(relPath)
        if (direct.exists()) return direct
        val nested = File("android/app/$relPath")
        if (nested.exists()) return nested
        val appRel = File("app/$relPath")
        if (appRel.exists()) return appRel
        return direct
    }

    @Test
    fun recoveryClearsEncryptedCertPinStorageAndThrowsOnCommitFailure() {
        val (ctx, prefsMap) = newStubContext()
        try {
            val ksMgr = KeyStoreManager(InMemoryAesKeyProvider())
            val pinStorage = EncryptedCertPinStorage(ctx, keyStoreManager = ksMgr)
            pinStorage.pinFingerprint("11".repeat(32))
            pinStorage.pinFingerprintForDevice("https://192.168.1.55:8765", "AA".repeat(32))
            assertFalse(pinStorage.listPinnedDeviceIds().isEmpty())
            assertNotNull(pinStorage.getPinnedFingerprint())

            prefsMap.getOrPut(AndroidOAuthManager.PREFS_NAME) { MemPrefs() }
                .edit().putString("access_tok_1", "secret").commit()

            val mgr = DeviceKeyManager(
                ctx,
                keyStoreManager = ksMgr,
                certPinStorageFactory = { EncryptedCertPinStorage(it, keyStoreManager = ksMgr) }
            )
            val original = mgr.getOrCreate()
            val recoveryKey = DeviceKeyManager.exportRecoveryKey(original)

            val restored = mgr.restoreFromRecoveryKey(recoveryKey)
            assertEquals(original.snowId, restored.snowId)
            val afterPinStorage = EncryptedCertPinStorage(ctx, keyStoreManager = ksMgr)
            assertTrue(
                "EncryptedCertPinStorage (`snow_security`) per-device pins must be empty after recovery",
                afterPinStorage.listPinnedDeviceIds().isEmpty()
            )
            assertNull(afterPinStorage.getPinnedFingerprint())
            assertTrue(prefsMap[AndroidOAuthManager.PREFS_NAME]!!.getAll().isEmpty())

            // Simulate commit failure in `snow_security` during EncryptedCertPinStorage.clearAllPinnedFingerprints():
            // exception must surface via DeviceRecoveryTrustResetException AND restored key stays intact.
            prefsMap["snow_security"]!!.failCommits = true
            var thrown: Throwable? = null
            try {
                mgr.restoreFromRecoveryKey(recoveryKey)
            } catch (e: DeviceRecoveryTrustResetException) {
                thrown = e
            }
            assertNotNull("Expected DeviceRecoveryTrustResetException on wipe commit failure", thrown)
            prefsMap["snow_security"]!!.failCommits = false
            assertEquals(original.snowId, mgr.getOrCreate().snowId)
        } finally {
            ctx.filesDir.deleteRecursively()
        }
    }

    @Test
    fun peerHostZeroPinQrOmitsPinWhileRetainingV2AndHandshakeToken() {
        val (ctx, _) = newStubContext()
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        val hostMgr = AndroidPeerHostManager(InMemoryPeerHostCertStorage())
        val dispatcher = AndroidCapabilityDispatcher(ctx, transferClientProvider = { null })
        val freePort = ServerSocket(0).use { it.localPort }
        try {
            hostMgr.setHostModeSettingEnabled(true)
            val started = hostMgr.enableHostMode(
                port = freePort,
                tokenStorage = InMemoryTokenStorage(),
                dispatcher = dispatcher,
                localDeviceId = "android-m45-node",
                manifestProvider = { emptyMap() },
                parentScope = scope,
                snowId = "SNW-CAFE-BABE",
                networkId = "SNW-NET-12345678",
            )
            assertTrue("AndroidPeerHostManager should bind on ephemeral port", started)
            val candidates = hostMgr.enumerateLocalIpv4Candidates()
            if (candidates.isNotEmpty()) {
                val jsonNoPin = hostMgr.generatePairingQrJson(
                    localDeviceId = "android-m45-node",
                    snowId = "SNW-CAFE-BABE",
                    networkId = "SNW-NET-12345678",
                    version = 2,
                    includePin = false,
                )
                assertNotNull(jsonNoPin)
                assertTrue(jsonNoPin!!.contains("\"v\":2"))
                assertTrue(jsonNoPin.contains("SNW-CAFE-BABE"))
                assertTrue(jsonNoPin.contains("\"handshake_token\""))
                assertFalse("Zero-PIN live QR must omit 'pin'", jsonNoPin.contains("\"pin\""))

                val jsonWithPin = hostMgr.generatePairingQrJson(
                    localDeviceId = "android-m45-node",
                    snowId = "SNW-CAFE-BABE",
                    networkId = "SNW-NET-12345678",
                    version = 2,
                    includePin = true,
                )
                assertNotNull(jsonWithPin)
                assertTrue(jsonWithPin!!.contains("\"pin\""))
            }
        } finally {
            hostMgr.disableHostMode()
            scope.cancel()
            ctx.filesDir.deleteRecursively()
        }
    }

    @Test
    fun androidUiParityTransferFolderNoSafAndStreamlinedPairingAndSettings() {
        val mainAct = resolveModuleFile("src/main/java/org/snow/ui/MainActivity.kt").readText()
        val safMgr = resolveModuleFile("src/main/java/org/snow/ui/files/SafFolderManager.kt").readText()
        val toolsSrc = resolveModuleFile("src/main/java/org/snow/ui/tools/ToolsScreen.kt").readText()
        val settingsSrc = resolveModuleFile("src/main/java/org/snow/ui/settings/SettingsScreen.kt").readText()
        val devicesSrc = resolveModuleFile("src/main/java/org/snow/ui/devices/DevicesScreen.kt").readText()
        val connectSrc = resolveModuleFile("src/main/java/org/snow/ui/connect/SnowConnectSheet.kt").readText()
        val repoSrc = resolveModuleFile("src/main/java/org/snow/ui/SnowUiRepository.kt").readText()
        val handlerSrc = resolveModuleFile("src/main/java/org/snow/capabilities/AndroidFileHandler.kt").readText()

        assertTrue(mainAct.contains("Transfer Folder"))
        assertTrue(safMgr.contains("Transfer Folder"))
        assertTrue(toolsSrc.contains("Save Files To"))
        assertTrue(settingsSrc.contains("Transfer Folder"))
        assertFalse(settingsSrc.contains("SAF Folder"))
        assertFalse(toolsSrc.contains("No SAF folder"))
        assertFalse(safMgr.contains("No SAF folder selected"))
        // Wire protocol SAF status codes must remain preserved intact
        assertTrue(handlerSrc.contains("SAF_FOLDER_NOT_CONFIGURED"))
        assertTrue(handlerSrc.contains("SAF_PERMISSION_REVOKED"))

        // Connect & Pair sheet shows live QR immediately without hidden toggle + distinct IDs + PIN button
        assertFalse(connectSrc.contains("var showMyQr"))
        assertTrue(connectSrc.contains("MY SNOW ID"))
        assertTrue(connectSrc.contains("MY NETWORK ID"))
        assertTrue(connectSrc.contains("Generate 6-Digit PIN"))
        assertFalse(connectSrc.contains("Fingerprint:"))

        // DevicesScreen drops federation UI cleanly while retaining Merge/Separate conflict banner
        assertFalse(devicesSrc.contains("CrossNetworkSharingCard("))
        assertTrue(devicesSrc.contains("Merge Networks"))
        assertTrue(devicesSrc.contains("Keep Separate"))

        // SettingsScreen surfaces top-level Remote AI Link & Authorized AI Clients + collapsed Advanced Settings
        assertTrue(settingsSrc.contains("Remote AI Link"))
        assertTrue(settingsSrc.contains("Authorized AI Clients"))
        assertTrue(settingsSrc.contains("Advanced Settings"))
        assertFalse(settingsSrc.contains("\"Cursor\""))

        // Repository canonicalSnowId derives dynamically from Ed25519 deviceKeyManager
        assertTrue(repoSrc.contains("val dk = deviceKeyManager.getOrCreate()"))
        assertTrue(repoSrc.contains("_permanentDeviceSnowId.value = dk.snowId"))
        assertFalse(repoSrc.contains("DeviceIdentity.formatSnowId(deviceIdentity.deviceId)"))
    }
}
