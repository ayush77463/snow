package org.snow.capabilities

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.setMain
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.snow.protocol.ErrorCode

@OptIn(ExperimentalCoroutinesApi::class)
class CapabilityDispatcherTest {

    private val testDispatcher = UnconfinedTestDispatcher()

    @Before
    fun setUp() {
        Dispatchers.setMain(testDispatcher)
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
    }

    @Test
    fun testRingerConstantsAndDefaults() {
        assertEquals(5, RingerHandler.DEFAULT_DURATION_SECONDS)
        assertEquals(1, RingerHandler.MIN_DURATION_SECONDS)
        assertEquals(15, RingerHandler.MAX_DURATION_SECONDS)
    }

    @Test
    fun testAppLauncherConstants() {
        assertEquals(50, AppLauncherHandler.DEFAULT_APP_LIMIT)
        assertEquals(100, AppLauncherHandler.MAX_APP_LIMIT)
    }

    @Test
    fun testClipboardConstants() {
        assertEquals(65536, ClipboardHandler.MAX_TEXT_BYTES)
    }

    @Test
    fun testUnsupportedActionReturnsStandardError() = runBlocking {
        val dummyContext = object : android.content.ContextWrapper(null) {}
        val dispatcher = AndroidCapabilityDispatcher(dummyContext, transferClientProvider = { null })

        val (res, error) = dispatcher.dispatch(
            action = "invalid_unknown_action",
            data = null,
            serverHost = "127.0.0.1",
            defaultTransferPort = 8766
        )

        assertNull(res)
        assertNotNull(error)
        assertEquals(ErrorCode.UNSUPPORTED_ACTION, error?.code)
        assertTrue(error?.message?.contains("Unsupported action") == true)
    }

    @Test
    fun testClipboardValidationNullOrEmpty() = runBlocking {
        val dummyContext = object : android.content.ContextWrapper(null) {}
        val handler = ClipboardHandler(dummyContext)

        // Null text
        val resNull = handler.pushClipboard(null)
        assertEquals("error", resNull["status"])
        assertEquals("Clipboard text cannot be null.", resNull["error"])

        // Excessive text > 64 KiB
        val hugeText = "A".repeat(65537)
        val resHuge = handler.pushClipboard(hugeText)
        assertEquals("error", resHuge["status"])
        assertTrue((resHuge["error"] as String).contains("exceeds maximum limit"))
    }

    private fun contextWithInstantSync(enabled: Boolean): android.content.ContextWrapper {
        val prefs = object : android.content.SharedPreferences {
            private val values = mutableMapOf<String, Any?>(
                org.snow.ui.SnowUiRepository.PREF_KEY_INSTANT_SYNC to enabled
            )
            override fun getAll(): MutableMap<String, *> = values
            override fun getString(key: String?, defValue: String?): String? = defValue
            override fun getStringSet(key: String?, defValues: MutableSet<String>?): MutableSet<String>? = defValues
            override fun getInt(key: String?, defValue: Int): Int = defValue
            override fun getLong(key: String?, defValue: Long): Long = defValue
            override fun getFloat(key: String?, defValue: Float): Float = defValue
            override fun getBoolean(key: String?, defValue: Boolean): Boolean =
                (values[key] as? Boolean) ?: defValue
            override fun contains(key: String?): Boolean = values.containsKey(key)
            override fun edit(): android.content.SharedPreferences.Editor = throw UnsupportedOperationException()
            override fun registerOnSharedPreferenceChangeListener(l: android.content.SharedPreferences.OnSharedPreferenceChangeListener?) {}
            override fun unregisterOnSharedPreferenceChangeListener(l: android.content.SharedPreferences.OnSharedPreferenceChangeListener?) {}
        }
        return object : android.content.ContextWrapper(null) {
            override fun getSharedPreferences(name: String?, mode: Int) = prefs
        }
    }

    @Test
    fun testClipboardPullForegroundAndUserIntentRestrictions() = runBlocking {
        val disabledSyncContext = contextWithInstantSync(false)
        val handler = ClipboardHandler(disabledSyncContext)

        // 1. App in background -> FOREGROUND_REQUIRED
        ClipboardHandler.isAppInForeground = false
        ClipboardHandler.isUserIntentGranted = true
        val resBg = handler.pullClipboard()
        assertEquals("error", resBg["status"])
        assertEquals("FOREGROUND_REQUIRED", resBg["error"])

        // 2. App in foreground with instant sync disabled & no user confirmation -> USER_CONFIRMATION_REQUIRED
        ClipboardHandler.isAppInForeground = true
        ClipboardHandler.isUserIntentGranted = false
        val resNoIntent = handler.pullClipboard()
        assertEquals("error", resNoIntent["status"])
        assertEquals("USER_CONFIRMATION_REQUIRED", resNoIntent["error"])
    }

    @Test
    fun testCapabilityDispatcherDispatchesClipboardPull() = runBlocking {
        val disabledSyncContext = contextWithInstantSync(false)
        val dispatcher = AndroidCapabilityDispatcher(disabledSyncContext, transferClientProvider = { null })

        // Backgrounded -> UNAUTHORIZED / FOREGROUND_REQUIRED
        ClipboardHandler.isAppInForeground = false
        ClipboardHandler.isUserIntentGranted = true
        val (resBg, errBg) = dispatcher.dispatch(
            action = "clipboard_pull",
            data = null,
            serverHost = "127.0.0.1",
            defaultTransferPort = 8766
        )
        assertNull(resBg)
        assertNotNull(errBg)
        assertEquals(ErrorCode.UNAUTHORIZED, errBg?.code)
        assertTrue(errBg?.message?.contains("FOREGROUND_REQUIRED") == true)

        // Foregrounded with instant sync disabled & unconfirmed -> UNAUTHORIZED / USER_CONFIRMATION_REQUIRED
        ClipboardHandler.isAppInForeground = true
        ClipboardHandler.isUserIntentGranted = false
        val (resNoIntent, errNoIntent) = dispatcher.dispatch(
            action = "clipboard_pull",
            data = null,
            serverHost = "127.0.0.1",
            defaultTransferPort = 8766
        )
        assertNull(resNoIntent)
        assertNotNull(errNoIntent)
        assertEquals(ErrorCode.UNAUTHORIZED, errNoIntent?.code)
        assertTrue(errNoIntent?.message?.contains("USER_CONFIRMATION_REQUIRED") == true)

        // Default true allows validation check without explicit prompt
        val defaultDispatcher = AndroidCapabilityDispatcher(object : android.content.ContextWrapper(null) {}, transferClientProvider = { null })
        assertNull(defaultDispatcher.validateExecutionContract("clipboard_pull", null))
    }

    @Test
    fun testAppLauncherPackageValidation() = runBlocking {
        val dummyContext = object : android.content.ContextWrapper(null) {}
        val handler = AppLauncherHandler(dummyContext)

        val resNull = handler.launchApp(null)
        assertEquals("error", resNull["status"])
        assertEquals("Package name cannot be empty.", resNull["error"])

        val resBlank = handler.launchApp("   ")
        assertEquals("error", resBlank["status"])
        assertEquals("Package name cannot be empty.", resBlank["error"])

        // Malformed package names
        val resMalformed1 = handler.launchApp("not_a_valid_package")
        assertEquals("MALFORMED_PACKAGE_NAME", resMalformed1["status"])
        val resMalformed2 = handler.launchApp("com..double.dot")
        assertEquals("MALFORMED_PACKAGE_NAME", resMalformed2["status"])

        // Unapproved package rejected by policy
        val resUnapproved = handler.launchApp("com.unapproved.arbitrary.app")
        assertEquals("POLICY_DENIED", resUnapproved["status"])
        assertEquals("POLICY_DENIED", resUnapproved["error"])

        // OWNER_MANUAL bypasses allowlist policy check (fails at package manager lookup in unit test, not POLICY_DENIED)
        val resOwnerBypass = handler.launchApp("com.unapproved.arbitrary.app", principal = "OWNER_MANUAL")
        assertEquals("error", resOwnerBypass["status"])
        assertTrue((resOwnerBypass["error"] as String).contains("not found or is not launchable"))

        // Approved package syntax passes policy check (fails at package manager lookup in unit test)
        val resApproved = handler.launchApp("com.google.android.calculator")
        assertEquals("error", resApproved["status"])
        assertTrue((resApproved["error"] as String).contains("not found or is not launchable"))
    }

    @Test
    fun testAppLauncherAllowlistCustomConfiguration() {
        val dummyContext = object : android.content.ContextWrapper(null) {}
        AppAllowlistPolicy.resetForTesting()

        assertTrue(AppAllowlistPolicy.isValidPackageSyntax("com.example.app"))
        assertFalse(AppAllowlistPolicy.isValidPackageSyntax("invalid-hyphen"))
        assertFalse(AppAllowlistPolicy.isValidPackageSyntax("com..double"))

        assertTrue(AppAllowlistPolicy.isAllowed(dummyContext, "com.google.android.calculator"))
        assertFalse(AppAllowlistPolicy.isAllowed(dummyContext, "com.evil.malware"))

        AppAllowlistPolicy.setCustomAllowlistForTesting(setOf("com.custom.allowed"))
        assertTrue(AppAllowlistPolicy.isAllowed(dummyContext, "com.custom.allowed"))
        assertFalse(AppAllowlistPolicy.isAllowed(dummyContext, "com.google.android.calculator"))

        AppAllowlistPolicy.resetForTesting()
    }

    @Test
    fun testCapabilityDispatcherDispatchesLaunchAppAllowlist() = runBlocking {
        val dummyContext = object : android.content.ContextWrapper(null) {}
        val dispatcher = AndroidCapabilityDispatcher(dummyContext, transferClientProvider = { null })

        ClipboardHandler.isAppInForeground = true

        // Unapproved package rejected with UNAUTHORIZED / POLICY_DENIED
        val (resDenied, errDenied) = dispatcher.dispatch(
            action = "launch_app",
            data = mapOf("package_name" to "com.unapproved.app"),
            serverHost = "127.0.0.1",
            defaultTransferPort = 8766
        )
        assertNull(resDenied)
        assertNotNull(errDenied)
        assertEquals(ErrorCode.UNAUTHORIZED, errDenied?.code)
        assertTrue(errDenied?.message?.contains("POLICY_DENIED") == true)

        // OWNER_MANUAL caller bypasses POLICY_DENIED allowlist rejection
        val (resOwner, errOwner) = dispatcher.dispatch(
            action = "launch_app",
            data = mapOf("package_name" to "com.unapproved.app", "principal" to "OWNER_MANUAL"),
            serverHost = "127.0.0.1",
            defaultTransferPort = 8766
        )
        assertNull(resOwner)
        assertNotNull(errOwner)
        // Fails with FILE_NOT_FOUND / error due to missing mock package, NOT UNAUTHORIZED / POLICY_DENIED
        assertEquals(ErrorCode.FILE_NOT_FOUND, errOwner?.code)
        assertFalse(errOwner?.message?.contains("POLICY_DENIED") == true)
        assertTrue(errOwner?.message?.contains("not found or is not launchable") == true)
    }

    @Test
    fun testFileHandlerValidationMissingParameters() = runBlocking {
        val tempDir = java.nio.file.Files.createTempDirectory("snow_file_test").toFile()
        val dummyContext = object : android.content.ContextWrapper(null) {
            override fun getFilesDir(): java.io.File = tempDir
            override fun getExternalFilesDir(type: String?): java.io.File = tempDir
        }
        val handler = AndroidFileHandler(dummyContext, transferClientProvider = { null })

        // Missing data
        val resNoData = handler.handleFileSendRequest(null, "127.0.0.1", 8766)
        assertEquals("error", resNoData["status"])
        assertEquals("Missing transfer payload.", resNoData["error"])

        // Missing transfer_id
        val resNoId = handler.handleFileSendRequest(mapOf("file_name" to "test.txt"), "127.0.0.1", 8766)
        assertEquals("error", resNoId["status"])
        assertTrue((resNoId["error"] as String).contains("Missing required fields"))

        // Invalid destination filename
        val resTraversal = handler.handleFileSendRequest(
            mapOf("transfer_id" to "t1", "file_name" to "..", "sha256" to "abc"),
            "127.0.0.1",
            8766
        )
        assertEquals("error", resTraversal["status"])
        assertEquals("Invalid destination filename.", resTraversal["error"])
    }
}
