package org.snow.capabilities

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.setMain
import org.junit.After
import org.junit.Assert.assertEquals
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
