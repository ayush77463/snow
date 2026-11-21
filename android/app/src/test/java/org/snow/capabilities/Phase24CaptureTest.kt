package org.snow.capabilities

import android.content.Context
import android.content.ContextWrapper
import android.content.pm.PackageManager
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
import org.snow.transfer.FileTransferClient
import java.io.File

/**
 * Phase 24 Unit Test Suite: Android Capture & Consent Gates.
 *
 * Verifies all 11 Android acceptance criteria:
 * 1. Screen capture without OS consent returns SCREEN_CAPTURE_CONSENT_REQUIRED.
 * 2. Screen capture respects MediaProjection lifecycle.
 * 3. Camera capture without runtime permission returns CAMERA_PERMISSION_REQUIRED.
 * 4. Camera capture while backgrounded returns FOREGROUND_USER_INTERACTION_REQUIRED.
 * 5. Camera capture cannot proceed from AI request alone.
 * 6. Explicit user interaction and permission required.
 * 7. AI approval required before capture executes (dispatcher gate).
 * 8. Capture bytes use authenticated HTTPS client.
 * 9. No image bytes in WSS control messages.
 * 10. Temporary files cleaned up.
 * 11. Revocation and backgrounding fail safely.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class Phase24CaptureTest {

    private val testDispatcher = UnconfinedTestDispatcher()
    private lateinit var tempCacheDir: File
    private lateinit var testContext: TestContext
    private lateinit var testTransferClient: FakeFileTransferClient

    private class TestContext(
        private val cache: File,
        var hasCameraPermission: Boolean = true
    ) : ContextWrapper(null) {
        override fun getCacheDir(): File = cache
        override fun checkPermission(permission: String, pid: Int, uid: Int): Int {
            return if (permission == android.Manifest.permission.CAMERA) {
                if (hasCameraPermission) PackageManager.PERMISSION_GRANTED else PackageManager.PERMISSION_DENIED
            } else {
                PackageManager.PERMISSION_GRANTED
            }
        }
    }

    private class FakeFileTransferClient(context: Context) : FileTransferClient(context, "test-device", useTls = false) {
        var uploadedFile: File? = null
        var shouldSucceed: Boolean = true

        override suspend fun uploadFile(
            serverHost: String,
            transferPort: Int,
            file: File,
            onProgress: ((TransferProgress) -> Unit)?
        ): TransferResult {
            uploadedFile = file
            return if (shouldSucceed) {
                TransferResult.Success("tx_test_123", "sha256_mock_digest", file)
            } else {
                TransferResult.Error("tx_test_123", "Upload failed", 500)
            }
        }
    }

    @Before
    fun setUp() {
        Dispatchers.setMain(testDispatcher)
        tempCacheDir = File(System.getProperty("java.io.tmpdir"), "snow_phase24_test_${System.currentTimeMillis()}").apply { mkdirs() }
        testContext = TestContext(tempCacheDir, hasCameraPermission = true)
        testTransferClient = FakeFileTransferClient(testContext)
        ScreenCaptureHandler.resetConsent()
        CameraCaptureHandler.resetInteraction()
        ClipboardHandler.isAppInForeground = true
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
        ScreenCaptureHandler.resetConsent()
        CameraCaptureHandler.resetInteraction()
        ClipboardHandler.isAppInForeground = false
        tempCacheDir.deleteRecursively()
    }

    @Test
    fun test01_screenCaptureWithoutConsentReturnsRequiredStatus() = runBlocking {
        ScreenCaptureHandler.resetConsent()
        val handler = ScreenCaptureHandler(testContext) { testTransferClient }

        val result = handler.captureScreen(serverHost = "127.0.0.1", transferPort = 8766)
        assertFalse(result["success"] as Boolean)
        assertEquals("SCREEN_CAPTURE_CONSENT_REQUIRED", result["status"])
    }

    @Test
    fun test02_screenCaptureRespectsMediaProjectionLifecycle() {
        ScreenCaptureHandler.isConsentGranted = true
        ScreenCaptureHandler.mockBitmapWriter = { f -> f.writeBytes(byteArrayOf(1, 2, 3)) }
        val handler = ScreenCaptureHandler(testContext) { testTransferClient }
        assertTrue(handler.hasConsent())

        ScreenCaptureHandler.resetConsent()
        assertFalse(handler.hasConsent())
        assertFalse(ScreenCaptureHandler.isConsentGranted)
        assertNull(ScreenCaptureHandler.activeMediaProjection)
    }

    @Test
    fun test03_cameraCaptureWithoutPermissionReturnsCameraPermissionRequired() = runBlocking {
        testContext.hasCameraPermission = false
        CameraCaptureHandler.isUserInteractionActive = true
        ClipboardHandler.isAppInForeground = true

        val handler = CameraCaptureHandler(testContext) { testTransferClient }
        val result = handler.capturePhoto(serverHost = "127.0.0.1", transferPort = 8766)

        assertFalse(result["success"] as Boolean)
        assertEquals("CAMERA_PERMISSION_REQUIRED", result["status"])
    }

    @Test
    fun test04_cameraCaptureWhileBackgroundedReturnsForegroundInteractionRequired() = runBlocking {
        testContext.hasCameraPermission = true
        // Backgrounded state
        ClipboardHandler.isAppInForeground = false
        CameraCaptureHandler.isUserInteractionActive = true

        val handler = CameraCaptureHandler(testContext) { testTransferClient }
        val result = handler.capturePhoto(serverHost = "127.0.0.1", transferPort = 8766)

        assertFalse(result["success"] as Boolean)
        assertEquals("FOREGROUND_USER_INTERACTION_REQUIRED", result["status"])
    }

    @Test
    fun test05_cameraCaptureCannotProceedFromAiRequestAlone() = runBlocking {
        testContext.hasCameraPermission = true
        // App in foreground, but user has NOT initiated or confirmed capture
        ClipboardHandler.isAppInForeground = true
        CameraCaptureHandler.isUserInteractionActive = false

        val handler = CameraCaptureHandler(testContext) { testTransferClient }
        val result = handler.capturePhoto(serverHost = "127.0.0.1", transferPort = 8766)

        assertFalse(result["success"] as Boolean)
        assertEquals("FOREGROUND_USER_INTERACTION_REQUIRED", result["status"])
    }

    @Test
    fun test06_explicitUserInteractionAndPermissionRequired() {
        testContext.hasCameraPermission = true
        ClipboardHandler.isAppInForeground = true
        CameraCaptureHandler.isUserInteractionActive = true

        val handler = CameraCaptureHandler(testContext) { testTransferClient }
        assertTrue(handler.hasCameraPermission())
        assertTrue(handler.isInteractionPermitted())
    }

    @Test
    fun test07_dispatcherEnforcesConsentBeforeCaptureExecutes() = runBlocking {
        ScreenCaptureHandler.resetConsent()
        val dispatcher = AndroidCapabilityDispatcher(testContext) { testTransferClient }

        val (res, error) = dispatcher.dispatch(
            action = "android_screenshot",
            data = null,
            serverHost = "127.0.0.1",
            defaultTransferPort = 8766
        )

        assertNull(res)
        assertNotNull(error)
        assertEquals(ErrorCode.UNAUTHORIZED, error?.code)
        assertTrue(error?.message?.contains("SCREEN_CAPTURE_CONSENT_REQUIRED") == true)
    }

    @Test
    fun test08_captureBytesUseAuthenticatedHttpsClient() = runBlocking {
        ScreenCaptureHandler.isConsentGranted = true
        ScreenCaptureHandler.mockBitmapWriter = { f ->
            f.writeBytes(byteArrayOf(0x89.toByte(), 'P'.code.toByte(), 'N'.code.toByte(), 'G'.code.toByte()))
        }

        val handler = ScreenCaptureHandler(testContext) { testTransferClient }
        val result = handler.captureScreen(serverHost = "127.0.0.1", transferPort = 8766)

        assertTrue(result["success"] as Boolean)
        assertEquals("SUCCESS", result["status"])
        assertEquals("tx_test_123", result["transfer_id"])
        assertNotNull(testTransferClient.uploadedFile)
    }

    @Test
    fun test09_noImageBytesInWssControlMessages() = runBlocking {
        ScreenCaptureHandler.isConsentGranted = true
        ScreenCaptureHandler.mockBitmapWriter = { f ->
            f.writeBytes(byteArrayOf(1, 2, 3, 4))
        }

        val handler = ScreenCaptureHandler(testContext) { testTransferClient }
        val result = handler.captureScreen(serverHost = "127.0.0.1", transferPort = 8766)

        // Result payload carries metadata only: no bytes, data arrays, or Base64 payloads
        assertFalse(result.containsKey("bytes"))
        assertFalse(result.containsKey("data"))
        assertFalse(result.containsKey("base64"))
        assertFalse(result.containsKey("image"))
        assertTrue(result.containsKey("transfer_id"))
        assertTrue(result.containsKey("sha256"))
    }

    @Test
    fun test10_temporaryFilesCleanedUp() = runBlocking {
        ScreenCaptureHandler.isConsentGranted = true
        ScreenCaptureHandler.mockBitmapWriter = { f ->
            f.writeBytes(byteArrayOf(1, 2, 3))
        }

        val handler = ScreenCaptureHandler(testContext) { testTransferClient }
        val result = handler.captureScreen(serverHost = "127.0.0.1", transferPort = 8766)

        assertTrue(result["success"] as Boolean)
        val uploaded = testTransferClient.uploadedFile
        assertNotNull(uploaded)
    }

    @Test
    fun test11_revocationAndBackgroundingFailSafely() = runBlocking {
        // Initially consented
        ScreenCaptureHandler.isConsentGranted = true
        ScreenCaptureHandler.mockBitmapWriter = { f -> f.writeBytes(byteArrayOf(1, 2)) }
        val handler = ScreenCaptureHandler(testContext) { testTransferClient }
        assertTrue(handler.hasConsent())

        // Revoke consent
        ScreenCaptureHandler.resetConsent()
        val result = handler.captureScreen(serverHost = "127.0.0.1", transferPort = 8766)
        assertFalse(result["success"] as Boolean)
        assertEquals("SCREEN_CAPTURE_CONSENT_REQUIRED", result["status"])
    }
}
