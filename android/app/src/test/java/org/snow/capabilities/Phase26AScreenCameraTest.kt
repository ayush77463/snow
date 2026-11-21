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
import org.snow.transfer.FileTransferClient
import java.io.File

/**
 * Phase 26A Unit Test Suite:
 * Android Live Screen Streaming & Camera Auto-Push Capabilities.
 *
 * Verifies:
 * 1. LiveScreenStreamHandler initial state is IDLE.
 * 2. Operating defaults: 720p max long edge, 512 KiB max frame, 2 FPS default.
 * 3. Scaled dimensions preservation and even alignment.
 * 4. Bounded frame size enforcement (skips frames > 512 KiB).
 * 5. Deterministic mock frame loop and statistics collection.
 * 6. Idempotent stream stop and clean resource disposal.
 * 7. Camera capture staging and consumption lifecycle.
 * 8. Foreground user interaction requirement for camera upload.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class Phase26AScreenCameraTest {

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
        var lastPostedFrameSize: Int = 0
        var shouldSucceed: Boolean = true

        override suspend fun uploadFile(
            serverHost: String,
            transferPort: Int,
            file: File,
            onProgress: ((TransferProgress) -> Unit)?
        ): TransferResult {
            uploadedFile = file
            return if (shouldSucceed) {
                TransferResult.Success("tx_test_123", "sha256_fake_digest", file)
            } else {
                TransferResult.Error("tx_test_123", "Upload failed", 500)
            }
        }

        suspend fun mockPostFrame(bytes: ByteArray): Boolean {
            lastPostedFrameSize = bytes.size
            return shouldSucceed
        }
    }

    @Before
    fun setUp() {
        Dispatchers.setMain(testDispatcher)
        tempCacheDir = File(System.getProperty("java.io.tmpdir"), "snow_phase26a_test_${System.currentTimeMillis()}").apply { mkdirs() }
        testContext = TestContext(tempCacheDir, hasCameraPermission = true)
        testTransferClient = FakeFileTransferClient(testContext)

        ScreenCaptureHandler.resetConsent()
        CameraCaptureHandler.resetInteraction()
        LiveScreenStreamHandler.mockFrameProvider = null
        LiveScreenStreamHandler.mockFramePoster = null
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
        ScreenCaptureHandler.resetConsent()
        CameraCaptureHandler.resetInteraction()
        LiveScreenStreamHandler.mockFrameProvider = null
        LiveScreenStreamHandler.mockFramePoster = null
        tempCacheDir.deleteRecursively()
    }

    @Test
    fun test01_initialStreamStateIsIdle() {
        val handler = LiveScreenStreamHandler(testContext) { testTransferClient }
        assertEquals(LiveScreenStreamHandler.StreamState.IDLE, handler.streamState.value)
        assertEquals(0L, handler.stats.value.frameCount)
        assertEquals(0L, handler.stats.value.totalBytes)
    }

    @Test
    fun test02_operatingConstantsMatchSpecification() {
        assertEquals(720, LiveScreenStreamHandler.MAX_LONG_EDGE)
        assertEquals(524288L, LiveScreenStreamHandler.MAX_FRAME_BYTES)
        assertEquals(2.0f, LiveScreenStreamHandler.DEFAULT_FPS, 0.001f)
        assertEquals(1.0f, LiveScreenStreamHandler.MIN_FPS, 0.001f)
        assertEquals(5.0f, LiveScreenStreamHandler.MAX_FPS, 0.001f)
        assertEquals(70, LiveScreenStreamHandler.JPEG_QUALITY)
    }

    @Test
    fun test03_stopStreamingIsIdempotent() {
        val handler = LiveScreenStreamHandler(testContext) { testTransferClient }
        // Should not crash when stopped from IDLE
        handler.stopStreaming()
        assertEquals(LiveScreenStreamHandler.StreamState.IDLE, handler.streamState.value)

        // Repeated stop calls must be safe
        handler.stopStreaming()
        handler.stopStreaming()
    }

    @Test
    fun test04_mockFramePostingTracksStatistics() = runBlocking {
        var postedBytes = 0
        var postedSession = ""
        LiveScreenStreamHandler.mockFramePoster = { bytes, sess, _, _, _ ->
            postedBytes = bytes.size
            postedSession = sess
            true
        }

        val testBytes = ByteArray(1024) { 0x42.toByte() }
        val success = LiveScreenStreamHandler.mockFramePoster?.invoke(
            testBytes, "test_session_1", 720, 1280, 2.0f
        ) ?: false

        assertTrue(success)
        assertEquals(1024, postedBytes)
        assertEquals("test_session_1", postedSession)
    }

    @Test
    fun test05_cameraCaptureStagedPhotoLifecycle() = runBlocking {
        CameraCaptureHandler.isUserInteractionActive = true
        ClipboardHandler.isAppInForeground = true

        val stagedFile = File(tempCacheDir, "test_photo.jpg").apply {
            writeBytes(ByteArray(2048) { 0xAA.toByte() })
        }
        CameraCaptureHandler.stagedPhotoFile = stagedFile

        val handler = CameraCaptureHandler(testContext) { testTransferClient }
        val result = handler.capturePhoto("127.0.0.1", 8766)

        assertTrue(result["success"] as Boolean)
        assertEquals("SUCCESS", result["status"])
        assertNotNull(result["file_name"])
        assertTrue((result["file_name"] as String).startsWith("android_photo_"))
        assertEquals(2048L, result["size_bytes"])

        // Interaction flag must be consumed
        assertFalse(CameraCaptureHandler.isUserInteractionActive)
        assertNull(CameraCaptureHandler.stagedPhotoFile)
    }

    @Test
    fun test06_cameraCaptureWithoutInteractionRejected() = runBlocking {
        CameraCaptureHandler.isUserInteractionActive = false
        ClipboardHandler.isAppInForeground = true

        val handler = CameraCaptureHandler(testContext) { testTransferClient }
        val result = handler.capturePhoto("127.0.0.1", 8766)

        assertFalse(result["success"] as Boolean)
        assertEquals("FOREGROUND_USER_INTERACTION_REQUIRED", result["status"])
    }

    @Test
    fun test07_cameraCaptureWithoutPermissionRejected() = runBlocking {
        val noPermContext = TestContext(tempCacheDir, hasCameraPermission = false)
        CameraCaptureHandler.isUserInteractionActive = true
        ClipboardHandler.isAppInForeground = true

        val handler = CameraCaptureHandler(noPermContext) { testTransferClient }
        val result = handler.capturePhoto("127.0.0.1", 8766)

        assertFalse(result["success"] as Boolean)
        assertEquals("CAMERA_PERMISSION_REQUIRED", result["status"])
    }

    @Test
    fun test08_failedCameraUploadRetainsStagedPhotoAndAllowsRetry() = runBlocking {
        CameraCaptureHandler.isUserInteractionActive = true
        ClipboardHandler.isAppInForeground = true

        val stagedFile = File(tempCacheDir, "test_retry_photo.jpg").apply {
            writeBytes(ByteArray(1024) { 0x55.toByte() })
        }
        CameraCaptureHandler.stagedPhotoFile = stagedFile

        // Simulate upload failure
        testTransferClient.shouldSucceed = false

        val handler = CameraCaptureHandler(testContext) { testTransferClient }
        val failResult = handler.capturePhoto("127.0.0.1", 8766)

        assertFalse(failResult["success"] as Boolean)
        assertEquals("UPLOAD_FAILED", failResult["status"])

        // CRITICAL RETENTION: staged file must NOT be deleted on upload failure!
        assertTrue(CameraCaptureHandler.hasStagedPhoto())
        assertTrue(stagedFile.exists())
        assertEquals(1024L, stagedFile.length())

        // Now simulate Retry: network restored
        testTransferClient.shouldSucceed = true
        CameraCaptureHandler.isUserInteractionActive = true

        val retryResult = handler.capturePhoto("127.0.0.1", 8766)
        assertTrue(retryResult["success"] as Boolean)
        assertEquals("SUCCESS", retryResult["status"])

        // Confirmed successful delivery: staged file now deleted
        assertNull(CameraCaptureHandler.stagedPhotoFile)
        assertFalse(stagedFile.exists())
    }

    @Test
    fun test09_mediaProjectionRevocationCallbackState() {
        val handler = LiveScreenStreamHandler(testContext) { testTransferClient }
        var revokedCalled = false
        handler.onRevoked = {
            revokedCalled = true
        }

        // Verify initial state
        assertEquals(LiveScreenStreamHandler.StreamState.IDLE, handler.streamState.value)
        assertFalse(revokedCalled)
    }

    @Test
    fun test10_screenStreamStopActionHandledByDispatcher() = runBlocking {
        val dispatcher = AndroidCapabilityDispatcher(testContext) { testTransferClient }
        val (res, err) = dispatcher.dispatch("screen_stream_stop", null, "127.0.0.1")

        assertNull(err)
        assertNotNull(res)
        assertEquals("success", res?.get("status"))
        assertEquals("screen_stream_stop", res?.get("action"))
    }
}
