package org.snow.capabilities

import android.content.Context
import android.graphics.Bitmap
import android.media.projection.MediaProjection
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.snow.security.SafeLog
import org.snow.transfer.FileTransferClient
import java.io.File
import java.io.FileOutputStream
import java.security.MessageDigest
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.UUID

/**
 * Consent-gated Android screen capture capability using MediaProjection.
 *
 * Enforces explicit OS-mediated user consent (MediaProjectionManager.createScreenCaptureIntent),
 * bounded image size, and HTTPS streaming upload via port 8766. Never transmits raw
 * image bytes or Base64 over the 64 KiB WSS control plane.
 */
class ScreenCaptureHandler(
    private val context: Context,
    private val transferClientProvider: () -> FileTransferClient?
) {
    companion object {
        private const val TAG = "ScreenCaptureHandler"
        const val MAX_IMAGE_WIDTH = 1920
        const val MAX_IMAGE_HEIGHT = 1080
        const val MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024L // 10 MiB

        @Volatile
        var isConsentGranted: Boolean = false

        @Volatile
        var activeMediaProjection: MediaProjection? = null

        /**
         * Test hook: inject mock consent and bitmap provider for deterministic automated testing.
         */
        @Volatile
        var mockBitmapProvider: (() -> Bitmap)? = null

        @Volatile
        var mockBitmapWriter: ((File) -> Unit)? = null

        fun resetConsent() {
            isConsentGranted = false
            activeMediaProjection?.stop()
            activeMediaProjection = null
            mockBitmapProvider = null
            mockBitmapWriter = null
            SafeLog.i(TAG, "MediaProjection consent and active session reset.")
        }
    }

    /**
     * Check if user has granted explicit MediaProjection consent for this capture session.
     */
    fun hasConsent(): Boolean {
        return isConsentGranted && (activeMediaProjection != null || mockBitmapProvider != null || mockBitmapWriter != null)
    }

    /**
     * Execute screen capture and upload resulting PNG via authenticated HTTPS port 8766.
     */
    suspend fun captureScreen(
        serverHost: String,
        transferPort: Int = 8766
    ): Map<String, Any?> = withContext(Dispatchers.IO) {
        if (!hasConsent()) {
            SafeLog.w(TAG, "Screen capture rejected: OS-mediated MediaProjection consent required.")
            return@withContext mapOf(
                "success" to false,
                "status" to "SCREEN_CAPTURE_CONSENT_REQUIRED",
                "error" to "MediaProjection consent has not been granted by the user.",
                "remediation_hint" to "Open SNOW on your Android device and initiate screen capture."
            )
        }

        val transferClient = transferClientProvider()
        if (transferClient == null) {
            SafeLog.e(TAG, "Transfer client unavailable for screenshot upload.")
            return@withContext mapOf(
                "success" to false,
                "status" to "TRANSFER_CLIENT_UNAVAILABLE",
                "error" to "File transfer client is not ready."
            )
        }

        val cacheDir = File(context.cacheDir, "captures").apply { mkdirs() }
        val timeStamp = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(Date())
        val uniqueTag = UUID.randomUUID().toString().take(8)
        val fileName = "android_screen_${timeStamp}_$uniqueTag.png"
        val tempFile = File(cacheDir, fileName)

        try {
            // 1. Acquire screen bitmap / write file
            if (mockBitmapWriter != null) {
                mockBitmapWriter!!.invoke(tempFile)
            } else {
                val bitmap = mockBitmapProvider?.invoke() ?: captureBitmapFromProjection()
                if (bitmap == null) {
                    return@withContext mapOf(
                        "success" to false,
                        "status" to "CAPTURE_FAILED",
                        "error" to "Failed acquiring screen bitmap surface."
                    )
                }

                // 2. Encode to PNG
                FileOutputStream(tempFile).use { fos ->
                    bitmap.compress(Bitmap.CompressFormat.PNG, 95, fos)
                    fos.flush()
                }
                if (mockBitmapProvider == null) {
                    bitmap.recycle()
                }
            }

            val sizeBytes = tempFile.length()
            if (sizeBytes > MAX_FILE_SIZE_BYTES) {
                tempFile.delete()
                return@withContext mapOf(
                    "success" to false,
                    "status" to "IMAGE_TOO_LARGE",
                    "error" to "Captured image ($sizeBytes bytes) exceeds limit ($MAX_FILE_SIZE_BYTES bytes)."
                )
            }

            // 3. Compute SHA-256
            val sha256 = FileTransferClient.computeSha256(tempFile)

            // 4. Upload via authenticated HTTPS
            val uploadRes = transferClient.uploadFile(
                serverHost = serverHost,
                transferPort = transferPort,
                file = tempFile
            )

            if (uploadRes !is FileTransferClient.TransferResult.Success) {
                val errMsg = if (uploadRes is FileTransferClient.TransferResult.Error) uploadRes.message else "Upload failed"
                SafeLog.e(TAG, "Failed uploading screen capture: $errMsg")
                return@withContext mapOf(
                    "success" to false,
                    "status" to "UPLOAD_FAILED",
                    "error" to "HTTPS transfer failed: $errMsg"
                )
            }

            val transferId = uploadRes.transferId

            SafeLog.i(TAG, "Android screen captured and uploaded successfully (file=$fileName, size=$sizeBytes).")
            return@withContext mapOf(
                "success" to true,
                "status" to "SUCCESS",
                "file_name" to fileName,
                "size_bytes" to sizeBytes,
                "sha256" to sha256,
                "transfer_id" to transferId
            )

        } catch (e: Exception) {
            SafeLog.e(TAG, "Exception during screen capture: ${e.message}", e)
            return@withContext mapOf(
                "success" to false,
                "status" to "CAPTURE_EXCEPTION",
                "error" to (e.message ?: "Screen capture error")
            )
        } finally {
            if (tempFile.exists()) {
                tempFile.delete()
            }
        }
    }

    private fun captureBitmapFromProjection(): Bitmap? {
        val proj = activeMediaProjection ?: return null
        val metrics = context.resources.displayMetrics
        val width = minOf(metrics.widthPixels, MAX_IMAGE_WIDTH)
        val height = minOf(metrics.heightPixels, MAX_IMAGE_HEIGHT)
        val density = metrics.densityDpi

        val projectionCallback = object : MediaProjection.Callback() {
            override fun onStop() {
                SafeLog.i(TAG, "MediaProjection stopped by system or user.")
                resetConsent()
            }
        }

        return try {
            // Android 14+ (API 34+) strictly requires a registered callback before createVirtualDisplay
            proj.registerCallback(projectionCallback, null)

            val imageReader = android.media.ImageReader.newInstance(
                width, height, android.graphics.PixelFormat.RGBA_8888, 2
            )
            val virtualDisplay = proj.createVirtualDisplay(
                "SnowScreenCapture",
                width,
                height,
                density,
                android.hardware.display.DisplayManager.VIRTUAL_DISPLAY_FLAG_AUTO_MIRROR,
                imageReader.surface,
                null,
                null
            )

            // Allow short frame draw cycle
            Thread.sleep(100)
            val image = imageReader.acquireLatestImage()
            val bitmap = if (image != null) {
                val planes = image.planes
                val buffer = planes[0].buffer
                val pixelStride = planes[0].pixelStride
                val rowStride = planes[0].rowStride
                val rowPadding = rowStride - pixelStride * width
                val bmp = Bitmap.createBitmap(
                    width + rowPadding / pixelStride, height, Bitmap.Config.ARGB_8888
                )
                bmp.copyPixelsFromBuffer(buffer)
                image.close()
                bmp
            } else {
                null
            }

            virtualDisplay.release()
            imageReader.close()
            try {
                proj.unregisterCallback(projectionCallback)
            } catch (_: Exception) {}
            bitmap
        } catch (e: Exception) {
            SafeLog.e(TAG, "Virtual display capture error: ${e.message}", e)
            try {
                proj.unregisterCallback(projectionCallback)
            } catch (_: Exception) {}
            null
        }
    }
}
