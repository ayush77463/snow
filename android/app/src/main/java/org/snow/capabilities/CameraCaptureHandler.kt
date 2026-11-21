package org.snow.capabilities

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.graphics.Bitmap
import androidx.core.content.ContextCompat
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.snow.security.SafeLog
import org.snow.transfer.FileTransferClient
import java.io.File
import java.io.FileOutputStream
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.UUID

/**
 * Consent-gated Android camera capture capability.
 *
 * Enforces:
 * 1. Explicit runtime CAMERA permission.
 * 2. Active foreground state and visible user interaction.
 * 3. Bounded photo acquisition and HTTPS streaming upload via port 8766.
 *
 * An AI request cannot silently trigger camera capture from the background.
 */
class CameraCaptureHandler(
    private val context: Context,
    private val transferClientProvider: () -> FileTransferClient?
) {
    companion object {
        private const val TAG = "CameraCaptureHandler"
        const val MAX_IMAGE_WIDTH = 1920
        const val MAX_IMAGE_HEIGHT = 1080
        const val MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024L // 10 MiB

        @Volatile
        var isUserInteractionActive: Boolean = false

        /**
         * Test hook: inject mock bitmap provider for deterministic automated testing.
         */
        @Volatile
        var mockBitmapProvider: (() -> Bitmap)? = null

        @Volatile
        var mockPhotoWriter: ((File) -> Unit)? = null

        @Volatile
        var stagedPhotoFile: File? = null

        fun hasStagedPhoto(): Boolean = stagedPhotoFile != null && stagedPhotoFile!!.exists()

        fun resetInteraction() {
            isUserInteractionActive = false
            mockBitmapProvider = null
            mockPhotoWriter = null
            stagedPhotoFile?.delete()
            stagedPhotoFile = null
            SafeLog.i(TAG, "Camera user interaction state reset.")
        }
    }

    /**
     * Verify whether runtime CAMERA permission has been granted.
     */
    fun hasCameraPermission(): Boolean {
        return ContextCompat.checkSelfPermission(
            context, Manifest.permission.CAMERA
        ) == PackageManager.PERMISSION_GRANTED
    }

    /**
     * Verify whether foreground visibility and user confirmation requirements are satisfied.
     */
    fun isInteractionPermitted(): Boolean {
        return ClipboardHandler.isAppInForeground && isUserInteractionActive
    }

    /**
     * Execute photo capture and upload JPEG via authenticated HTTPS port 8766.
     */
    suspend fun capturePhoto(
        serverHost: String,
        transferPort: Int = 8766
    ): Map<String, Any?> = withContext(Dispatchers.IO) {
        // 1. Permission Check
        if (!hasCameraPermission()) {
            SafeLog.w(TAG, "Camera capture rejected: CAMERA runtime permission missing.")
            return@withContext mapOf(
                "success" to false,
                "status" to "CAMERA_PERMISSION_REQUIRED",
                "error" to "Camera runtime permission has not been granted by user.",
                "remediation_hint" to "Grant Camera permission in Android Settings."
            )
        }

        // 2. Foreground & Active Interaction Check
        if (!isInteractionPermitted() && mockBitmapProvider == null) {
            SafeLog.w(TAG, "Camera capture rejected: app not in foreground or no active user interaction.")
            return@withContext mapOf(
                "success" to false,
                "status" to "FOREGROUND_USER_INTERACTION_REQUIRED",
                "error" to "Camera capture requires SNOW to be in the foreground with an active visible user interaction.",
                "remediation_hint" to "Open SNOW on your Android phone and confirm camera capture."
            )
        }

        val transferClient = transferClientProvider()
        if (transferClient == null) {
            SafeLog.e(TAG, "Transfer client unavailable for photo upload.")
            return@withContext mapOf(
                "success" to false,
                "status" to "TRANSFER_CLIENT_UNAVAILABLE",
                "error" to "File transfer client is not ready."
            )
        }

        val cacheDir = File(context.cacheDir, "camera_captures").apply { mkdirs() }
        val timeStamp = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(Date())
        val uniqueTag = UUID.randomUUID().toString().take(8)
        val fileName = "android_photo_${timeStamp}_$uniqueTag.jpg"
        val tempFile = File(cacheDir, fileName)

        try {
            if (mockPhotoWriter != null) {
                mockPhotoWriter!!.invoke(tempFile)
            } else if (mockBitmapProvider != null) {
                val bitmap = mockBitmapProvider!!.invoke()
                FileOutputStream(tempFile).use { fos ->
                    bitmap.compress(Bitmap.CompressFormat.JPEG, 90, fos)
                    fos.flush()
                }
            } else if (stagedPhotoFile != null && stagedPhotoFile!!.exists()) {
                stagedPhotoFile!!.copyTo(tempFile, overwrite = true)
                // Retain stagedPhotoFile until delivery is confirmed!
            } else {
                SafeLog.w(TAG, "Camera capture rejected: no staged photo available from user interaction.")
                return@withContext mapOf(
                    "success" to false,
                    "status" to "FOREGROUND_USER_INTERACTION_REQUIRED",
                    "error" to "Camera capture requires user interaction to take a photo on the Android device.",
                    "remediation_hint" to "Open SNOW on your Android phone and take a photo."
                )
            }

            val sizeBytes = tempFile.length()
            if (sizeBytes > MAX_FILE_SIZE_BYTES) {
                tempFile.delete()
                return@withContext mapOf(
                    "success" to false,
                    "status" to "IMAGE_TOO_LARGE",
                    "error" to "Captured photo ($sizeBytes bytes) exceeds limit ($MAX_FILE_SIZE_BYTES bytes)."
                )
            }

            // 5. Compute SHA-256
            val sha256 = FileTransferClient.computeSha256(tempFile)

            // 6. Upload via authenticated HTTPS
            val uploadRes = transferClient.uploadFile(
                serverHost = serverHost,
                transferPort = transferPort,
                file = tempFile
            )

            if (uploadRes !is FileTransferClient.TransferResult.Success) {
                val errMsg = if (uploadRes is FileTransferClient.TransferResult.Error) uploadRes.message else "Upload failed"
                SafeLog.e(TAG, "Failed uploading camera photo: $errMsg")
                return@withContext mapOf(
                    "success" to false,
                    "status" to "UPLOAD_FAILED",
                    "error" to "HTTPS transfer failed: $errMsg"
                )
            }

            val transferId = uploadRes.transferId

            // Critical retention rule: Delete staged photo ONLY after confirmed successful delivery
            stagedPhotoFile?.delete()
            stagedPhotoFile = null

            SafeLog.i(TAG, "Android camera photo captured and uploaded successfully (file=$fileName, size=$sizeBytes).")
            return@withContext mapOf(
                "success" to true,
                "status" to "SUCCESS",
                "file_name" to fileName,
                "size_bytes" to sizeBytes,
                "sha256" to sha256,
                "transfer_id" to transferId
            )

        } catch (e: Exception) {
            SafeLog.e(TAG, "Exception during camera capture: ${e.message}", e)
            return@withContext mapOf(
                "success" to false,
                "status" to "CAPTURE_EXCEPTION",
                "error" to (e.message ?: "Camera capture error")
            )
        } finally {
            if (tempFile.exists()) {
                tempFile.delete()
            }
            // Consume user interaction flag once finished (fresh interaction required per capture)
            isUserInteractionActive = false
        }
    }
}
