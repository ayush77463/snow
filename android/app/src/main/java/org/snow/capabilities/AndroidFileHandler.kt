package org.snow.capabilities

import android.content.Context
import android.os.Environment
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.snow.security.SafeLog
import org.snow.transfer.FileTransferClient
import java.io.File

/**
 * Android bidirectional file transfer capability handler.
 *
 * Implements Sub-Milestone 6.5:
 * - Directs incoming desktop files into app-scoped storage via FileTransferClient.downloadFile.
 * - Uploads requested Android files to Desktop Core via FileTransferClient.uploadFile.
 * - Strictly enforces scoped path containment and 64 KiB streaming chunk digests.
 * - Reuses existing Phase 3 authenticated HTTPS streaming infrastructure on port 8766.
 */
class AndroidFileHandler(
    private val context: Context,
    private val transferClientProvider: () -> FileTransferClient?
) {
    companion object {
        private const val TAG = "AndroidFileHandler"
    }

    /**
     * Resolves the primary app-scoped directory for transferred files.
     */
    fun getTransfersDirectory(): File {
        val extDir = context.getExternalFilesDir(Environment.DIRECTORY_DOWNLOADS)
        val dir = if (extDir != null) {
            File(extDir, "SNOW")
        } else {
            File(context.filesDir, "transfers")
        }
        if (!dir.exists()) {
            dir.mkdirs()
        }
        return dir
    }

    /**
     * Handle desktop -> Android file transmission request.
     */
    suspend fun handleFileSendRequest(
        data: Map<String, Any?>?,
        serverHost: String,
        defaultTransferPort: Int
    ): Map<String, Any?> = withContext(Dispatchers.IO) {
        if (data == null) {
            return@withContext mapOf("status" to "error", "error" to "Missing transfer payload.")
        }

        val transferId = data["transfer_id"] as? String
        val rawFileName = data["file_name"] as? String
        val expectedSha256 = data["sha256"] as? String
        val transferPort = (data["transfer_port"] as? Number)?.toInt() ?: defaultTransferPort

        if (transferId.isNullOrBlank() || rawFileName.isNullOrBlank() || expectedSha256.isNullOrBlank()) {
            return@withContext mapOf(
                "status" to "error",
                "error" to "Missing required fields: transfer_id, file_name, or sha256."
            )
        }

        // Sanitize filename to prevent directory traversal
        val safeFileName = File(rawFileName).name
        if (safeFileName.isBlank() || safeFileName == "." || safeFileName == "..") {
            return@withContext mapOf("status" to "error", "error" to "Invalid destination filename.")
        }

        val client = transferClientProvider()
        if (client == null) {
            return@withContext mapOf("status" to "error", "error" to "FileTransferClient not initialized.")
        }

        val destinationDir = getTransfersDirectory()
        val destinationFile = File(destinationDir, safeFileName)

        SafeLog.i(TAG, "Downloading incoming file '$safeFileName' [transfer_id=$transferId]...")
        val result = client.downloadFile(
            serverHost = serverHost,
            transferPort = transferPort,
            transferId = transferId,
            destinationFile = destinationFile,
            expectedSha256 = expectedSha256,
            resume = true
        )

        when (result) {
            is FileTransferClient.TransferResult.Success -> {
                SafeLog.i(TAG, "Download successful: ${destinationFile.absolutePath} (${destinationFile.length()} bytes)")
                mapOf(
                    "status" to "success",
                    "transfer_id" to transferId,
                    "file_name" to safeFileName,
                    "bytes_downloaded" to destinationFile.length(),
                    "sha256" to result.sha256,
                    "saved_path" to destinationFile.absolutePath
                )
            }
            is FileTransferClient.TransferResult.Duplicate -> {
                mapOf(
                    "status" to "success",
                    "transfer_id" to transferId,
                    "file_name" to safeFileName,
                    "bytes_downloaded" to destinationFile.length(),
                    "sha256" to result.sha256,
                    "message" to "File already exists with matching SHA-256."
                )
            }
            is FileTransferClient.TransferResult.Error -> {
                SafeLog.e(TAG, "Download failed: ${result.message}")
                mapOf(
                    "status" to "error",
                    "transfer_id" to transferId,
                    "error" to result.message
                )
            }
        }
    }

    /**
     * Handle Android -> desktop file request.
     */
    suspend fun handleFileReceiveRequest(
        data: Map<String, Any?>?,
        serverHost: String,
        defaultTransferPort: Int
    ): Map<String, Any?> = withContext(Dispatchers.IO) {
        if (data == null) {
            return@withContext mapOf("status" to "error", "error" to "Missing transfer payload.")
        }

        val rawFileName = data["file_name"] as? String
        val transferPort = (data["transfer_port"] as? Number)?.toInt() ?: defaultTransferPort

        if (rawFileName.isNullOrBlank()) {
            return@withContext mapOf("status" to "error", "error" to "Missing required field: file_name.")
        }

        val safeFileName = File(rawFileName).name
        if (safeFileName.isBlank() || safeFileName == "." || safeFileName == "..") {
            return@withContext mapOf("status" to "error", "error" to "Invalid filename requested.")
        }

        val transferDir = getTransfersDirectory()
        val localFile = File(transferDir, safeFileName)

        if (!localFile.exists() || !localFile.isFile) {
            SafeLog.w(TAG, "Requested file '$safeFileName' not found in ${transferDir.absolutePath}")
            return@withContext mapOf(
                "status" to "error",
                "error" to "File '$safeFileName' does not exist in Android SNOW transfer storage."
            )
        }

        val client = transferClientProvider()
        if (client == null) {
            return@withContext mapOf("status" to "error", "error" to "FileTransferClient not initialized.")
        }

        SafeLog.i(TAG, "Uploading file '$safeFileName' (${localFile.length()} bytes) to desktop core...")
        val result = client.uploadFile(
            serverHost = serverHost,
            transferPort = transferPort,
            file = localFile
        )

        when (result) {
            is FileTransferClient.TransferResult.Success -> {
                SafeLog.i(TAG, "Upload successful: ${localFile.name} (sha256=${result.sha256})")
                mapOf(
                    "status" to "success",
                    "transfer_id" to result.transferId,
                    "file_name" to localFile.name,
                    "bytes_uploaded" to localFile.length(),
                    "sha256" to result.sha256
                )
            }
            is FileTransferClient.TransferResult.Duplicate -> {
                mapOf(
                    "status" to "success",
                    "file_name" to localFile.name,
                    "bytes_uploaded" to localFile.length(),
                    "sha256" to result.sha256,
                    "message" to "File already exists on desktop core with matching SHA-256."
                )
            }
            is FileTransferClient.TransferResult.Error -> {
                SafeLog.e(TAG, "Upload failed: ${result.message}")
                mapOf(
                    "status" to "error",
                    "error" to result.message
                )
            }
        }
    }
}
