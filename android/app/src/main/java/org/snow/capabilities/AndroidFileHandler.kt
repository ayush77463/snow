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

        val client = transferClientProvider()
        if (client == null) {
            return@withContext mapOf("status" to "error", "error" to "FileTransferClient not initialized.")
        }

        // 1. First resolve from user-configured SAF DocumentFile tree
        val subpath = data["subpath"] as? String
        val safDoc = resolveSafDocument(subpath, safeFileName)
        if (safDoc != null && safDoc.exists() && safDoc.isFile) {
            SafeLog.i(TAG, "Uploading SAF file '$safeFileName' (${safDoc.length()} bytes) to desktop core...")
            val result = client.uploadUri(
                serverHost = serverHost,
                transferPort = transferPort,
                uri = safDoc.uri,
                fileName = safDoc.name ?: safeFileName,
                fileSize = safDoc.length()
            )
            return@withContext when (result) {
                is FileTransferClient.TransferResult.Success -> {
                    SafeLog.i(TAG, "SAF upload successful: ${safDoc.name} (sha256=${result.sha256})")
                    mapOf(
                        "status" to "success",
                        "transfer_id" to result.transferId,
                        "file_name" to (safDoc.name ?: safeFileName),
                        "bytes_uploaded" to safDoc.length(),
                        "sha256" to result.sha256
                    )
                }
                is FileTransferClient.TransferResult.Duplicate -> {
                    mapOf(
                        "status" to "success",
                        "file_name" to (safDoc.name ?: safeFileName),
                        "bytes_uploaded" to safDoc.length(),
                        "sha256" to result.sha256,
                        "message" to "File already exists on desktop core with matching SHA-256."
                    )
                }
                is FileTransferClient.TransferResult.Error -> {
                    SafeLog.e(TAG, "SAF upload failed: ${result.message}")
                    mapOf(
                        "status" to "error",
                        "transfer_id" to result.transferId,
                        "error" to result.message
                    )
                }
            }
        }

        // 2. Documented fallback: app-specific transfers directory
        val transferDir = getTransfersDirectory()
        val localFile = File(transferDir, safeFileName)

        if (!localFile.exists() || !localFile.isFile) {
            SafeLog.w(TAG, "Requested file '$safeFileName' not found in SAF tree or ${transferDir.absolutePath}")
            return@withContext mapOf(
                "status" to "error",
                "error" to "File '$safeFileName' does not exist in Android SAF storage or transfer directory."
            )
        }

        SafeLog.i(TAG, "Uploading fallback file '$safeFileName' (${localFile.length()} bytes) to desktop core...")
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

    /**
     * Enumerate files and directories within the user-configured SAF DocumentFile tree.
     */
    fun handleFileList(data: Map<String, Any?>?): Map<String, Any?> {
        val safManager = org.snow.ui.files.SafFolderManager(context)
        val treeUri = safManager.getDestinationUri()
        if (treeUri == null) {
            return mapOf(
                "status" to "SAF_FOLDER_NOT_CONFIGURED",
                "error" to "No SAF destination folder has been configured by the user.",
                "remediation_hint" to "Open SNOW Files tab on the phone and pick a destination folder.",
                "items" to emptyList<Any>()
            )
        }

        val rootDoc = try {
            androidx.documentfile.provider.DocumentFile.fromTreeUri(context, treeUri)
        } catch (e: Exception) {
            return mapOf(
                "status" to "error",
                "error" to "Failed resolving SAF tree URI: ${e.message}",
                "items" to emptyList<Any>()
            )
        }

        if (rootDoc == null || !rootDoc.exists() || !rootDoc.canRead()) {
            return mapOf(
                "status" to "SAF_PERMISSION_REVOKED",
                "error" to "Persisted SAF tree permission has expired or been revoked.",
                "items" to emptyList<Any>()
            )
        }

        // Navigate subpath if requested
        val subpath = (data?.get("subpath") as? String ?: data?.get("path") as? String)?.trim()?.trim('/')
        var targetDoc: androidx.documentfile.provider.DocumentFile = rootDoc
        if (!subpath.isNullOrEmpty()) {
            val segments = subpath.split('/')
            for (segment in segments) {
                if (segment.isBlank() || segment == ".") continue
                if (segment == "..") {
                    return mapOf(
                        "status" to "error",
                        "error" to "PATH_TRAVERSAL_DETECTED",
                        "message" to "Relative path traversal '..' is forbidden."
                    )
                }
                val child = targetDoc.findFile(segment)
                if (child == null || !child.isDirectory) {
                    return mapOf(
                        "status" to "DIRECTORY_NOT_FOUND",
                        "error" to "Subdirectory '$segment' not found in SAF tree.",
                        "items" to emptyList<Any>()
                    )
                }
                targetDoc = child
            }
        }

        val items = mutableListOf<Map<String, Any?>>()
        val children = targetDoc.listFiles()
        for (child in children) {
            items.add(mapOf(
                "name" to (child.name ?: "unknown"),
                "type" to if (child.isDirectory) "directory" else "file",
                "size_bytes" to (if (child.isDirectory) 0L else child.length()),
                "last_modified" to child.lastModified(),
                "uri" to child.uri.toString()
            ))
            if (items.size >= 100) break
        }

        return mapOf(
            "status" to "success",
            "folder_name" to (targetDoc.name ?: safManager.getDestinationDisplayName()),
            "subpath" to (subpath ?: ""),
            "count" to items.size,
            "items" to items
        )
    }

    /**
     * Resolve a file DocumentFile safely within the persisted SAF tree.
     */
    fun resolveSafDocument(subpath: String?, fileName: String): androidx.documentfile.provider.DocumentFile? {
        val safManager = org.snow.ui.files.SafFolderManager(context)
        val treeUri = safManager.getDestinationUri() ?: return null
        val rootDoc = try {
            androidx.documentfile.provider.DocumentFile.fromTreeUri(context, treeUri)
        } catch (_: Exception) {
            null
        } ?: return null

        if (!rootDoc.exists() || !rootDoc.canRead()) return null

        var currentDoc = rootDoc
        val cleanSubpath = subpath?.trim()?.trim('/')
        if (!cleanSubpath.isNullOrEmpty()) {
            val segments = cleanSubpath.split('/')
            for (segment in segments) {
                if (segment.isBlank() || segment == ".") continue
                if (segment == "..") return null // Path traversal forbidden
                val child = currentDoc.findFile(segment) ?: return null
                if (!child.isDirectory) return null
                currentDoc = child
            }
        }
        val target = currentDoc.findFile(fileName)
        return if (target != null && target.exists() && target.isFile) target else null
    }
}
