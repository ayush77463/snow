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

        fun isPathContained(candidate: File, root: File): Boolean {
            val candPath = candidate.canonicalPath
            val rootPath = root.canonicalPath
            return candPath == rootPath || candPath.startsWith(rootPath + File.separator)
        }
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

        val requestedScope = data["scope"] as? String
        val principal = data["principal"] as? String ?: "AI_MCP"
        val subpath = data["subpath"] as? String

        val isFullStorageEligible = isAllFilesAccessGranted() && principal == "OWNER_MANUAL" && requestedScope != "saf"

        // 1. If eligible, resolve from full shared internal storage
        if (isFullStorageEligible) {
            val sharedFile = resolveSharedStorageFile(subpath, safeFileName)
            if (sharedFile != null && sharedFile.exists() && sharedFile.isFile) {
                SafeLog.i(TAG, "Uploading full storage file '$safeFileName' (${sharedFile.length()} bytes) to desktop core...")
                val result = client.uploadFile(
                    serverHost = serverHost,
                    transferPort = transferPort,
                    file = sharedFile
                )
                return@withContext when (result) {
                    is FileTransferClient.TransferResult.Success -> {
                        SafeLog.i(TAG, "Full storage upload successful: ${sharedFile.name} (sha256=${result.sha256})")
                        mapOf(
                            "status" to "success",
                            "transfer_id" to result.transferId,
                            "file_name" to sharedFile.name,
                            "bytes_uploaded" to sharedFile.length(),
                            "sha256" to result.sha256
                        )
                    }
                    is FileTransferClient.TransferResult.Duplicate -> {
                        mapOf(
                            "status" to "success",
                            "file_name" to sharedFile.name,
                            "bytes_uploaded" to sharedFile.length(),
                            "sha256" to result.sha256,
                            "message" to "File already exists on desktop core with matching SHA-256."
                        )
                    }
                    is FileTransferClient.TransferResult.Error -> {
                        SafeLog.e(TAG, "Full storage upload failed: ${result.message}")
                        mapOf(
                            "status" to "error",
                            "transfer_id" to result.transferId,
                            "error" to result.message
                        )
                    }
                }
            }
        }

        // 2. Resolve from user-configured SAF DocumentFile tree
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

        SafeLog.w(TAG, "Requested file '$safeFileName' not found in accessible storage.")
        return@withContext mapOf(
            "status" to "error",
            "error" to "FILE_NOT_FOUND",
            "message" to "File '$safeFileName' does not exist in Android shared storage or SAF folder."
        )
    }

    /**
     * Check whether Android 11+ All Files Access (MANAGE_EXTERNAL_STORAGE) is granted.
     */
    fun isAllFilesAccessGranted(): Boolean {
        return if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.R) {
            Environment.isExternalStorageManager()
        } else {
            false
        }
    }

    /**
     * Enumerate files and directories within Full Shared Internal Storage or SAF DocumentFile tree.
     */
    fun handleFileList(data: Map<String, Any?>?): Map<String, Any?> {
        val requestedScope = data?.get("scope") as? String
        val principal = data?.get("principal") as? String ?: "AI_MCP"
        val showHidden = (data?.get("show_hidden") as? Boolean) ?: false
        val subpath = (data?.get("subpath") as? String ?: data?.get("path") as? String)?.trim()?.trim('/')

        // AI_MCP is strictly restricted to SAF mode in this phase
        val isFullStorageEligible = isAllFilesAccessGranted() && principal != "AI_MCP" && requestedScope != "saf"

        if (requestedScope == "full" && !isAllFilesAccessGranted()) {
            return mapOf(
                "status" to "ALL_FILES_ACCESS_REQUIRED",
                "error" to "Full Phone Storage Access is not granted on this device. Please grant access in Android Settings.",
                "remediation_hint" to "Open SNOW Settings > Full Phone Storage Access on your phone.",
                "storage_mode" to "unavailable",
                "items" to emptyList<Any>()
            )
        }

        if (isFullStorageEligible && (requestedScope == "full" || requestedScope == null)) {
            return listFullSharedStorage(subpath, showHidden)
        }

        // Fallback to SAF DocumentFile Tree
        return listSafTree(subpath)
    }

    private fun listFullSharedStorage(subpath: String?, showHidden: Boolean): Map<String, Any?> {
        val rootDir = Environment.getExternalStorageDirectory()
        if (rootDir == null || !rootDir.exists() || !rootDir.canRead()) {
            return mapOf(
                "status" to "STORAGE_UNAVAILABLE",
                "error" to "Shared internal storage root is currently inaccessible.",
                "storage_mode" to "full_shared_storage",
                "items" to emptyList<Any>()
            )
        }

        val canonicalRoot = rootDir.canonicalFile
        var targetDir = canonicalRoot

        if (!subpath.isNullOrEmpty()) {
            // Path traversal validation
            val segments = subpath.split('/')
            for (segment in segments) {
                if (segment.isBlank() || segment == ".") continue
                if (segment == ".." || segment.contains('\\')) {
                    return mapOf(
                        "status" to "error",
                        "error" to "PATH_TRAVERSAL_DETECTED",
                        "message" to "Relative path traversal '..' is strictly prohibited.",
                        "storage_mode" to "full_shared_storage",
                        "items" to emptyList<Any>()
                    )
                }
            }

            val candidate = File(canonicalRoot, subpath).canonicalFile
            if (!isPathContained(candidate, canonicalRoot)) {
                return mapOf(
                    "status" to "error",
                    "error" to "PATH_TRAVERSAL_DETECTED",
                    "message" to "Target directory lies outside the allowed shared storage root.",
                    "storage_mode" to "full_shared_storage",
                    "items" to emptyList<Any>()
                )
            }

            // Block restricted Android/data and Android/obb directories
            val relPath = candidate.path.removePrefix(canonicalRoot.path).replace('\\', '/').trim('/')
            if (relPath.equals("Android/data", ignoreCase = true) ||
                relPath.startsWith("Android/data/", ignoreCase = true) ||
                relPath.equals("Android/obb", ignoreCase = true) ||
                relPath.startsWith("Android/obb/", ignoreCase = true)) {
                return mapOf(
                    "status" to "ACCESS_DENIED",
                    "error" to "Access to protected directory '$relPath' is denied by Android OS security policy.",
                    "storage_mode" to "full_shared_storage",
                    "items" to emptyList<Any>()
                )
            }

            if (!candidate.exists() || !candidate.isDirectory) {
                return mapOf(
                    "status" to "DIRECTORY_NOT_FOUND",
                    "error" to "Directory '$subpath' was not found on phone shared storage.",
                    "storage_mode" to "full_shared_storage",
                    "items" to emptyList<Any>()
                )
            }
            targetDir = candidate
        }

        val items = mutableListOf<Map<String, Any?>>()
        val files = targetDir.listFiles() ?: emptyArray()

        // Sort directories first, then alphabetical
        val sortedFiles = files.sortedWith(compareBy({ !it.isDirectory }, { it.name.lowercase() }))

        for (file in sortedFiles) {
            val name = file.name
            val isHidden = name.startsWith(".")
            if (isHidden && !showHidden) continue

            // Block listing internal Android/data and Android/obb folders
            val relFromRoot = file.canonicalFile.path.removePrefix(canonicalRoot.path).replace('\\', '/').trim('/')
            if (relFromRoot.equals("Android/data", ignoreCase = true) || relFromRoot.equals("Android/obb", ignoreCase = true)) {
                continue
            }

            items.add(mapOf(
                "name" to name,
                "type" to if (file.isDirectory) "directory" else "file",
                "size_bytes" to (if (file.isDirectory) 0L else file.length()),
                "last_modified" to file.lastModified(),
                "is_hidden" to isHidden,
                "path" to relFromRoot
            ))
            if (items.size >= 200) break
        }

        val displayFolder = if (targetDir == canonicalRoot) "Root" else targetDir.name
        return mapOf(
            "status" to "success",
            "storage_mode" to "full_shared_storage",
            "folder_name" to displayFolder,
            "subpath" to (subpath ?: ""),
            "count" to items.size,
            "items" to items
        )
    }

    private fun listSafTree(subpath: String?): Map<String, Any?> {
        val safManager = try {
            org.snow.ui.files.SafFolderManager(context)
        } catch (_: Exception) {
            null
        }
        val treeUri = try {
            safManager?.getDestinationUri()
        } catch (_: Exception) {
            null
        }
        if (treeUri == null || safManager == null) {
            return mapOf(
                "status" to "SAF_FOLDER_NOT_CONFIGURED",
                "error" to "No SAF destination folder has been configured by the user.",
                "remediation_hint" to "Open SNOW Files tab on the phone and pick a destination folder.",
                "storage_mode" to "saf_tree",
                "items" to emptyList<Any>()
            )
        }

        val rootDoc = try {
            androidx.documentfile.provider.DocumentFile.fromTreeUri(context, treeUri)
        } catch (e: Exception) {
            return mapOf(
                "status" to "error",
                "error" to "Failed resolving SAF tree URI: ${e.message}",
                "storage_mode" to "saf_tree",
                "items" to emptyList<Any>()
            )
        }

        if (rootDoc == null || !rootDoc.exists() || !rootDoc.canRead()) {
            return mapOf(
                "status" to "SAF_PERMISSION_REVOKED",
                "error" to "Persisted SAF tree permission has expired or been revoked.",
                "storage_mode" to "saf_tree",
                "items" to emptyList<Any>()
            )
        }

        var targetDoc: androidx.documentfile.provider.DocumentFile = rootDoc
        if (!subpath.isNullOrEmpty()) {
            val segments = subpath.split('/')
            for (segment in segments) {
                if (segment.isBlank() || segment == ".") continue
                if (segment == ".." || segment.contains('\\')) {
                    return mapOf(
                        "status" to "error",
                        "error" to "PATH_TRAVERSAL_DETECTED",
                        "message" to "Relative path traversal '..' is forbidden.",
                        "storage_mode" to "saf_tree"
                    )
                }
                val child = targetDoc.findFile(segment)
                if (child == null || !child.isDirectory) {
                    return mapOf(
                        "status" to "DIRECTORY_NOT_FOUND",
                        "error" to "Subdirectory '$segment' not found in SAF tree.",
                        "storage_mode" to "saf_tree",
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
                "uri" to child.uri.toString(),
                "storage_mode" to "saf_tree"
            ))
            if (items.size >= 100) break
        }

        return mapOf(
            "status" to "success",
            "storage_mode" to "saf_tree",
            "folder_name" to (targetDoc.name ?: safManager?.getDestinationDisplayName() ?: "SAF Folder"),
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

    /**
     * Resolve a regular File on shared internal storage safely with path containment.
     */
    fun resolveSharedStorageFile(subpath: String?, fileName: String): File? {
        if (!isAllFilesAccessGranted()) return null
        val rootDir = Environment.getExternalStorageDirectory() ?: return null
        val canonicalRoot = rootDir.canonicalFile

        val safeFileName = File(fileName).name
        if (safeFileName.isBlank() || safeFileName == "." || safeFileName == ".." || safeFileName.contains('\\')) {
            return null
        }

        val cleanSub = subpath?.trim()?.trim('/')
        if (!cleanSub.isNullOrEmpty()) {
            val segments = cleanSub.split('/')
            for (seg in segments) {
                if (seg.isBlank() || seg == "." || seg == ".." || seg.contains('\\')) return null
            }
        }

        val parentDir = if (cleanSub.isNullOrEmpty()) canonicalRoot else File(canonicalRoot, cleanSub).canonicalFile
        if (!isPathContained(parentDir, canonicalRoot)) return null

        val relPath = parentDir.path.removePrefix(canonicalRoot.path).replace('\\', '/').trim('/')
        if (relPath.equals("Android/data", ignoreCase = true) ||
            relPath.startsWith("Android/data/", ignoreCase = true) ||
            relPath.equals("Android/obb", ignoreCase = true) ||
            relPath.startsWith("Android/obb/", ignoreCase = true)) {
            return null
        }

        val targetFile = File(parentDir, safeFileName).canonicalFile
        if (!isPathContained(targetFile, canonicalRoot)) return null
        return if (targetFile.exists() && targetFile.isFile && targetFile.canRead()) targetFile else null
    }
}
