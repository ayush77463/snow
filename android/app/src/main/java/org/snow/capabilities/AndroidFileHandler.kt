package org.snow.capabilities

import android.content.ContentValues
import android.content.Context
import android.os.Build
import android.os.Environment
import android.provider.MediaStore
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.snow.security.SafeLog
import org.snow.transfer.FileTransferClient
import org.snow.ui.files.SafFolderManager
import java.io.File
import java.util.concurrent.ConcurrentHashMap

/**
 * Android bidirectional file transfer capability handler.
 *
 * Implements Sub-Milestone 6.5:
 * - Directs incoming desktop files into app-scoped storage via FileTransferClient.downloadFile.
 * - Uploads requested Android files to Desktop Core via FileTransferClient.uploadFile.
 * - Strictly enforces scoped path containment and 64 KiB streaming chunk digests.
 * - Reuses existing Phase 3 authenticated HTTPS streaming infrastructure on port 8766.
 */
class AndroidFileHandler @JvmOverloads constructor(
    private val context: Context,
    private val transferClientProvider: () -> FileTransferClient?,
    private val storageRootDirProvider: (() -> File?)? = null,
    private val allFilesAccessProvider: (() -> Boolean)? = null,
    internal val safNodeProviderOverride: (() -> SafNode?)? = null
) {
    interface SafNode {
        val name: String?
        val isDirectory: Boolean
        val isFile: Boolean
        val length: Long
        val lastModified: Long
        val canRead: Boolean
        val canWrite: Boolean
        val exists: Boolean
        fun findChild(displayName: String): SafNode?
        fun listChildren(): List<SafNode>
        fun createChildFile(mimeType: String, displayName: String): SafNode?
        fun createChildDirectory(displayName: String): SafNode?
        fun openInputStream(): java.io.InputStream?
        fun openOutputStream(truncate: Boolean): java.io.OutputStream?
    }

    private inner class DocumentFileSafNode(
        private val doc: androidx.documentfile.provider.DocumentFile
    ) : SafNode {
        override val name: String? get() = doc.name
        override val isDirectory: Boolean get() = doc.isDirectory
        override val isFile: Boolean get() = doc.isFile
        override val length: Long get() = doc.length()
        override val lastModified: Long get() = doc.lastModified()
        override val canRead: Boolean get() = doc.canRead()
        override val canWrite: Boolean get() = doc.canWrite()
        override val exists: Boolean get() = doc.exists()
        override fun findChild(displayName: String): SafNode? = doc.findFile(displayName)?.let { DocumentFileSafNode(it) }
        override fun listChildren(): List<SafNode> = doc.listFiles().map { DocumentFileSafNode(it) }
        override fun createChildFile(mimeType: String, displayName: String): SafNode? =
            doc.createFile(mimeType, displayName)?.let { DocumentFileSafNode(it) }
        override fun createChildDirectory(displayName: String): SafNode? =
            doc.createDirectory(displayName)?.let { DocumentFileSafNode(it) }
        override fun openInputStream(): java.io.InputStream? = context.contentResolver?.openInputStream(doc.uri)
        override fun openOutputStream(truncate: Boolean): java.io.OutputStream? =
            if (truncate) {
                try { context.contentResolver?.openOutputStream(doc.uri, "wt") } catch (_: Exception) {
                    context.contentResolver?.openOutputStream(doc.uri)
                }
            } else {
                context.contentResolver?.openOutputStream(doc.uri)
            }
    }
    private val fileScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val activeDownloadJobs = ConcurrentHashMap<String, Job>()
    private val cancelledTransferIds = ConcurrentHashMap.newKeySet<String>()

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

    fun cancelTransfer(transferId: String): Boolean {
        val cleanId = transferId.trim()
        if (cleanId.isEmpty()) return false
        cancelledTransferIds.add(cleanId)
        val job = activeDownloadJobs.remove(cleanId)
        job?.cancel()
        transferClientProvider()?.cancelTransfer(cleanId)
        val stagingDir = try {
            SafFolderManager(context).getStagingDir()
        } catch (_: Exception) {
            getTransfersDirectory()
        }
        stagingDir.listFiles { f -> f.isFile && f.name.startsWith("${cleanId}_") }?.forEach { f ->
            try { f.delete() } catch (_: Exception) {}
        }
        return job != null || cancelledTransferIds.contains(cleanId)
    }

    /**
     * Handle desktop -> Android file transmission request.
     */
    suspend fun handleFileSendRequest(
        data: Map<String, Any?>?,
        serverHost: String,
        defaultTransferPort: Int,
        completionNotifier: ((Map<String, Any?>) -> Unit)? = null
    ): Map<String, Any?> = withContext(Dispatchers.IO) {
        if (data == null) {
            return@withContext mapOf("status" to "error", "error" to "Missing transfer payload.")
        }

        val transferId = data["transfer_id"] as? String
        val rawFileName = data["file_name"] as? String
        val expectedSha256 = data["sha256"] as? String
        val transferPort = (data["transfer_port"] as? Number)?.toInt() ?: defaultTransferPort
        val isAsync = data["async"] == true

        if (transferId.isNullOrBlank() || rawFileName.isNullOrBlank() || expectedSha256.isNullOrBlank()) {
            return@withContext mapOf(
                "status" to "error",
                "error" to "Missing required fields: transfer_id, file_name, or sha256."
            )
        }

        if (cancelledTransferIds.contains(transferId)) {
            return@withContext mapOf("status" to "error", "transfer_id" to transferId, "error" to "Transfer already cancelled.")
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

        suspend fun executeDownloadAndCommit(): Map<String, Any?> {
            val safManager = try {
                SafFolderManager(context)
            } catch (_: Exception) {
                null
            }
            val safUri = try {
                safManager?.getDestinationUri()
            } catch (_: Exception) {
                null
            }
            val stagingDir = try {
                safManager?.getStagingDir() ?: File(context.cacheDir, "snow_staging").apply { mkdirs() }
            } catch (_: Exception) {
                getTransfersDirectory()
            }
            val stagedFile = File(stagingDir, "${transferId}_$safeFileName")

            SafeLog.i(TAG, "Downloading incoming file '$safeFileName' [transfer_id=$transferId]...")
            val result = client.downloadFile(
                serverHost = serverHost,
                transferPort = transferPort,
                transferId = transferId,
                destinationFile = stagedFile,
                expectedSha256 = expectedSha256,
                resume = true
            )

            return when (result) {
                is FileTransferClient.TransferResult.Success -> {
                    val expectedBytes = stagedFile.length()
                    val commitOutcome = commitDownloadedFile(
                        stagedFile = stagedFile,
                        safeFileName = safeFileName,
                        expectedBytes = expectedBytes,
                        safManager = safManager,
                        hasConfiguredSaf = (safUri != null),
                    )
                    if (commitOutcome.isFailure) {
                        try { stagedFile.delete() } catch (_: Exception) {}
                        val errMsg = commitOutcome.exceptionOrNull()?.message ?: "Failed saving downloaded file."
                        SafeLog.e(TAG, "Commit failed for '$safeFileName': $errMsg")
                        mapOf(
                            "status" to "error",
                            "transfer_id" to transferId,
                            "error" to errMsg
                        )
                    } else {
                        val (savedPath, storageMode) = commitOutcome.getOrThrow()
                        SafeLog.i(TAG, "Download successful [$storageMode]: $savedPath ($expectedBytes bytes)")
                        mapOf(
                            "status" to "success",
                            "transfer_id" to transferId,
                            "file_name" to safeFileName,
                            "bytes_downloaded" to expectedBytes,
                            "sha256" to result.sha256,
                            "saved_path" to savedPath,
                            "storage_mode" to storageMode,
                        )
                    }
                }
                is FileTransferClient.TransferResult.Duplicate -> {
                    val bytes = if (stagedFile.exists()) stagedFile.length() else 0L
                    val commitOutcome = if (stagedFile.exists()) {
                        commitDownloadedFile(
                            stagedFile = stagedFile,
                            safeFileName = safeFileName,
                            expectedBytes = bytes,
                            safManager = safManager,
                            hasConfiguredSaf = (safUri != null),
                        )
                    } else {
                        val defaultDisplay = safManager?.getDestinationDisplayName() ?: "Downloads/SNOW"
                        Result.success(defaultDisplay to if (safUri != null) "saf_tree" else "public_downloads")
                    }
                    if (commitOutcome.isFailure) {
                        try { stagedFile.delete() } catch (_: Exception) {}
                        val errMsg = commitOutcome.exceptionOrNull()?.message ?: "Failed saving duplicate file."
                        mapOf(
                            "status" to "error",
                            "transfer_id" to transferId,
                            "error" to errMsg
                        )
                    } else {
                        val (savedPath, storageMode) = commitOutcome.getOrThrow()
                        mapOf(
                            "status" to "success",
                            "transfer_id" to transferId,
                            "file_name" to safeFileName,
                            "bytes_downloaded" to bytes,
                            "sha256" to result.sha256,
                            "saved_path" to savedPath,
                            "storage_mode" to storageMode,
                            "message" to "File already exists with matching SHA-256."
                        )
                    }
                }
                is FileTransferClient.TransferResult.Error -> {
                    try { stagedFile.delete() } catch (_: Exception) {}
                    SafeLog.e(TAG, "Download failed: ${result.message}")
                    mapOf(
                        "status" to "error",
                        "transfer_id" to transferId,
                        "error" to result.message
                    )
                }
            }
        }

        if (isAsync) {
            val job = fileScope.launch {
                try {
                    val finalRes = executeDownloadAndCommit()
                    val statusOut = if (cancelledTransferIds.contains(transferId)) {
                        "CANCELLED"
                    } else if (finalRes["status"] == "success") {
                        "COMPLETED"
                    } else {
                        "FAILED"
                    }
                    completionNotifier?.invoke(
                        mapOf(
                            "transfer_id" to transferId,
                            "status" to statusOut,
                            "sha256" to (finalRes["sha256"] ?: expectedSha256),
                            "saved_path" to finalRes["saved_path"],
                            "error" to finalRes["error"]
                        )
                    )
                } catch (ce: kotlinx.coroutines.CancellationException) {
                    completionNotifier?.invoke(
                        mapOf("transfer_id" to transferId, "status" to "CANCELLED")
                    )
                    throw ce
                } catch (e: Exception) {
                    completionNotifier?.invoke(
                        mapOf("transfer_id" to transferId, "status" to "FAILED", "error" to e.message)
                    )
                } finally {
                    activeDownloadJobs.remove(transferId)
                }
            }
            activeDownloadJobs[transferId] = job
            return@withContext mapOf(
                "status" to "accepted",
                "accepted" to true,
                "transfer_id" to transferId,
                "file_name" to safeFileName
            )
        }

        return@withContext executeDownloadAndCommit()
    }

    private fun commitDownloadedFile(
        stagedFile: File,
        safeFileName: String,
        expectedBytes: Long,
        safManager: SafFolderManager?,
        hasConfiguredSaf: Boolean,
    ): Result<Pair<String, String>> {
        if (!stagedFile.exists()) {
            return Result.failure(IllegalStateException("Staged transfer file missing before destination commit."))
        }

        // 1. User-configured SAF directory takes strict precedence when configured
        if (hasConfiguredSaf && safManager != null) {
            val safRes = safManager.commitVerifiedDownload(stagedFile, safeFileName)
            return safRes.map { saved -> saved to "saf_tree" }
        }

        // 2. Supported public Downloads/SNOW destination via MediaStore (Android 10+ / scoped storage safe)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            val resolver = try { context.contentResolver } catch (_: Exception) { null }
            if (resolver != null) {
                try {
                    val values = ContentValues().apply {
                        put(MediaStore.Downloads.DISPLAY_NAME, safeFileName)
                        put(MediaStore.Downloads.MIME_TYPE, "application/octet-stream")
                        put(MediaStore.Downloads.RELATIVE_PATH, "${Environment.DIRECTORY_DOWNLOADS}/SNOW")
                        put(MediaStore.Downloads.IS_PENDING, 1)
                    }
                    val itemUri = resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values)
                    if (itemUri != null) {
                        var copied = 0L
                        resolver.openOutputStream(itemUri)?.use { out ->
                            stagedFile.inputStream().use { input ->
                                copied = input.copyTo(out)
                            }
                            out.flush()
                        } ?: throw IllegalStateException("ContentResolver output stream unavailable")
                        if (copied != expectedBytes) {
                            resolver.delete(itemUri, null, null)
                            throw IllegalStateException("Incomplete MediaStore write ($copied/$expectedBytes bytes)")
                        }
                        val publishValues = ContentValues().apply {
                            put(MediaStore.Downloads.IS_PENDING, 0)
                        }
                        resolver.update(itemUri, publishValues, null, null)
                        stagedFile.delete()
                        return Result.success("Downloads/SNOW/$safeFileName" to "public_downloads")
                    }
                } catch (e: Exception) {
                    SafeLog.w(TAG, "MediaStore Downloads save fell back: ${e.message}")
                }
            }
        }

        // 3. Direct public Downloads/SNOW file commit (or SAF fallback if available)
        if (safManager != null) {
            val directRes = safManager.commitVerifiedDownload(stagedFile, safeFileName)
            if (directRes.isSuccess) {
                return directRes.map { saved -> saved to "public_downloads" }
            }
        }

        // 4. Last-resort verified app-scoped fallback (primarily for constrained test hosts)
        val fallbackDir = getTransfersDirectory()
        val targetFile = File(fallbackDir, safeFileName)
        return try {
            stagedFile.inputStream().use { input ->
                targetFile.outputStream().use { out ->
                    input.copyTo(out)
                    out.flush()
                }
            }
            if (!targetFile.exists() || targetFile.length() != expectedBytes) {
                return Result.failure(IllegalStateException("Destination file write verification failed."))
            }
            stagedFile.delete()
            Result.success(targetFile.absolutePath to "app_transfers")
        } catch (e: Exception) {
            Result.failure(e)
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

        val requestedScope = data["scope"] as? String
        val principal = data["principal"] as? String ?: "AI_MCP"
        val subpath = data["subpath"] as? String

        val isFullStorageEligible = isAllFilesAccessGranted() && principal == "OWNER_MANUAL" && requestedScope != "saf"

        // 1. If eligible, resolve from full shared internal storage
        if (isFullStorageEligible) {
            val sharedFile = resolveSharedStorageFile(subpath, safeFileName)
            if (sharedFile != null && sharedFile.exists() && sharedFile.isFile) {
                val client = transferClientProvider()
                if (client == null) {
                    return@withContext mapOf("status" to "error", "error" to "FileTransferClient not initialized.")
                }
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
            val client = transferClientProvider()
            if (client == null) {
                return@withContext mapOf("status" to "error", "error" to "FileTransferClient not initialized.")
            }
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
     * Check whether direct full-storage mode is overridden (SAF folder mode is used by default).
     */
    fun isAllFilesAccessGranted(): Boolean {
        if (allFilesAccessProvider != null) {
            return allFilesAccessProvider.invoke()
        }
        return false
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

        if (isFullStorageEligible && (requestedScope == "full" || requestedScope == "auto" || requestedScope == null)) {
            return listFullSharedStorage(subpath, showHidden)
        }

        // Fallback to SAF DocumentFile Tree
        return listSafTree(subpath)
    }

    private fun listFullSharedStorage(subpath: String?, showHidden: Boolean): Map<String, Any?> {
        val rootDir = storageRootDirProvider?.invoke() ?: Environment.getExternalStorageDirectory()
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
                "error" to "No Transfer Folder has been configured by the user.",
                "remediation_hint" to "Open SNOW Settings or Files tab on the phone and choose a Transfer Folder.",
                "storage_mode" to "saf_tree",
                "items" to emptyList<Any>()
            )
        }

        val rootDoc = try {
            androidx.documentfile.provider.DocumentFile.fromTreeUri(context, treeUri)
        } catch (e: Exception) {
            return mapOf(
                "status" to "error",
                "error" to "Failed resolving Transfer Folder URI: ${e.message}",
                "storage_mode" to "saf_tree",
                "items" to emptyList<Any>()
            )
        }

        if (rootDoc == null || !rootDoc.exists() || !rootDoc.canRead()) {
            return mapOf(
                "status" to "SAF_PERMISSION_REVOKED",
                "error" to "Persisted Transfer Folder permission has expired or been revoked.",
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
            "folder_name" to (targetDoc.name ?: safManager?.getDestinationDisplayName() ?: "Transfer Folder"),
            "subpath" to (subpath ?: ""),
            "count" to items.size,
            "items" to items
        )
    }

    /**
     * Resolve a file DocumentFile safely within the persisted SAF tree.
     */
    fun resolveSafDocument(subpath: String?, fileName: String): androidx.documentfile.provider.DocumentFile? {
        val safManager = try {
            org.snow.ui.files.SafFolderManager(context)
        } catch (_: Exception) {
            null
        }
        val treeUri = try {
            safManager?.getDestinationUri()
        } catch (_: Exception) {
            null
        } ?: return null
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
        val rootDir = storageRootDirProvider?.invoke() ?: Environment.getExternalStorageDirectory() ?: return null
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

    private fun resolveSafRootForM44(requireWrite: Boolean): Pair<SafNode?, Map<String, Any?>?> {
        safNodeProviderOverride?.let { override ->
            val root = try { override.invoke() } catch (_: Exception) { null }
            if (root == null || !root.exists || !root.canRead || (requireWrite && !root.canWrite)) {
                return null to mapOf(
                    "status" to "SAF_PERMISSION_REVOKED",
                    "error" to "Configured Transfer Folder is missing read/write permission.",
                    "storage_mode" to "saf_tree"
                )
            }
            return root to null
        }

        val safManager = try {
            org.snow.ui.files.SafFolderManager(context)
        } catch (_: Exception) {
            null
        }
        val treeUri = try {
            safManager?.getDestinationUri()
        } catch (_: Exception) {
            null
        } ?: return null to mapOf(
            "status" to "SAF_FOLDER_NOT_CONFIGURED",
            "error" to "No Transfer Folder has been configured by the user.",
            "remediation_hint" to "Open SNOW Settings or Files tab on Android and choose a Transfer Folder.",
            "storage_mode" to "saf_tree"
        )

        val rootDoc = try {
            androidx.documentfile.provider.DocumentFile.fromTreeUri(context, treeUri)
        } catch (e: Exception) {
            null
        }
        if (rootDoc == null || !rootDoc.exists() || !rootDoc.canRead() || (requireWrite && !rootDoc.canWrite())) {
            return null to mapOf(
                "status" to "SAF_PERMISSION_REVOKED",
                "error" to "Persisted Transfer Folder permission expired or was revoked.",
                "remediation_hint" to "Re-select the Transfer Folder in SNOW Android Settings or Files tab.",
                "storage_mode" to "saf_tree"
            )
        }
        return DocumentFileSafNode(rootDoc) to null
    }

    private fun validateRelativeSafSegments(rawPath: String?, allowEmpty: Boolean = false): Pair<List<String>?, Map<String, Any?>?> {
        if (rawPath == null) {
            return if (allowEmpty) emptyList<String>() to null else null to mapOf(
                "status" to "INVALID_PATH",
                "error" to "A valid relative folder path is required."
            )
        }
        val trimmed = rawPath.trim()
        if (trimmed.isEmpty()) {
            return if (allowEmpty) emptyList<String>() to null else null to mapOf(
                "status" to "INVALID_PATH",
                "error" to "Relative folder path must be non-empty."
            )
        }
        if (trimmed.startsWith("/") || trimmed.contains('\\') || trimmed.contains('\u0000') || trimmed.any { it.code < 32 }) {
            return null to mapOf(
                "status" to "PATH_TRAVERSAL_DETECTED",
                "error" to "Absolute paths, backslashes, null bytes, and control characters are forbidden."
            )
        }
        val lower = trimmed.lowercase()
        if (lower.contains("%2e") || lower.contains("%2f") || lower.contains("%5c") || lower.contains("%25") || lower.contains("%00")) {
            return null to mapOf(
                "status" to "PATH_TRAVERSAL_DETECTED",
                "error" to "Percent-encoded traversal or separator sequences are forbidden."
            )
        }
        val rawSegments = trimmed.split('/')
        if (rawSegments.any { it.isEmpty() || it == "." || it == ".." }) {
            return null to mapOf(
                "status" to "PATH_TRAVERSAL_DETECTED",
                "error" to "Path traversal segments (., .., or empty segments) are forbidden."
            )
        }
        return rawSegments to null
    }

    fun readSafTextFile(data: Map<String, Any?>?): Map<String, Any?> {
        val rawPath = data?.get("path") as? String
        val (segments, pathErr) = validateRelativeSafSegments(rawPath, allowEmpty = false)
        if (pathErr != null || segments == null || segments.isEmpty()) {
            return pathErr ?: mapOf("status" to "INVALID_PATH", "error" to "Invalid relative path.")
        }
        val (rootDoc, safErr) = resolveSafRootForM44(requireWrite = false)
        if (safErr != null || rootDoc == null) {
            return safErr ?: mapOf("status" to "SAF_FOLDER_NOT_CONFIGURED", "error" to "Transfer Folder not configured.")
        }

        var current: SafNode = rootDoc
        for (i in 0 until segments.size - 1) {
            val child = current.findChild(segments[i])
            if (child == null || !child.exists || !child.isDirectory) {
                return mapOf("status" to "FILE_NOT_FOUND", "error" to "Directory '${segments[i]}' not found in Transfer Folder.")
            }
            current = child
        }
        val target = current.findChild(segments.last())
        if (target == null || !target.exists || !target.isFile) {
            return mapOf("status" to "FILE_NOT_FOUND", "error" to "File '${segments.joinToString("/")}' not found in Transfer Folder.")
        }

        val maxBytes = 256 * 1024 // 256 KiB cap
        val inputStream = try {
            target.openInputStream()
        } catch (e: Exception) {
            return mapOf("status" to "READ_FAILED", "error" to "Failed opening file stream: ${e.message}")
        } ?: return mapOf("status" to "READ_FAILED", "error" to "Unable to open input stream for Transfer Folder file.")

        val rawBytes = try {
            inputStream.use { stream ->
                val baos = java.io.ByteArrayOutputStream()
                val buf = ByteArray(8192)
                var total = 0
                while (true) {
                    val read = stream.read(buf)
                    if (read <= 0) break
                    total += read
                    if (total > maxBytes) {
                        return mapOf(
                            "status" to "FILE_TOO_LARGE",
                            "error" to "File exceeds maximum 256 KiB text read limit."
                        )
                    }
                    baos.write(buf, 0, read)
                }
                baos.toByteArray()
            }
        } catch (e: Exception) {
            return mapOf("status" to "READ_FAILED", "error" to "Failed reading SAF file: ${e.message}")
        }

        val decodedText = try {
            val decoder = Charsets.UTF_8.newDecoder()
                .onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
                .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT)
            val txt = decoder.decode(java.nio.ByteBuffer.wrap(rawBytes)).toString()
            if (txt.contains('\u0000')) {
                return mapOf("status" to "BINARY_OR_INVALID_UTF8", "error" to "Binary file containing NUL bytes cannot be read as UTF-8 text.")
            }
            txt
        } catch (_: java.nio.charset.CharacterCodingException) {
            return mapOf("status" to "BINARY_OR_INVALID_UTF8", "error" to "File is binary or not valid UTF-8 text.")
        }

        return mapOf(
            "status" to "success",
            "path" to segments.joinToString("/"),
            "name" to (target.name ?: segments.last()),
            "size_bytes" to rawBytes.size,
            "content" to decodedText,
            "storage_mode" to "saf_tree"
        )
    }

    fun writeSafTextFile(data: Map<String, Any?>?): Map<String, Any?> {
        val rawPath = data?.get("path") as? String
        val content = data?.get("content") as? String
            ?: return mapOf("status" to "INVALID_ARGUMENT", "error" to "'content' string is required.")
        val overwrite = (data["overwrite"] as? Boolean) == true

        val (segments, pathErr) = validateRelativeSafSegments(rawPath, allowEmpty = false)
        if (pathErr != null || segments == null || segments.isEmpty()) {
            return pathErr ?: mapOf("status" to "INVALID_PATH", "error" to "Invalid relative path.")
        }

        val maxBytes = 256 * 1024
        val contentBytes = content.toByteArray(Charsets.UTF_8)
        if (contentBytes.size > maxBytes) {
            return mapOf(
                "status" to "FILE_TOO_LARGE",
                "error" to "Content exceeds 256 KiB write limit (${contentBytes.size} bytes)."
            )
        }

        val (rootDoc, safErr) = resolveSafRootForM44(requireWrite = true)
        if (safErr != null || rootDoc == null) {
            return safErr ?: mapOf("status" to "SAF_FOLDER_NOT_CONFIGURED", "error" to "Writable SAF folder not configured.")
        }

        var parentDoc: SafNode = rootDoc
        for (i in 0 until segments.size - 1) {
            val seg = segments[i]
            val existingDir = parentDoc.findChild(seg)
            parentDoc = if (existingDir == null) {
                parentDoc.createChildDirectory(seg)
                    ?: return mapOf("status" to "WRITE_FAILED", "error" to "Failed creating SAF subdirectory '$seg'.")
            } else if (existingDir.isDirectory) {
                existingDir
            } else {
                return mapOf("status" to "PATH_NOT_DIRECTORY", "error" to "Path segment '$seg' is an existing file, not a directory.")
            }
        }

        val fileName = segments.last()
        val existingFile = parentDoc.findChild(fileName)
        val outcome: String
        val targetDoc: SafNode
        if (existingFile != null) {
            if (existingFile.isDirectory) {
                return mapOf("status" to "IS_A_DIRECTORY", "error" to "Target '$fileName' is an existing directory.")
            }
            if (!overwrite) {
                return mapOf(
                    "status" to "FILE_EXISTS",
                    "error" to "File '${segments.joinToString("/")}' already exists and overwrite is false."
                )
            }
            targetDoc = existingFile
            outcome = "updated"
        } else {
            targetDoc = parentDoc.createChildFile("text/plain", fileName)
                ?: return mapOf("status" to "WRITE_FAILED", "error" to "Failed creating SAF file '$fileName'.")
            outcome = "created"
        }

        val outStream = try {
            targetDoc.openOutputStream(truncate = (outcome == "updated"))
        } catch (e: Exception) {
            return mapOf("status" to "WRITE_FAILED", "error" to "Failed opening SAF output stream: ${e.message}")
        } ?: return mapOf("status" to "WRITE_FAILED", "error" to "Unable to open output stream for SAF write.")

        return try {
            outStream.use { out ->
                out.write(contentBytes)
                out.flush()
            }
            mapOf(
                "status" to "success",
                "outcome" to outcome,
                "path" to segments.joinToString("/"),
                "name" to (targetDoc.name ?: fileName),
                "bytes_written" to contentBytes.size,
                "storage_mode" to "saf_tree"
            )
        } catch (e: Exception) {
            mapOf("status" to "WRITE_FAILED", "error" to "Transfer Folder write failed: ${e.message}")
        }
    }

    fun searchSafFileNames(data: Map<String, Any?>?): Map<String, Any?> {
        val rawQuery = (data?.get("query") as? String)?.trim().orEmpty()
        if (rawQuery.isEmpty() || rawQuery.length > 128) {
            return mapOf("status" to "INVALID_ARGUMENT", "error" to "'query' must be 1..128 characters.")
        }
        val rawSubpath = data?.get("subpath") as? String
        val (subSegments, pathErr) = validateRelativeSafSegments(rawSubpath, allowEmpty = true)
        if (pathErr != null || subSegments == null) {
            return pathErr ?: mapOf("status" to "INVALID_PATH", "error" to "Invalid subpath.")
        }

        val maxResults = ((data?.get("max_results") as? Number)?.toInt() ?: 25).coerceIn(1, 50)
        val maxDepth = ((data?.get("max_depth") as? Number)?.toInt() ?: 3).coerceIn(1, 5)
        val maxVisited = 1000
        val deadlineMs = System.currentTimeMillis() + 3_000L

        val (rootDoc, safErr) = resolveSafRootForM44(requireWrite = false)
        if (safErr != null || rootDoc == null) {
            return safErr ?: mapOf("status" to "SAF_FOLDER_NOT_CONFIGURED", "error" to "Transfer Folder not configured.")
        }

        var startDoc: SafNode = rootDoc
        for (seg in subSegments) {
            val child = startDoc.findChild(seg)
            if (child == null || !child.exists || !child.isDirectory) {
                return mapOf("status" to "DIRECTORY_NOT_FOUND", "error" to "Subdirectory '$seg' not found in Transfer Folder.")
            }
            startDoc = child
        }

        val queue = ArrayDeque<Triple<SafNode, String, Int>>()
        queue.addLast(Triple(startDoc, subSegments.joinToString("/"), 0))
        val matches = mutableListOf<Map<String, Any?>>()
        var visited = 0
        var truncated = false
        val needle = rawQuery.lowercase()

        while (queue.isNotEmpty()) {
            if (System.currentTimeMillis() > deadlineMs || visited >= maxVisited || matches.size >= maxResults) {
                truncated = true
                break
            }
            val (dirDoc, prefix, depth) = queue.removeFirst()
            val children = try { dirDoc.listChildren() } catch (_: Exception) { emptyList() }
            for (child in children) {
                visited++
                val name = child.name ?: continue
                val rel = if (prefix.isEmpty()) name else "$prefix/$name"
                if (name.lowercase().contains(needle)) {
                    matches.add(
                        mapOf(
                            "path" to rel,
                            "name" to name,
                            "type" to if (child.isDirectory) "directory" else "file",
                            "size_bytes" to if (child.isDirectory) 0L else child.length,
                            "last_modified" to child.lastModified
                        )
                    )
                    if (matches.size >= maxResults) {
                        truncated = true
                        break
                    }
                }
                if (child.isDirectory && depth + 1 < maxDepth) {
                    queue.addLast(Triple(child, rel, depth + 1))
                }
                if (visited >= maxVisited || System.currentTimeMillis() > deadlineMs) {
                    truncated = true
                    break
                }
            }
        }

        return mapOf(
            "status" to "success",
            "query" to rawQuery,
            "count" to matches.size,
            "truncated" to truncated,
            "matches" to matches,
            "storage_mode" to "saf_tree"
        )
    }
}
