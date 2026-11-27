package org.snow.ui.files

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Environment
import androidx.documentfile.provider.DocumentFile
import org.snow.security.SafeLog
import java.io.File

/**
 * Storage Access Framework (SAF) folder picker and persisted URI manager for SNOW file downloads.
 */
class SafFolderManager(
    private val context: Context,
    private val fallbackDownloadDirOverride: File? = null,
    private val persistUriPermissionHandler: ((Uri, Int) -> Unit)? = null,
    private val uriAccessValidator: ((Uri) -> Boolean)? = null
) {

    companion object {
        private const val TAG = "SafFolderManager"
        private const val PREFS_NAME = "snow_saf_prefs"
        private const val KEY_DESTINATION_URI = "saf_destination_uri"
        private const val KEY_DESTINATION_NAME = "saf_destination_name"
    }

    private val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    private fun isTreeUriAccessible(uri: Uri): Boolean {
        val validator = uriAccessValidator
        if (validator != null) {
            return try {
                validator.invoke(uri)
            } catch (_: Throwable) {
                false
            }
        }
        return try {
            val doc = DocumentFile.fromTreeUri(context, uri)
            if (doc == null || !doc.exists() || !doc.canRead() || !doc.canWrite()) {
                return false
            }
            val persisted = try {
                context.contentResolver?.persistedUriPermissions
            } catch (_: Throwable) {
                null
            }
            if (persisted != null) {
                persisted.any { it.uri == uri && it.isReadPermission && it.isWritePermission }
            } else {
                true
            }
        } catch (_: Throwable) {
            false
        }
    }

    /**
     * Persist the selected tree URI permission and verify persisted read/write access.
     * Preserves any prior valid selection intact if persistence or verification fails.
     */
    fun persistFolderUri(uri: Uri): Boolean {
        if (!uri.scheme.equals("content", ignoreCase = true) || uri.toString().isBlank()) {
            SafeLog.w(TAG, "Refusing non-content SAF URI: $uri")
            return false
        }
        val flags = Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION
        try {
            if (persistUriPermissionHandler != null) {
                persistUriPermissionHandler.invoke(uri, flags)
            } else {
                val cr = context.contentResolver
                    ?: throw SecurityException("ContentResolver unavailable to persist SAF permission.")
                cr.takePersistableUriPermission(uri, flags)
            }
        } catch (se: SecurityException) {
            SafeLog.w(TAG, "Failed taking persistable SAF permission: ${se.message}")
            return false
        } catch (e: Exception) {
            SafeLog.e(TAG, "Error taking persistable SAF permission: ${e.message}")
            return false
        }

        if (!isTreeUriAccessible(uri)) {
            SafeLog.w(TAG, "Selected SAF URI lacks persisted read/write access: $uri")
            return false
        }

        val displayName = resolveFolderDisplayName(uri)
        prefs.edit()
            .putString(KEY_DESTINATION_URI, uri.toString())
            .putString(KEY_DESTINATION_NAME, displayName)
            .apply()
        SafeLog.i(TAG, "Persisted SAF destination folder: $displayName ($uri)")
        return true
    }

    fun hasValidPersistedFolderUri(): Boolean {
        val uri = getDestinationUri() ?: return false
        return isTreeUriAccessible(uri)
    }

    /**
     * Return the currently configured SAF tree URI, or null if using default downloads.
     */
    fun getDestinationUri(): Uri? {
        val uriStr = prefs.getString(KEY_DESTINATION_URI, null) ?: return null
        return try {
            Uri.parse(uriStr)
        } catch (_: Exception) {
            null
        }
    }

    /**
     * Return a user-friendly display path for the destination folder.
     */
    fun getDestinationDisplayName(): String {
        return prefs.getString(KEY_DESTINATION_NAME, null)
            ?: "Default: Downloads/SNOW"
    }

    /**
     * Reset to default destination directory.
     */
    fun resetToDefault() {
        prefs.edit().clear().apply()
        SafeLog.i(TAG, "Reset SAF destination to default.")
    }

    /**
     * Fallback standard file directory if SAF URI is unset.
     */
    fun getDefaultDownloadDir(): File {
        val publicDownloads = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
        val target = fallbackDownloadDirOverride
            ?: if (publicDownloads != null) {
                File(publicDownloads, "SNOW")
            } else {
                val appExternalDownloads = context.getExternalFilesDir(Environment.DIRECTORY_DOWNLOADS)
                File(appExternalDownloads ?: File(context.filesDir, "downloads"), "SNOW")
            }
        if (!target.exists()) {
            target.mkdirs()
        }
        return target
    }

    /**
     * Internal cache/temp directory for staging streaming chunks before SHA-256 verification.
     */
    fun getStagingDir(): File {
        val dir = File(context.cacheDir, "snow_staging")
        if (!dir.exists()) {
            dir.mkdirs()
        }
        return dir
    }

    /**
     * Commit verified downloaded file bytes to the configured SAF destination directory,
     * or to Downloads/SNOW fallback if no SAF directory was configured.
     *
     * Strict policy: If a SAF directory was configured by user but permission was revoked
     * or inaccessible, reports failure explicitly rather than silently falling back.
     */
    fun commitVerifiedDownload(tempFile: File, fileName: String): Result<String> {
        val configuredSafRaw = prefs.getString(KEY_DESTINATION_URI, null)?.trim()
        if (!configuredSafRaw.isNullOrEmpty()) {
            val safUri = getDestinationUri()
            val pickedDir = safUri?.let { DocumentFile.fromTreeUri(context, it) }
            if (pickedDir == null || !pickedDir.canWrite()) {
                return Result.failure(
                    IllegalStateException(
                        "Configured Transfer Folder is inaccessible or write permission was revoked. Please select a valid folder in Settings."
                    )
                )
            }

            // Handle duplicate filenames safely without overwriting
            val uniqueName = generateUniqueSafName(pickedDir, fileName)
            val destDoc = pickedDir.createFile("application/octet-stream", uniqueName)
                ?: return Result.failure(
                    IllegalStateException("Failed to create destination file in Transfer Folder: $uniqueName")
                )

            return try {
                val outputStream = context.contentResolver.openOutputStream(destDoc.uri)
                    ?: return Result.failure(
                        IllegalStateException("ContentResolver failed to open output stream for: ${destDoc.uri}")
                    )

                outputStream.use { out ->
                    tempFile.inputStream().use { input ->
                        input.copyTo(out)
                    }
                    out.flush()
                }
                tempFile.delete()
                val display = "${getDestinationDisplayName()}/$uniqueName"
                SafeLog.i(TAG, "Successfully committed download to SAF: $display")
                Result.success(display)
            } catch (e: Exception) {
                SafeLog.e(TAG, "Write failure committing to SAF: ${e.message}", e)
                Result.failure(e)
            }
        } else {
            // No custom SAF directory chosen: use Downloads/SNOW fallback
            val fallbackDir = getDefaultDownloadDir()
            if (!fallbackDir.exists() && !fallbackDir.mkdirs()) {
                return Result.failure(
                    IllegalStateException("Failed creating fallback Downloads/SNOW directory.")
                )
            }

            val uniqueTarget = generateUniqueFile(fallbackDir, fileName)
            return try {
                tempFile.inputStream().use { input ->
                    uniqueTarget.outputStream().use { out ->
                        input.copyTo(out)
                        out.flush()
                    }
                }
                tempFile.delete()
                SafeLog.i(TAG, "Committed download to fallback directory: ${uniqueTarget.absolutePath}")
                Result.success(uniqueTarget.absolutePath)
            } catch (e: Exception) {
                SafeLog.e(TAG, "Write failure committing to fallback directory: ${e.message}", e)
                Result.failure(e)
            }
        }
    }

    /**
     * Atomically commit a verified multi-file bundle (1..5 files) to SAF or Downloads/SNOW.
     * Pre-validates destination writability and avoids leaving partial files on failure.
     */
    fun commitVerifiedDownloadBatch(entries: List<Pair<File, String>>): Result<List<String>> {
        if (entries.isEmpty() || entries.size > 5) {
            return Result.failure(IllegalArgumentException("Clipboard bundle must contain 1 to 5 files."))
        }
        val configuredSafRaw = prefs.getString(KEY_DESTINATION_URI, null)?.trim()
        if (!configuredSafRaw.isNullOrEmpty()) {
            val safUri = getDestinationUri()
            val pickedDir = safUri?.let { DocumentFile.fromTreeUri(context, it) }
            if (pickedDir == null || !pickedDir.canWrite()) {
                return Result.failure(
                    IllegalStateException(
                        "Configured Transfer Folder is inaccessible or write permission was revoked. Please select a valid folder in Settings."
                    )
                )
            }
            val createdDocs = mutableListOf<DocumentFile>()
            val committedNames = mutableListOf<String>()
            try {
                for ((tempFile, safeName) in entries) {
                    val uniqueName = generateUniqueSafName(pickedDir, safeName)
                    val destDoc = pickedDir.createFile("application/octet-stream", uniqueName)
                        ?: throw IllegalStateException("Failed to create file in Transfer Folder: $uniqueName")
                    createdDocs.add(destDoc)
                    val outStream = context.contentResolver.openOutputStream(destDoc.uri)
                        ?: throw IllegalStateException("ContentResolver failed opening stream for $uniqueName")
                    outStream.use { out ->
                        tempFile.inputStream().use { input -> input.copyTo(out) }
                        out.flush()
                    }
                    committedNames.add(uniqueName)
                }
                entries.forEach { (tempFile, _) -> tempFile.delete() }
                return Result.success(committedNames)
            } catch (e: Exception) {
                createdDocs.forEach { doc ->
                    try { doc.delete() } catch (_: Exception) {}
                }
                SafeLog.e(TAG, "Batch SAF commit failed; rolled back created entries: ${e.message}", e)
                return Result.failure(e)
            }
        } else {
            val fallbackDir = getDefaultDownloadDir()
            if (!fallbackDir.exists() && !fallbackDir.mkdirs()) {
                return Result.failure(IllegalStateException("Failed creating fallback Downloads/SNOW directory."))
            }
            val createdFiles = mutableListOf<File>()
            val committedPaths = mutableListOf<String>()
            try {
                for ((tempFile, safeName) in entries) {
                    val uniqueTarget = generateUniqueFile(fallbackDir, safeName)
                    tempFile.inputStream().use { input ->
                        uniqueTarget.outputStream().use { out ->
                            input.copyTo(out)
                            out.flush()
                        }
                    }
                    createdFiles.add(uniqueTarget)
                    committedPaths.add(uniqueTarget.name)
                }
                entries.forEach { (tempFile, _) -> tempFile.delete() }
                return Result.success(committedPaths)
            } catch (e: Exception) {
                createdFiles.forEach { f ->
                    try { f.delete() } catch (_: Exception) {}
                }
                SafeLog.e(TAG, "Batch fallback commit failed; rolled back created files: ${e.message}", e)
                return Result.failure(e)
            }
        }
    }

    private fun generateUniqueSafName(dir: DocumentFile, baseName: String): String {
        if (dir.findFile(baseName) == null) return baseName

        val dotIndex = baseName.lastIndexOf('.')
        val nameWithoutExt = if (dotIndex > 0) baseName.substring(0, dotIndex) else baseName
        val ext = if (dotIndex > 0) baseName.substring(dotIndex) else ""

        var counter = 1
        while (counter < 1000) {
            val candidate = "$nameWithoutExt ($counter)$ext"
            if (dir.findFile(candidate) == null) {
                return candidate
            }
            counter++
        }
        return "${nameWithoutExt}_${System.currentTimeMillis()}$ext"
    }

    private fun generateUniqueFile(dir: File, baseName: String): File {
        val direct = File(dir, baseName)
        if (!direct.exists()) return direct

        val dotIndex = baseName.lastIndexOf('.')
        val nameWithoutExt = if (dotIndex > 0) baseName.substring(0, dotIndex) else baseName
        val ext = if (dotIndex > 0) baseName.substring(dotIndex) else ""

        var counter = 1
        while (counter < 1000) {
            val candidate = File(dir, "$nameWithoutExt ($counter)$ext")
            if (!candidate.exists()) {
                return candidate
            }
            counter++
        }
        return File(dir, "${nameWithoutExt}_${System.currentTimeMillis()}$ext")
    }

    private fun resolveFolderDisplayName(uri: Uri): String {
        try {
            val doc = DocumentFile.fromTreeUri(context, uri)
            val docName = doc?.name
            if (!docName.isNullOrBlank()) {
                return docName
            }
        } catch (_: Exception) {}

        val path = uri.path ?: return uri.toString()
        val decoded = Uri.decode(path)
        val colonIndex = decoded.lastIndexOf(':')
        if (colonIndex != -1 && colonIndex < decoded.length - 1) {
            val seg = decoded.substring(colonIndex + 1).trim('/')
            if (seg.isNotBlank()) return seg
        }
        val slashIndex = decoded.lastIndexOf('/')
        if (slashIndex != -1 && slashIndex < decoded.length - 1) {
            val seg = decoded.substring(slashIndex + 1).trim('/')
            if (seg.isNotBlank()) return seg
        }
        return decoded
    }
}
