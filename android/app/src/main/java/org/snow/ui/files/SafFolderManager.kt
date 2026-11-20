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
class SafFolderManager(private val context: Context) {

    companion object {
        private const val TAG = "SafFolderManager"
        private const val PREFS_NAME = "snow_saf_prefs"
        private const val KEY_DESTINATION_URI = "saf_destination_uri"
        private const val KEY_DESTINATION_NAME = "saf_destination_name"
    }

    private val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    /**
     * Persist the selected tree URI permission and store it across app restarts.
     */
    fun persistFolderUri(uri: Uri): Boolean {
        return try {
            val flags = Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION
            try {
                context.contentResolver.takePersistableUriPermission(uri, flags)
            } catch (e: SecurityException) {
                SafeLog.w(TAG, "Failed taking persistable permission: ${e.message}")
            }

            val displayName = resolveFolderDisplayName(uri)
            prefs.edit()
                .putString(KEY_DESTINATION_URI, uri.toString())
                .putString(KEY_DESTINATION_NAME, displayName)
                .apply()
            SafeLog.i(TAG, "Persisted SAF destination folder: $displayName ($uri)")
            true
        } catch (e: Exception) {
            SafeLog.e(TAG, "Error persisting SAF destination URI: ${e.message}")
            false
        }
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
        val target = File(publicDownloads, "SNOW")
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
        val safUri = getDestinationUri()
        if (safUri != null) {
            // User configured a custom SAF tree directory
            val pickedDir = DocumentFile.fromTreeUri(context, safUri)
            if (pickedDir == null || !pickedDir.canWrite()) {
                return Result.failure(
                    IllegalStateException(
                        "Configured SAF destination directory is inaccessible or write permission was revoked. Please select a valid folder in Settings."
                    )
                )
            }

            // Handle duplicate filenames safely without overwriting
            val uniqueName = generateUniqueSafName(pickedDir, fileName)
            val destDoc = pickedDir.createFile("application/octet-stream", uniqueName)
                ?: return Result.failure(
                    IllegalStateException("Failed to create destination file in SAF directory: $uniqueName")
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
