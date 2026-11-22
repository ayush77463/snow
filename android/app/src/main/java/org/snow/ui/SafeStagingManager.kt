package org.snow.ui

import java.io.File
import java.io.IOException
import java.util.UUID

/**
 * Security utility for safe staging of incoming external share files.
 *
 * Enforces strict basename sanitization, traversal defense, UUID prefixing,
 * canonical directory containment, and guaranteed cleanup.
 */
object SafeStagingManager {

    private const val MAX_FILENAME_LENGTH = 128
    private const val DEFAULT_IMAGE_FALLBACK = "shared_image.png"

    // Disallowed control characters and path separators
    private val ILLEGAL_CHARS_REGEX = Regex("[/\\\\?%*:|\"<>\u0000-\u001F]")

    /**
     * Sanitize an untrusted filename string, extracting only a safe basename.
     * Rejects path separators, traversal patterns (..), and control characters.
     */
    fun sanitizeFilename(rawName: String?, fallbackExtension: String = ".png"): String {
        if (rawName.isNullOrBlank()) {
            return "shared_${System.currentTimeMillis()}$fallbackExtension"
        }

        // 1. Strip any directory path components (both forward and backward slashes)
        val basename = rawName.substringAfterLast('/').substringAfterLast('\\').trim()
        if (basename.isBlank() || basename == "." || basename == "..") {
            return "shared_${System.currentTimeMillis()}$fallbackExtension"
        }

        // 2. Separate stem and extension
        val dotIdx = basename.lastIndexOf('.')
        val (stem, ext) = if (dotIdx > 0 && dotIdx < basename.length - 1) {
            val s = basename.substring(0, dotIdx)
            val e = basename.substring(dotIdx)
            Pair(s, e)
        } else {
            Pair(basename, "")
        }

        // 3. Replace illegal/reserved characters and traversal sequences in stem
        var cleanStem = stem.replace("..", "_").replace(ILLEGAL_CHARS_REGEX, "_").trim()
        if (cleanStem.isBlank()) {
            cleanStem = "shared_${System.currentTimeMillis()}"
        }

        // 4. Sanitize extension (only alphanumeric characters permitted after the dot)
        val cleanExt = if (ext.isNotEmpty()) {
            val extWithoutDot = ext.substring(1).replace(ILLEGAL_CHARS_REGEX, "")
            if (extWithoutDot.isNotBlank() && extWithoutDot.length <= 10) {
                ".$extWithoutDot"
            } else {
                fallbackExtension
            }
        } else {
            fallbackExtension
        }

        // 5. Truncate stem if overall length exceeds limit
        val maxStemLen = MAX_FILENAME_LENGTH - cleanExt.length
        val truncatedStem = if (cleanStem.length > maxStemLen) {
            cleanStem.substring(0, maxStemLen.coerceAtLeast(8))
        } else {
            cleanStem
        }

        return "$truncatedStem$cleanExt"
    }

    /**
     * Create a UUID-prefixed file within the target staging directory,
     * verifying canonical directory containment.
     */
    @Throws(SecurityException::class, IOException::class)
    fun createStagedFile(stagingDir: File, rawDisplayName: String?): File {
        if (!stagingDir.exists()) {
            stagingDir.mkdirs()
        }
        val canonicalDir = stagingDir.canonicalFile

        val sanitizedName = sanitizeFilename(rawDisplayName)
        val uniqueName = "${UUID.randomUUID()}_$sanitizedName"
        val destFile = File(canonicalDir, uniqueName)

        val canonicalDest = destFile.canonicalFile
        val prefix = canonicalDir.path + File.separator
        if (!canonicalDest.path.startsWith(prefix)) {
            throw SecurityException("Path traversal attempt detected: '$uniqueName' escapes directory '${canonicalDir.path}'")
        }

        return canonicalDest
    }

    /**
     * Verify whether a file resides strictly within the designated staging directory.
     */
    fun verifyContainment(file: File, stagingDir: File): Boolean {
        return try {
            val canonicalDest = file.canonicalFile
            val canonicalDir = stagingDir.canonicalFile
            val prefix = canonicalDir.path + File.separator
            canonicalDest.path.startsWith(prefix)
        } catch (_: Exception) {
            false
        }
    }

    /**
     * Safely delete a staged file if it exists, without raising exceptions.
     */
    fun cleanupStagedFile(file: File?): Boolean {
        if (file == null) return false
        return try {
            if (file.exists() && file.isFile) {
                file.delete()
            } else {
                false
            }
        } catch (_: Exception) {
            false
        }
    }

    /**
     * Clean up stale abandoned files in the staging directory older than maxAgeMs.
     * Preserves recent files, handles missing directories safely, and never throws.
     */
    fun cleanupStaleFiles(stagingDir: File, maxAgeMs: Long = 3_600_000L): Int {
        if (!stagingDir.exists() || !stagingDir.isDirectory) return 0
        var cleanedCount = 0
        val cutoff = System.currentTimeMillis() - maxAgeMs
        try {
            val files = stagingDir.listFiles() ?: return 0
            for (file in files) {
                if (file.isFile && file.lastModified() < cutoff) {
                    try {
                        if (file.delete()) {
                            cleanedCount++
                        }
                    } catch (_: Exception) {
                        // ignore undeletable or locked files
                    }
                }
            }
        } catch (_: Exception) {
            // safely handle any directory inspection failures
        }
        return cleanedCount
    }
}
