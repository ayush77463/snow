package org.snow.ui

import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

/**
 * JVM unit tests for SafeStagingManager verifying strict filename sanitization,
 * traversal defense, UUID prefixing, canonical containment, and cleanup guarantees.
 */
class SafeStagingManagerTest {

    @get:Rule
    val tempFolder = TemporaryFolder()

    @Test
    fun testSanitizeFilename_nullOrEmpty() {
        val resultNull = SafeStagingManager.sanitizeFilename(null)
        assertTrue(resultNull.startsWith("shared_"))
        assertTrue(resultNull.endsWith(".png"))

        val resultBlank = SafeStagingManager.sanitizeFilename("   ")
        assertTrue(resultBlank.startsWith("shared_"))
        assertTrue(resultBlank.endsWith(".png"))
    }

    @Test
    fun testSanitizeFilename_directoryTraversalDots() {
        val traversal = "../../../../data/data/org.snow/databases/snow.db"
        val sanitized = SafeStagingManager.sanitizeFilename(traversal)
        assertFalse("Should not contain traversal path separators", sanitized.contains("/"))
        assertFalse("Should not contain traversal path separators", sanitized.contains("\\"))
        assertFalse("Should not contain traversal dots", sanitized.contains(".."))
        assertEquals("snow.db", sanitized)
    }

    @Test
    fun testSanitizeFilename_windowsPathSeparators() {
        val winPath = "C:\\Windows\\System32\\cmd.exe"
        val sanitized = SafeStagingManager.sanitizeFilename(winPath)
        assertFalse(sanitized.contains("\\"))
        assertFalse(sanitized.contains(":"))
        assertEquals("cmd.exe", sanitized)
    }

    @Test
    fun testSanitizeFilename_illegalCharacters() {
        val dirty = "photo*with?bad:chars|name<>.jpg"
        val sanitized = SafeStagingManager.sanitizeFilename(dirty)
        assertFalse(sanitized.contains("*"))
        assertFalse(sanitized.contains("?"))
        assertFalse(sanitized.contains(":"))
        assertFalse(sanitized.contains("|"))
        assertFalse(sanitized.contains("<"))
        assertFalse(sanitized.contains(">"))
        assertTrue(sanitized.endsWith(".jpg"))
    }

    @Test
    fun testSanitizeFilename_unicodePreserved() {
        val unicodeName = "截图_❄️_2026.png"
        val sanitized = SafeStagingManager.sanitizeFilename(unicodeName)
        assertTrue(sanitized.contains("截图"))
        assertTrue(sanitized.endsWith(".png"))
    }

    @Test
    fun testSanitizeFilename_lengthTruncation() {
        val longStem = "a".repeat(200)
        val longName = "$longStem.png"
        val sanitized = SafeStagingManager.sanitizeFilename(longName)
        assertTrue("Filename length should be capped", sanitized.length <= 128)
        assertTrue(sanitized.endsWith(".png"))
    }

    @Test
    fun testCreateStagedFile_uuidPrefixAndContainment() {
        val stagingDir = tempFolder.newFolder("screenshots")
        val staged = SafeStagingManager.createStagedFile(stagingDir, "sample.png")

        assertTrue(staged.name.contains("_sample.png"))
        assertTrue(SafeStagingManager.verifyContainment(staged, stagingDir))
        assertTrue(staged.canonicalPath.startsWith(stagingDir.canonicalPath))
    }

    @Test
    fun testVerifyContainment_detectsEscape() {
        val stagingDir = tempFolder.newFolder("screenshots")
        val outsideFile = tempFolder.newFile("unauthorized.txt")

        assertFalse(SafeStagingManager.verifyContainment(outsideFile, stagingDir))
    }

    @Test
    fun testCleanupStagedFile_removesFile() {
        val stagingDir = tempFolder.newFolder("screenshots")
        val staged = SafeStagingManager.createStagedFile(stagingDir, "to_delete.png")
        staged.writeText("sample image content")
        assertTrue(staged.exists())

        val cleaned = SafeStagingManager.cleanupStagedFile(staged)
        assertTrue(cleaned)
        assertFalse(staged.exists())

        // Calling cleanup on already deleted file should safely return false without exception
        assertFalse(SafeStagingManager.cleanupStagedFile(staged))
        assertFalse(SafeStagingManager.cleanupStagedFile(null))
    }

    @Test
    fun testCleanupStaleFiles_deletesStaleAndPreservesRecent() {
        val stagingDir = tempFolder.newFolder("safe_staging")
        val staleFile = File(stagingDir, "uuid1_old.png")
        staleFile.writeText("old data")
        // Set lastModified to 2 hours ago (7,200,000 ms)
        staleFile.setLastModified(System.currentTimeMillis() - 7_200_000L)

        val recentFile = File(stagingDir, "uuid2_fresh.png")
        recentFile.writeText("fresh data")
        recentFile.setLastModified(System.currentTimeMillis())

        val cleaned = SafeStagingManager.cleanupStaleFiles(stagingDir, maxAgeMs = 3_600_000L)
        assertEquals(1, cleaned)
        assertFalse("Stale file should be deleted", staleFile.exists())
        assertTrue("Recent file should be preserved", recentFile.exists())
    }

    @Test
    fun testCleanupStaleFiles_missingDirectorySafelyHandled() {
        val missingDir = File(tempFolder.root, "does_not_exist")
        val cleaned = SafeStagingManager.cleanupStaleFiles(missingDir)
        assertEquals(0, cleaned)
    }
}
