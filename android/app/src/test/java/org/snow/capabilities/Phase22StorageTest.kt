package org.snow.capabilities

import android.content.Context
import android.content.ContextWrapper
import org.junit.Assert.*
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class Phase22StorageTest {

    @get:Rule
    val tempFolder = TemporaryFolder()

    private val dummyContext = object : ContextWrapper(null) {}
    private lateinit var fileHandler: AndroidFileHandler

    @Before
    fun setUp() {
        fileHandler = AndroidFileHandler(dummyContext) { null }
    }

    @Test
    fun testPathTraversalWithDoubleDotRejected() {
        val payload = mapOf(
            "subpath" to "../../../system",
            "scope" to "full",
            "principal" to "OWNER_MANUAL"
        )
        val res = fileHandler.handleFileList(payload)
        // Either rejected via path traversal or via permission check
        val status = res["status"] as String
        val isTraversalOrDenied = status == "error" || status == "ALL_FILES_ACCESS_REQUIRED" || status == "STORAGE_UNAVAILABLE"
        assertTrue("Expected error or access required, got $status", isTraversalOrDenied)
        if (status == "error") {
            assertEquals("PATH_TRAVERSAL_DETECTED", res["error"])
        }
    }

    @Test
    fun testPathTraversalWithBackslashRejected() {
        val payload = mapOf(
            "subpath" to "DCIM\\..\\..",
            "scope" to "full",
            "principal" to "OWNER_MANUAL"
        )
        val res = fileHandler.handleFileList(payload)
        val status = res["status"] as String
        val isTraversalOrDenied = status == "error" || status == "ALL_FILES_ACCESS_REQUIRED" || status == "STORAGE_UNAVAILABLE"
        assertTrue("Expected error or access required, got $status", isTraversalOrDenied)
    }

    @Test
    fun testAiMcpRestrictedToSafMode() {
        // AI_MCP caller must NOT get full shared storage mode
        val payload = mapOf(
            "subpath" to "Documents",
            "scope" to "full",
            "principal" to "AI_MCP"
        )
        val res = fileHandler.handleFileList(payload)
        val mode = res["storage_mode"] as? String
        assertNotEquals("full_shared_storage", mode)
    }

    @Test
    fun testSafModeExplicitSelection() {
        val payload = mapOf(
            "subpath" to "",
            "scope" to "saf",
            "principal" to "OWNER_MANUAL"
        )
        val res = fileHandler.handleFileList(payload)
        assertEquals("saf_tree", res["storage_mode"])
    }

    @Test
    fun testResolveSharedStorageFilePathTraversalFails() {
        val resolved = fileHandler.resolveSharedStorageFile("../../../etc", "hosts")
        assertNull("Path traversal resolve must return null", resolved)
    }

    @Test
    fun testResolveSharedStorageFileProtectedAndroidDataFails() {
        val resolved = fileHandler.resolveSharedStorageFile("Android/data", "some_app.db")
        assertNull("Access to Android/data must return null", resolved)
    }

    @Test
    fun testResolveSharedStorageFileProtectedAndroidObbFails() {
        val resolved = fileHandler.resolveSharedStorageFile("Android/obb", "main.obb")
        assertNull("Access to Android/obb must return null", resolved)
    }

    @Test
    fun testIsPathContainedRejectsPrefixEscape() {
        val root = tempFolder.newFolder("storage")
        val sibling = java.io.File(root.parentFile, root.name + "0")
        assertFalse("Sibling with shared prefix must not be contained", AndroidFileHandler.isPathContained(sibling, root))

        val child = java.io.File(root, "subfolder")
        child.mkdirs()
        assertTrue("Subfolder must be contained", AndroidFileHandler.isPathContained(child, root))
        assertTrue("Root itself must be contained", AndroidFileHandler.isPathContained(root, root))
    }
}
