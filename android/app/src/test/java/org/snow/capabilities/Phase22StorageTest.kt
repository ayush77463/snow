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
        fileHandler = AndroidFileHandler(dummyContext, transferClientProvider = { null })
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

    @Test
    fun testHandleFileReceiveMissingPayloadReturnsError() = kotlinx.coroutines.runBlocking {
        val res = fileHandler.handleFileReceiveRequest(null, "127.0.0.1", 8766)
        assertEquals("error", res["status"])
    }

    @Test
    fun testHandleFileReceiveBlankFileNameReturnsError() = kotlinx.coroutines.runBlocking {
        val res = fileHandler.handleFileReceiveRequest(mapOf("file_name" to ""), "127.0.0.1", 8766)
        assertEquals("error", res["status"])
    }

    @Test
    fun testHandleFileReceiveNonExistentFileReturnsStructuredError() = kotlinx.coroutines.runBlocking {
        val res = fileHandler.handleFileReceiveRequest(
            mapOf("file_name" to "non_existent_file_12345.pdf", "scope" to "full", "principal" to "OWNER_MANUAL"),
            "127.0.0.1",
            8766
        )
        assertEquals("error", res["status"])
        assertEquals("FILE_NOT_FOUND", res["error"])
    }

    @Test
    fun testPositiveFullStorageDownloadHandoff() = kotlinx.coroutines.runBlocking {
        val fakeClient = FakeTestFileTransferClient(dummyContext)
        val downloadFolder = tempFolder.newFolder("Download")
        val reportFile = java.io.File(downloadFolder, "report.pdf")
        reportFile.writeText("PDF-Mock-Content-For-Testing")

        val handler = AndroidFileHandler(
            context = dummyContext,
            storageRootDirProvider = { tempFolder.root },
            allFilesAccessProvider = { true },
            transferClientProvider = { fakeClient }
        )

        val res = handler.handleFileReceiveRequest(
            mapOf(
                "file_name" to "report.pdf",
                "subpath" to "Download",
                "scope" to "full",
                "principal" to "OWNER_MANUAL"
            ),
            "127.0.0.1",
            8766
        )

        assertEquals("success", res["status"])
        assertEquals("report.pdf", res["file_name"])
        assertEquals(1, fakeClient.uploadCount)
        assertEquals(reportFile.canonicalPath, fakeClient.lastUploadedFile?.canonicalPath)
    }

    @Test
    fun testAiMcpForbiddenFromFullStorageDownload() = kotlinx.coroutines.runBlocking {
        val fakeClient = FakeTestFileTransferClient(dummyContext)
        val downloadFolder = tempFolder.newFolder("SecretDocs")
        val secretFile = java.io.File(downloadFolder, "passwords.txt")
        secretFile.writeText("SECRET_DATA")

        val handler = AndroidFileHandler(
            context = dummyContext,
            storageRootDirProvider = { tempFolder.root },
            allFilesAccessProvider = { true },
            transferClientProvider = { fakeClient }
        )

        // AI_MCP principal must NOT resolve via shared storage, falling back to SAF (which fails as not found)
        val res = handler.handleFileReceiveRequest(
            mapOf(
                "file_name" to "passwords.txt",
                "subpath" to "SecretDocs",
                "scope" to "full",
                "principal" to "AI_MCP"
            ),
            "127.0.0.1",
            8766
        )

        assertEquals("error", res["status"])
        assertEquals(0, fakeClient.uploadCount)
    }

    private class FakeTestFileTransferClient(ctx: Context) : org.snow.transfer.FileTransferClient(
        context = ctx,
        deviceId = "fake-device",
        useTls = false
    ) {
        var uploadCount = 0
        var lastUploadedFile: java.io.File? = null

        override suspend fun uploadFile(
            serverHost: String,
            transferPort: Int,
            file: java.io.File,
            onProgress: ((org.snow.transfer.FileTransferClient.TransferProgress) -> Unit)?
        ): TransferResult {
            uploadCount++
            lastUploadedFile = file
            return TransferResult.Success("test-transfer-id-999", "mock-sha256-hash", file)
        }
    }
}
