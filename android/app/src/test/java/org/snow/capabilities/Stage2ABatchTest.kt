package org.snow.capabilities

import android.content.ContextWrapper
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.File

class Stage2ABatchTest {

    private lateinit var tempCacheDir: File
    private lateinit var testContext: TestContext

    private class TestContext(private val cache: File) : ContextWrapper(null) {
        override fun getCacheDir(): File = cache
    }

    @Before
    fun setUp() {
        tempCacheDir = File(System.getProperty("java.io.tmpdir"), "snow_stage2a_test_${System.currentTimeMillis()}").apply { mkdirs() }
        testContext = TestContext(tempCacheDir)
        ScreenCaptureHandler.resetConsent()
    }

    @After
    fun tearDown() {
        tempCacheDir.deleteRecursively()
        ScreenCaptureHandler.resetConsent()
    }

    @Test
    fun testBoundedImageCachePruning() {
        val clipDir = File(tempCacheDir, "clipboard").apply { mkdirs() }
        // Create 12 image files with ascending timestamps
        for (i in 1..12) {
            val f = File(clipDir, "clip_test_$i.png")
            f.writeText("test_content_$i")
            f.setLastModified(System.currentTimeMillis() + (i * 1000))
        }

        val before = clipDir.listFiles { f -> f.isFile && f.name.endsWith(".png") }
        assertEquals(12, before?.size)

        // Prune keeping file 12 preserved
        ClipboardHandler.pruneImageCache(clipDir, preserveFileName = "clip_test_12.png")

        val after = clipDir.listFiles { f -> f.isFile && f.name.endsWith(".png") }
        assertNotNull(after)
        assertTrue("Cache size must be <= 10, got ${after!!.size}", after.size <= 10)
        assertTrue("Preserved file must still exist", File(clipDir, "clip_test_12.png").exists())
    }

    @Test
    fun testScreenCaptureConsentGating() {
        val handler = ScreenCaptureHandler(testContext) { null }
        assertFalse("Screen capture must require explicit consent", handler.hasConsent())

        // Set test mock
        ScreenCaptureHandler.isConsentGranted = true
        ScreenCaptureHandler.mockBitmapWriter = { file -> file.writeText("fake_png") }
        assertTrue("Consent hook active", handler.hasConsent())

        // Reset consent
        ScreenCaptureHandler.resetConsent()
        assertFalse("Consent reset", handler.hasConsent())
    }
}
