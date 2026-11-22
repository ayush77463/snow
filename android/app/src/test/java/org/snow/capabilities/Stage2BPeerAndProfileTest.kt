package org.snow.capabilities

import android.content.ContextWrapper
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.snow.network.AndroidPeerHostManager
import java.io.File

class Stage2BPeerAndProfileTest {

    private class TestContext(private val cache: File) : ContextWrapper(null) {
        override fun getCacheDir(): File = cache
    }

    @Test
    fun testDispatcherPermissionProfileEnforcement() {
        val tempDir = File(System.getProperty("java.io.tmpdir"), "snow_stage2b_test_${System.currentTimeMillis()}").apply { mkdirs() }
        try {
            val ctx = TestContext(tempDir)
            val dispatcher = AndroidCapabilityDispatcher(ctx) { null }

            // 1. Test Clipboard Only
            dispatcher.activePermissionProfile = "clipboard_only"
            assertTrue(dispatcher.isActionAllowedByProfile("battery_status"))
            assertTrue(dispatcher.isActionAllowedByProfile("android_battery"))
            assertTrue(dispatcher.isActionAllowedByProfile("clipboard_push"))
            assertFalse(dispatcher.isActionAllowedByProfile("file_list"))
            assertFalse(dispatcher.isActionAllowedByProfile("android_screenshot"))
            assertFalse(dispatcher.isActionAllowedByProfile("android_camera_capture"))

            val deniedFiles = dispatcher.validateExecutionContract("file_list", null)
            assertNotNull(deniedFiles)
            assertEquals("PERMISSION_DENIED", deniedFiles?.get("status"))

            val deniedScreen = dispatcher.validateExecutionContract("android_screenshot", null)
            assertNotNull(deniedScreen)
            assertEquals("PERMISSION_DENIED", deniedScreen?.get("status"))

            // 2. Test Files & Clipboard
            dispatcher.activePermissionProfile = "files_and_clipboard"
            assertTrue(dispatcher.isActionAllowedByProfile("battery_status"))
            assertTrue(dispatcher.isActionAllowedByProfile("clipboard_push"))
            assertTrue(dispatcher.isActionAllowedByProfile("file_list"))
            assertTrue(dispatcher.isActionAllowedByProfile("file_receive_request"))
            assertFalse(dispatcher.isActionAllowedByProfile("android_screenshot"))
            assertFalse(dispatcher.isActionAllowedByProfile("android_camera_capture"))

            val deniedCamera = dispatcher.validateExecutionContract("android_camera_capture", null)
            assertNotNull(deniedCamera)
            assertEquals("PERMISSION_DENIED", deniedCamera?.get("status"))

            // 3. Test Full Control
            dispatcher.activePermissionProfile = "full_control"
            assertTrue(dispatcher.isActionAllowedByProfile("battery_status"))
            assertTrue(dispatcher.isActionAllowedByProfile("file_list"))
            assertTrue(dispatcher.isActionAllowedByProfile("android_screenshot"))
            assertTrue(dispatcher.isActionAllowedByProfile("android_camera_capture"))
        } finally {
            tempDir.deleteRecursively()
        }
    }

    @Test
    fun testPeerHostManagerPinGeneration() {
        val manager = AndroidPeerHostManager()
        val pin = manager.generatePairingPin()
        assertEquals(6, pin.length)
        assertTrue(pin.all { it.isDigit() })

        val info = manager.getCurrentEphemeralPinInfo()
        assertNotNull(info)
        assertEquals(pin, info?.first)
        assertTrue((info?.second ?: 0L) > 0L)

        // Single-use consumption
        val verified = manager.verifyAndConsumePairingPin(pin)
        assertTrue(verified)
        assertFalse(manager.verifyAndConsumePairingPin(pin)) // Cannot reuse
    }
}
