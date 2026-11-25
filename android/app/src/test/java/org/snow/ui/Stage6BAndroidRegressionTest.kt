package org.snow.ui

import android.app.NotificationManager
import android.content.Context
import android.content.ContextWrapper
import android.content.Intent
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.snow.capabilities.AndroidCapabilityDispatcher
import org.snow.capabilities.DndHandler
import org.snow.capabilities.WhatsAppHandler
import java.io.File

class Stage6BAndroidRegressionTest {

    private class Stage6BFakeContext(private val tempRoot: File) : ContextWrapper(null) {
        override fun getApplicationContext(): Context = this
        override fun getCacheDir(): File = File(tempRoot, "cache").apply { mkdirs() }
        override fun getFilesDir(): File = File(tempRoot, "files").apply { mkdirs() }
        override fun getPackageName(): String = "org.snow"
        override fun getSystemService(name: String): Any? = null
    }

    private fun resolveModuleFile(relativePath: String): File {
        val candidates = listOf(
            File(relativePath),
            File("app", relativePath),
            File("android/app", relativePath),
        )
        return candidates.firstOrNull { it.exists() }
            ?: error("Could not locate project file: $relativePath (cwd=${File(".").absolutePath})")
    }

    @Test
    fun testFiveTierPermissionModelFailClosedAndMatrixEnforcement() {
        val tempDir = File(System.getProperty("java.io.tmpdir"), "snow_6b_5tier_${System.nanoTime()}").apply { mkdirs() }
        try {
            val dispatcher = AndroidCapabilityDispatcher(Stage6BFakeContext(tempDir)) { null }

            // 1. files_only allows files and telemetry, blocks clipboard and system/apps
            dispatcher.activePermissionProfile = "files_only"
            assertTrue(dispatcher.isActionAllowedByProfile("battery_status"))
            assertTrue(dispatcher.isActionAllowedByProfile("file_list"))
            assertTrue(dispatcher.isActionAllowedByProfile("file_send_request"))
            assertFalse(dispatcher.isActionAllowedByProfile("clipboard_pull"))
            assertFalse(dispatcher.isActionAllowedByProfile("clipboard_push"))
            assertFalse(dispatcher.isActionAllowedByProfile("whatsapp_send"))
            assertFalse(dispatcher.isActionAllowedByProfile("android_dnd_toggle"))
            assertEquals("PERMISSION_DENIED", dispatcher.validateExecutionContract("clipboard_pull", null)?.get("status"))

            // 2. not_allowed blocks ALL actions including telemetry
            dispatcher.activePermissionProfile = "not_allowed"
            assertFalse(dispatcher.isActionAllowedByProfile("battery_status"))
            assertFalse(dispatcher.isActionAllowedByProfile("clipboard_pull"))
            assertFalse(dispatcher.isActionAllowedByProfile("file_list"))
            assertFalse(dispatcher.isActionAllowedByProfile("whatsapp_send"))
            assertEquals("PERMISSION_DENIED", dispatcher.validateExecutionContract("battery_status", null)?.get("status"))

            // 3. Unknown tier fails closed (never falls back to full_control)
            dispatcher.activePermissionProfile = "superuser_override"
            assertFalse(dispatcher.isActionAllowedByProfile("battery_status"))
            assertFalse(dispatcher.isActionAllowedByProfile("file_list"))
            assertEquals("not_allowed", SnowUiRepository.normalizeAccessProfile("superuser_override"))
        } finally {
            tempDir.deleteRecursively()
        }
    }

    @Test
    fun testWhatsAppHandlerRequiresExplicitTapNeverSilentAutoSend() {
        val tempDir = File(System.getProperty("java.io.tmpdir"), "snow_6b_wa_${System.nanoTime()}").apply { mkdirs() }
        try {
            val ctx = Stage6BFakeContext(tempDir)
            var startedIntent: Intent? = null
            var postedNotification = false

            // Missing WhatsApp installation reported honestly
            val missingWa = WhatsAppHandler(
                context = ctx,
                installedWhatsAppPackageProvider = { null }
            )
            val errRes = missingWa.composeWhatsApp("+15550101234", "Hello there", userConfirmed = true)
            assertEquals("error", errRes["status"])
            assertEquals("WHATSAPP_NOT_INSTALLED", errRes["error"])

            // Backgrounded draft posts actionable notification, never auto-sends
            val bgWa = WhatsAppHandler(
                context = ctx,
                isForegroundProvider = { false },
                installedWhatsAppPackageProvider = { "com.whatsapp" },
                notificationPoster = { _, _, _, intent ->
                    postedNotification = true
                    startedIntent = intent
                    true
                }
            )
            val bgRes = bgWa.composeWhatsApp("+15550101234", "Review draft", userConfirmed = true)
            assertEquals("success", bgRes["status"])
            assertEquals(false, bgRes["auto_sent"])
            assertEquals(true, bgRes["requires_manual_tap"])
            assertEquals("actionable_notification", bgRes["delivery_mode"])
            assertEquals("com.whatsapp", bgRes["package"])
            assertTrue(postedNotification)

            // Foreground confirmed draft opens compose screen, still requires user tap
            var fgLaunched = false
            val fgWa = WhatsAppHandler(
                context = ctx,
                isForegroundProvider = { true },
                installedWhatsAppPackageProvider = { "com.whatsapp.w4b" },
                activityStarter = { intent ->
                    fgLaunched = true
                    startedIntent = intent
                }
            )
            val fgRes = fgWa.composeWhatsApp("+15550101234", "Confirm before sending", userConfirmed = true)
            assertEquals("success", fgRes["status"])
            assertEquals(false, fgRes["auto_sent"])
            assertEquals(true, fgRes["requires_manual_tap"])
            assertEquals("intent_compose", fgRes["delivery_mode"])
            assertEquals("com.whatsapp.w4b", fgRes["package"])
            assertTrue(fgLaunched)
            assertTrue(startedIntent != null)
        } finally {
            tempDir.deleteRecursively()
        }
    }

    @Test
    fun testDndHandlerPermissionCheckAndRealFilterState() {
        val tempDir = File(System.getProperty("java.io.tmpdir"), "snow_6b_dnd_${System.nanoTime()}").apply { mkdirs() }
        try {
            val ctx = Stage6BFakeContext(tempDir)
            val deniedHandler = DndHandler(
                context = ctx,
                hasPolicyAccessProvider = { false }
            )
            val deniedRes = deniedHandler.toggleDnd(true)
            assertEquals("error", deniedRes["status"])
            assertEquals("RUNTIME_PERMISSION_REQUIRED", deniedRes["error"])

            var filterState = NotificationManager.INTERRUPTION_FILTER_ALL
            val grantedHandler = DndHandler(
                context = ctx,
                hasPolicyAccessProvider = { true },
                setInterruptionFilterProvider = { f ->
                    filterState = f
                    true
                },
                currentFilterProvider = { filterState }
            )
            val onRes = grantedHandler.toggleDnd(true)
            assertEquals("success", onRes["status"])
            assertEquals(true, onRes["enabled"])
            assertEquals(NotificationManager.INTERRUPTION_FILTER_PRIORITY, onRes["interruption_filter"])

            val offRes = grantedHandler.toggleDnd(false)
            assertEquals("success", offRes["status"])
            assertEquals(false, offRes["enabled"])
            assertEquals(NotificationManager.INTERRUPTION_FILTER_ALL, offRes["interruption_filter"])
        } finally {
            tempDir.deleteRecursively()
        }
    }

    @Test
    fun testStage6BConnectSheetAndFiveTierDevicesUiContracts() {
        val connectSrc = resolveModuleFile("src/main/java/org/snow/ui/connect/SnowConnectSheet.kt").readText()
        assertFalse(connectSrc.contains("Manual IP or Code"))
        assertTrue(connectSrc.contains("SNOW ID or Network Code"))

        val devicesSrc = resolveModuleFile("src/main/java/org/snow/ui/devices/DevicesScreen.kt").readText()
        assertTrue(devicesSrc.contains("\"Full Control\""))
        assertTrue(devicesSrc.contains("\"Files & Clip\""))
        assertTrue(devicesSrc.contains("\"Files Only\""))
        assertTrue(devicesSrc.contains("\"Clip Only\""))
        assertTrue(devicesSrc.contains("\"Not Allowed\""))
        assertTrue(devicesSrc.contains("USB • Zero Data"))
        assertTrue(devicesSrc.contains("Wi-Fi • Zero Data"))
        assertTrue(devicesSrc.contains("Remote • Uses Data"))

        val pairingFlowSrc = resolveModuleFile("src/main/java/org/snow/security/PairingFlow.kt").readText()
        assertTrue(pairingFlowSrc.contains("fun submitHandshakeToken("))
        assertTrue(pairingFlowSrc.contains("handshake_token"))
    }
}
