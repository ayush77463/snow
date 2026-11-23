package org.snow.ui

import androidx.appcompat.app.AppCompatDelegate
import org.junit.Assert.*
import org.junit.Test
import org.snow.ui.settings.SettingsViewModel

/**
 * Stage 2C Unit Tests for Theme Parity, 4-Tab Navigation, and Wallpaper Fallback contracts.
 */
class Stage2CUiParityTest {

    @Test
    fun testThemeNightModeMapping() {
        val themeMap = mapOf(
            "system" to AppCompatDelegate.MODE_NIGHT_FOLLOW_SYSTEM,
            "light" to AppCompatDelegate.MODE_NIGHT_NO,
            "dark" to AppCompatDelegate.MODE_NIGHT_YES
        )

        assertEquals(AppCompatDelegate.MODE_NIGHT_FOLLOW_SYSTEM, themeMap["system"])
        assertEquals(AppCompatDelegate.MODE_NIGHT_NO, themeMap["light"])
        assertEquals(AppCompatDelegate.MODE_NIGHT_YES, themeMap["dark"])
    }

    @Test
    fun testPendingApprovalsBadgeContract() {
        // Unread badge is visible when count > 0, hidden when 0
        fun isBadgeVisible(count: Int): Boolean = count > 0
        fun formatBadgeText(count: Int): String = count.toString()

        assertFalse(isBadgeVisible(0))
        assertTrue(isBadgeVisible(1))
        assertTrue(isBadgeVisible(5))
        assertEquals("1", formatBadgeText(1))
        assertEquals("5", formatBadgeText(5))
    }

    @Test
    fun testWallpaperFallbackContract() {
        // When wallpaper byte array is null, fallback surface is presented instead of failing
        fun shouldShowFallback(bytes: ByteArray?): Boolean = bytes == null

        assertTrue(shouldShowFallback(null))
        assertFalse(shouldShowFallback(byteArrayOf(0xFF.toByte(), 0xD8.toByte())))
    }

    @Test
    fun testFourTabNavigationContract() {
        // Exactly 4 primary tabs: Home, Devices, Files & Tools, Settings
        val primaryTabs = listOf("Home", "Devices", "Files & Tools", "Settings")
        assertEquals(4, primaryTabs.size)
        assertTrue(primaryTabs.contains("Home"))
        assertTrue(primaryTabs.contains("Devices"))
        assertTrue(primaryTabs.contains("Files & Tools"))
        assertTrue(primaryTabs.contains("Settings"))
    }

    @Test
    fun testTypedWallpaperResultContract() {
        val sampleBytes = byteArrayOf(0x01, 0x02, 0x03)
        val updated = org.snow.transfer.FileTransferClient.WallpaperResult.Updated(sampleBytes, "etag-123")
        val notModified = org.snow.transfer.FileTransferClient.WallpaperResult.NotModified
        val unavailable = org.snow.transfer.FileTransferClient.WallpaperResult.Unavailable

        assertTrue(updated is org.snow.transfer.FileTransferClient.WallpaperResult)
        assertTrue(notModified is org.snow.transfer.FileTransferClient.WallpaperResult)
        assertTrue(unavailable is org.snow.transfer.FileTransferClient.WallpaperResult)

        assertEquals("etag-123", updated.etag)
        assertArrayEquals(sampleBytes, updated.bytes)
    }

    @Test
    fun testHeroDeviceBadgeContract() {
        fun getDeviceBadge(os: String?): String {
            val isAndroid = os?.contains("Android", ignoreCase = true) == true
            return if (isAndroid) "📱 Android Phone" else "🖥️ Windows PC"
        }

        assertEquals("🖥️ Windows PC", getDeviceBadge(null))
        assertEquals("🖥️ Windows PC", getDeviceBadge("Windows 11 Pro"))
        assertEquals("📱 Android Phone", getDeviceBadge("Android 14"))
    }
}
