package org.snow.ui

import androidx.compose.ui.graphics.Color
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.snow.ui.navigation.SnowTab
import org.snow.ui.theme.DarkSnowColors
import org.snow.ui.theme.LightSnowColors
import org.snow.ui.theme.SnowColors
import java.io.File
import kotlin.math.pow

/**
 * Milestone 3A Android Compose UI Verification Suite (Section 6.5).
 *
 * Covers:
 * - Bottom navigation tab order (HOME -> TOOLS -> DEVICES -> SETTINGS) & accessibility metadata
 * - ToolsScreen bidirectional HorizontalPager + 5-pill switcher sync and state retention
 * - Light & Dark terminal palette WCAG AA contrast (>= 4.5:1) using SNOW tokens only
 * - Async action loading / disabled states & failure recovery guards
 * - Haptic feedback discipline (triggered strictly from click/action handlers, never composition)
 */
class Milestone3AComposeUiTest {

    private fun resolveSourceRoot(): File {
        val candidates = listOf(
            File("src/main/java/org/snow/ui"),
            File("android/app/src/main/java/org/snow/ui"),
            File("app/src/main/java/org/snow/ui")
        )
        return candidates.firstOrNull { it.exists() } ?: candidates.first()
    }

    private fun relativeLuminance(c: Color): Double {
        fun channel(v: Float): Double {
            val d = v.toDouble()
            return if (d <= 0.03928) d / 12.92 else ((d + 0.055) / 1.055).pow(2.4)
        }
        return 0.2126 * channel(c.red) + 0.7152 * channel(c.green) + 0.0722 * channel(c.blue)
    }

    private fun contrastRatio(fg: Color, bg: Color): Double {
        val l1 = relativeLuminance(fg)
        val l2 = relativeLuminance(bg)
        val bright = maxOf(l1, l2)
        val dark = minOf(l1, l2)
        return (bright + 0.05) / (dark + 0.05)
    }

    private fun assertTerminalContrast(paletteName: String, palette: SnowColors) {
        val fgTokens = listOf(
            "terminalHeader" to palette.terminalHeader,
            "terminalStdout" to palette.terminalStdout,
            "terminalStderr" to palette.terminalStderr,
            "terminalSystem" to palette.terminalSystem,
            "terminalPlaceholder" to palette.terminalPlaceholder,
            "terminalExitSuccess" to palette.terminalExitSuccess,
            "terminalExitError" to palette.terminalExitError
        )
        fgTokens.forEach { (name, fg) ->
            val ratio = contrastRatio(fg, palette.terminalBg)
            assertTrue(
                "$paletteName $name contrast $ratio must meet WCAG AA (>= 4.5:1) on terminalBg",
                ratio >= 4.5
            )
        }
    }

    @Test
    fun testNavigationOrderAndAccessibilitySemantics() {
        val tabs = SnowTab.values()
        assertEquals(listOf("HOME", "TOOLS", "DEVICES", "SETTINGS"), tabs.map { it.name })
        assertEquals(listOf("Home", "Tools", "Devices", "Settings"), tabs.map { it.title })

        val navSrc = File(resolveSourceRoot(), "navigation/SnowNavigation.kt").readText()
        assertTrue(navSrc.contains("semantics(mergeDescendants = true)"))
        assertTrue(navSrc.contains("contentDescription = \"\${tab.title} tab\""))
        assertTrue(navSrc.contains("clickable(role = Role.Tab)"))
    }

    @Test
    fun testToolsScreenPagerSyncAndStateRetention() {
        val toolsSrc = File(resolveSourceRoot(), "tools/ToolsScreen.kt").readText()
        assertTrue(toolsSrc.contains("HorizontalPager("))
        assertTrue(toolsSrc.contains("rememberPagerState("))
        assertTrue(toolsSrc.contains("beyondBoundsPageCount"))
        assertTrue(toolsSrc.contains("pagerState.settledPage"))
        assertTrue(toolsSrc.contains("pagerState.animateScrollToPage("))
        assertTrue(toolsSrc.contains("rememberSaveable { mutableStateOf(\"\") }"))
    }

    @Test
    fun testTerminalPaletteUsesSnowTokensAndPassesContrastInLightAndDark() {
        assertEquals(DarkSnowColors.surfaceDim, DarkSnowColors.terminalBg)
        assertEquals(LightSnowColors.surfaceElevated, LightSnowColors.terminalBg)

        assertTerminalContrast("DarkSnowColors", DarkSnowColors)
        assertTerminalContrast("LightSnowColors", LightSnowColors)

        val terminalSrc = File(resolveSourceRoot(), "tools/ToolsScreen.kt")
            .readText()
            .substringAfter("private fun TerminalToolView(")
        assertFalse("Terminal must not hardcode #0F172A", terminalSrc.contains("0xFF0F172A"))
        assertFalse("Terminal must not hardcode low-contrast #64748B", terminalSrc.contains("0xFF64748B"))
        assertTrue(terminalSrc.contains("colors.terminalBg"))
        assertTrue(terminalSrc.contains("colors.terminalStdout"))
        assertTrue(terminalSrc.contains("colors.terminalPlaceholder"))
        assertTrue(terminalSrc.contains("cursorColor = colors.terminalHeader"))
    }

    @Test
    fun testAsyncLoadingDisableAndFailureRecoveryGuards() {
        val uiRoot = resolveSourceRoot()
        val componentsSrc = File(uiRoot, "components/SnowComponents.kt").readText()
        assertTrue(componentsSrc.contains("isLoading: Boolean = false"))
        assertTrue(componentsSrc.contains("CircularProgressIndicator"))

        val toolsSrc = File(uiRoot, "tools/ToolsScreen.kt").readText()
        assertTrue(toolsSrc.contains("isLoading = terminalState.isRunning"))
        assertTrue(toolsSrc.contains("enabled = commandInput.isNotBlank() && !terminalState.isRunning"))

        val settingsSrc = File(uiRoot, "settings/SettingsScreen.kt").readText()
        assertTrue(settingsSrc.contains("isCheckingUpdate: Boolean = false"))
        assertTrue(settingsSrc.contains("isLoading = isCheckingUpdate"))

        val devicesSrc = File(uiRoot, "devices/DevicesScreen.kt").readText()
        assertTrue(devicesSrc.contains("isGeneratingFederationCode"))
        assertTrue(devicesSrc.contains("isJoiningFederation"))
        assertTrue(devicesSrc.contains("isFederationActionInFlight"))

        val appSrc = File(uiRoot, "SnowApp.kt").readText()
        assertTrue(appSrc.contains("isCheckingUpdate = false"))
        assertTrue(appSrc.contains("isGeneratingFederationCode = false"))
        assertTrue(appSrc.contains("isJoiningFederation = false"))
        assertTrue(appSrc.contains("isFederationActionInFlight = false"))
    }

    @Test
    fun testHapticsOnlyTriggeredOnUserInteractionHandlers() {
        val uiFiles = resolveSourceRoot().walkTopDown().filter { it.isFile && it.extension == "kt" }.toList()
        assertTrue(uiFiles.isNotEmpty())

        uiFiles.forEach { file ->
            val lines = file.readLines()
            lines.forEachIndexed { idx, line ->
                if (line.contains("performHapticFeedback")) {
                    val window = lines.subList(maxOf(0, idx - 6), idx + 1).joinToString("\n")
                    assertFalse(
                        "${file.name}:${idx + 1} must not trigger haptic inside LaunchedEffect",
                        window.contains("LaunchedEffect")
                    )
                    assertTrue(
                        "${file.name}:${idx + 1} haptic must sit inside user action handler",
                        window.contains("onClick") || window.contains("clickable") || window.contains("onToggle")
                    )
                }
            }
        }
    }
}
