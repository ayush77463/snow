package org.snow.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.Immutable
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp

@Immutable
data class SnowColors(
    val canvas: Color,
    val bars: Color,
    val surface: Color,
    val surfaceElevated: Color,
    val surfaceDim: Color,
    val border: Color,
    val borderSubtle: Color,
    val textPrimary: Color,
    val textSecondary: Color,
    val textMuted: Color,
    val accentBlue: Color,
    val accentCyan: Color,
    val accentEmerald: Color,
    val brandGradient: Brush,
    val terminalBg: Color,
    val isDark: Boolean,
    val terminalBorder: Color = border,
    val terminalDivider: Color = borderSubtle,
    val terminalHeader: Color = accentCyan,
    val terminalStdout: Color = textPrimary,
    val terminalStderr: Color = Color(0xFFF87171),
    val terminalSystem: Color = accentBlue,
    val terminalPlaceholder: Color = textSecondary,
    val terminalExitSuccess: Color = accentEmerald,
    val terminalExitError: Color = Color(0xFFF87171)
)

val DarkSnowColors = SnowColors(
    canvas = Color(0xFF0F0F0F),
    bars = Color(0xFF000000),
    surface = Color(0xFF181818),
    surfaceElevated = Color(0xFF242424),
    surfaceDim = Color(0xFF121212),
    border = Color(0x1FFFFFFF), // 12% white hairline
    borderSubtle = Color(0x0FFFFFFF), // 6% white
    textPrimary = Color(0xFFF1F5F9),
    textSecondary = Color(0xFF94A3B8),
    textMuted = Color(0xFF71717A),
    accentBlue = Color(0xFF2563EB),
    accentCyan = Color(0xFF00E5FF),
    accentEmerald = Color(0xFF10B981),
    brandGradient = Brush.linearGradient(
        listOf(Color(0xFF2563EB), Color(0xFF00E5FF), Color(0xFF10B981))
    ),
    terminalBg = Color(0xFF121212),
    isDark = true,
    terminalBorder = Color(0x1FFFFFFF),
    terminalDivider = Color(0x14FFFFFF),
    terminalHeader = Color(0xFF00E5FF),
    terminalStdout = Color(0xFFF1F5F9),
    terminalStderr = Color(0xFFF87171),
    terminalSystem = Color(0xFF38BDF8),
    terminalPlaceholder = Color(0xFF94A3B8),
    terminalExitSuccess = Color(0xFF10B981),
    terminalExitError = Color(0xFFF87171)
)

val LightSnowColors = SnowColors(
    canvas = Color(0xFFF8FAFC),
    bars = Color(0xFFFFFFFF),
    surface = Color(0xFFFFFFFF),
    surfaceElevated = Color(0xFFF1F5F9),
    surfaceDim = Color(0xFFE2E8F0),
    border = Color(0xFFE2E8F0),
    borderSubtle = Color(0xFFF1F5F9),
    textPrimary = Color(0xFF0F172A),
    textSecondary = Color(0xFF475569),
    textMuted = Color(0xFF64748B),
    accentBlue = Color(0xFF2563EB),
    accentCyan = Color(0xFF06B6D4),
    accentEmerald = Color(0xFF10B981),
    brandGradient = Brush.linearGradient(
        listOf(Color(0xFF2563EB), Color(0xFF06B6D4), Color(0xFF10B981))
    ),
    terminalBg = Color(0xFFF1F5F9),
    isDark = false,
    terminalBorder = Color(0xFFE2E8F0),
    terminalDivider = Color(0xFFCBD5E1),
    terminalHeader = Color(0xFF1D4ED8),
    terminalStdout = Color(0xFF0F172A),
    terminalStderr = Color(0xFFB91C1C),
    terminalSystem = Color(0xFF0369A1),
    terminalPlaceholder = Color(0xFF475569),
    terminalExitSuccess = Color(0xFF047857),
    terminalExitError = Color(0xFFB91C1C)
)

val LocalSnowColors = staticCompositionLocalOf { DarkSnowColors }

private val M3DarkColorScheme = darkColorScheme(
    primary = Color(0xFF2563EB),
    onPrimary = Color.White,
    primaryContainer = Color(0xFF1D4ED8),
    onPrimaryContainer = Color(0xFFEEF2FF),
    secondary = Color(0xFF00E5FF),
    onSecondary = Color(0xFF001F26),
    tertiary = Color(0xFF10B981),
    onTertiary = Color.White,
    background = Color(0xFF0F0F0F),
    onBackground = Color(0xFFF1F5F9),
    surface = Color(0xFF181818),
    onSurface = Color(0xFFF1F5F9),
    surfaceVariant = Color(0xFF242424),
    onSurfaceVariant = Color(0xFF94A3B8),
    outline = Color(0x26FFFFFF),
    outlineVariant = Color(0x14FFFFFF)
)

private val M3LightColorScheme = lightColorScheme(
    primary = Color(0xFF2563EB),
    onPrimary = Color.White,
    primaryContainer = Color(0xFFDBEAFE),
    onPrimaryContainer = Color(0xFF1E3A8A),
    secondary = Color(0xFF06B6D4),
    onSecondary = Color.White,
    tertiary = Color(0xFF10B981),
    onTertiary = Color.White,
    background = Color(0xFFF8FAFC),
    onBackground = Color(0xFF0F172A),
    surface = Color(0xFFFFFFFF),
    onSurface = Color(0xFF0F172A),
    surfaceVariant = Color(0xFFF1F5F9),
    onSurfaceVariant = Color(0xFF475569),
    outline = Color(0xFFE2E8F0),
    outlineVariant = Color(0xFFCBD5E1)
)

object SnowTypography {
    val displayLarge = TextStyle(
        fontFamily = FontFamily.Default,
        fontWeight = FontWeight.Bold,
        fontSize = 32.sp,
        lineHeight = 40.sp,
        letterSpacing = (-0.5).sp
    )
    val titleLarge = TextStyle(
        fontFamily = FontFamily.Default,
        fontWeight = FontWeight.SemiBold,
        fontSize = 20.sp,
        lineHeight = 28.sp
    )
    val titleMedium = TextStyle(
        fontFamily = FontFamily.Default,
        fontWeight = FontWeight.SemiBold,
        fontSize = 16.sp,
        lineHeight = 24.sp
    )
    val titleSmall = TextStyle(
        fontFamily = FontFamily.Default,
        fontWeight = FontWeight.Medium,
        fontSize = 14.sp,
        lineHeight = 20.sp
    )
    val bodyLarge = TextStyle(
        fontFamily = FontFamily.Default,
        fontWeight = FontWeight.Normal,
        fontSize = 16.sp,
        lineHeight = 24.sp
    )
    val bodyMedium = TextStyle(
        fontFamily = FontFamily.Default,
        fontWeight = FontWeight.Normal,
        fontSize = 14.sp,
        lineHeight = 20.sp
    )
    val bodySmall = TextStyle(
        fontFamily = FontFamily.Default,
        fontWeight = FontWeight.Normal,
        fontSize = 12.sp,
        lineHeight = 16.sp
    )
    val labelLarge = TextStyle(
        fontFamily = FontFamily.Default,
        fontWeight = FontWeight.SemiBold,
        fontSize = 14.sp,
        lineHeight = 20.sp
    )
    val labelMedium = TextStyle(
        fontFamily = FontFamily.Default,
        fontWeight = FontWeight.Medium,
        fontSize = 12.sp,
        lineHeight = 16.sp,
        letterSpacing = 0.5.sp
    )
    val labelSmall = TextStyle(
        fontFamily = FontFamily.Default,
        fontWeight = FontWeight.SemiBold,
        fontSize = 11.sp,
        lineHeight = 14.sp,
        letterSpacing = 0.5.sp
    )
    val monospaceSmall = TextStyle(
        fontFamily = FontFamily.Monospace,
        fontWeight = FontWeight.Medium,
        fontSize = 12.sp,
        lineHeight = 16.sp
    )
}

@Composable
fun SnowTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit
) {
    val snowColors = if (darkTheme) DarkSnowColors else LightSnowColors
    val m3Colors = if (darkTheme) M3DarkColorScheme else M3LightColorScheme

    CompositionLocalProvider(LocalSnowColors provides snowColors) {
        MaterialTheme(
            colorScheme = m3Colors,
            content = content
        )
    }
}
