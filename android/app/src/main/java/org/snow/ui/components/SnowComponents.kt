package org.snow.ui.components

import androidx.compose.animation.core.Animatable
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxScope
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.input.nestedscroll.NestedScrollConnection
import androidx.compose.ui.input.nestedscroll.NestedScrollSource
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.IntOffset
import androidx.compose.ui.unit.Velocity
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.launch
import kotlin.math.roundToInt
import org.snow.ui.theme.LocalSnowColors
import org.snow.ui.theme.SnowTypography

/**
 * Standard SNOW specular card container with 20.dp radius and 1.dp hairline border.
 */
@Composable
fun SnowCard(
    modifier: Modifier = Modifier,
    cornerRadius: Dp = 20.dp,
    borderWidth: Dp = 1.dp,
    borderColor: Color = LocalSnowColors.current.border,
    backgroundColor: Color = LocalSnowColors.current.surface,
    elevation: Dp = 2.dp,
    contentPadding: PaddingValues = PaddingValues(16.dp),
    content: @Composable () -> Unit
) {
    val shape = RoundedCornerShape(cornerRadius)
    Surface(
        modifier = modifier
            .shadow(elevation, shape, clip = false)
            .clip(shape)
            .border(borderWidth, borderColor, shape),
        shape = shape,
        color = backgroundColor
    ) {
        Box(modifier = Modifier.padding(contentPadding)) {
            content()
        }
    }
}

/**
 * Brand gradient pill action button (135° Arctic Gradient).
 */
@Composable
fun SnowGradientButton(
    text: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    icon: ImageVector? = null,
    enabled: Boolean = true,
    isLoading: Boolean = false
) {
    val colors = LocalSnowColors.current
    val shape = RoundedCornerShape(9999.dp)
    val interactive = enabled && !isLoading

    Box(
        modifier = modifier
            .clip(shape)
            .alpha(if (interactive) 1f else 0.55f)
            .background(if (interactive) colors.brandGradient else Brush.linearGradient(listOf(Color.Gray, Color.DarkGray)))
            .clickable(enabled = interactive, onClick = onClick)
            .padding(horizontal = 20.dp, vertical = 12.dp),
        contentAlignment = Alignment.Center
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.Center
        ) {
            if (isLoading) {
                CircularProgressIndicator(
                    modifier = Modifier.size(16.dp),
                    strokeWidth = 2.dp,
                    color = Color.White
                )
                Spacer(modifier = Modifier.width(8.dp))
            } else if (icon != null) {
                Icon(
                    imageVector = icon,
                    contentDescription = null,
                    tint = Color.White,
                    modifier = Modifier.size(18.dp)
                )
                Spacer(modifier = Modifier.width(8.dp))
            }
            Text(
                text = text,
                color = Color.White,
                style = SnowTypography.labelLarge
            )
        }
    }
}

/**
 * Tonal pill button for secondary operations (#242424 in Dark, #F1F5F9 in Light).
 */
@Composable
fun SnowTonalButton(
    text: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    icon: ImageVector? = null,
    enabled: Boolean = true,
    contentPadding: PaddingValues = PaddingValues(horizontal = 16.dp, vertical = 10.dp),
    isLoading: Boolean = false
) {
    val colors = LocalSnowColors.current
    val shape = RoundedCornerShape(9999.dp)
    val interactive = enabled && !isLoading

    Surface(
        modifier = modifier
            .clip(shape)
            .alpha(if (interactive) 1f else 0.52f)
            .clickable(enabled = interactive, onClick = onClick),
        shape = shape,
        color = colors.surfaceElevated
    ) {
        Row(
            modifier = Modifier.padding(contentPadding),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.Center
        ) {
            if (isLoading) {
                CircularProgressIndicator(
                    modifier = Modifier.size(16.dp),
                    strokeWidth = 2.dp,
                    color = colors.accentCyan
                )
                Spacer(modifier = Modifier.width(8.dp))
            } else if (icon != null) {
                Icon(
                    imageVector = icon,
                    contentDescription = null,
                    tint = colors.textPrimary,
                    modifier = Modifier.size(18.dp)
                )
                Spacer(modifier = Modifier.width(8.dp))
            }
            Text(
                text = text,
                color = colors.textPrimary,
                style = SnowTypography.labelMedium
            )
        }
    }
}

/**
 * Hairline outlined pill button.
 */
@Composable
fun SnowOutlinedButton(
    text: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    icon: ImageVector? = null,
    enabled: Boolean = true,
    isLoading: Boolean = false
) {
    val colors = LocalSnowColors.current
    val shape = RoundedCornerShape(9999.dp)
    val interactive = enabled && !isLoading

    Surface(
        modifier = modifier
            .clip(shape)
            .alpha(if (interactive) 1f else 0.52f)
            .border(1.dp, colors.border, shape)
            .clickable(enabled = interactive, onClick = onClick),
        shape = shape,
        color = Color.Transparent
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 16.dp, vertical = 10.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.Center
        ) {
            if (isLoading) {
                CircularProgressIndicator(
                    modifier = Modifier.size(16.dp),
                    strokeWidth = 2.dp,
                    color = colors.accentCyan
                )
                Spacer(modifier = Modifier.width(8.dp))
            } else if (icon != null) {
                Icon(
                    imageVector = icon,
                    contentDescription = null,
                    tint = colors.textPrimary,
                    modifier = Modifier.size(18.dp)
                )
                Spacer(modifier = Modifier.width(8.dp))
            }
            Text(
                text = text,
                color = colors.textPrimary,
                style = SnowTypography.labelMedium
            )
        }
    }
}

enum class SnowBadgeType {
    CONNECTED,
    PROCESSING,
    STANDBY,
    ERROR
}

/**
 * Standard status badge with glowing/colored dot and label.
 */
@Composable
fun SnowStatusBadge(
    text: String,
    type: SnowBadgeType,
    modifier: Modifier = Modifier
) {
    val colors = LocalSnowColors.current
    val isDark = colors.isDark

    val (bg, dot, txt) = when (type) {
        SnowBadgeType.CONNECTED -> if (isDark) {
            Triple(Color(0xFF064E3B), Color(0xFF10B981), Color(0xFF6EE7B7))
        } else {
            Triple(Color(0xFFECFDF5), Color(0xFF10B981), Color(0xFF047857))
        }
        SnowBadgeType.PROCESSING -> if (isDark) {
            Triple(Color(0xFF1E3A8A), Color(0xFF00E5FF), Color(0xFF93C5FD))
        } else {
            Triple(Color(0xFFEFF6FF), Color(0xFF06B6D4), Color(0xFF1D4ED8))
        }
        SnowBadgeType.STANDBY -> if (isDark) {
            Triple(Color(0xFF27272A), Color(0xFF71717A), Color(0xFFA1A1AA))
        } else {
            Triple(Color(0xFFF1F5F9), Color(0xFF94A3B8), Color(0xFF64748B))
        }
        SnowBadgeType.ERROR -> if (isDark) {
            Triple(Color(0xFF450A0A), Color(0xFFEF4444), Color(0xFFFCA5A5))
        } else {
            Triple(Color(0xFFFEF2F2), Color(0xFFEF4444), Color(0xFFB91C1C))
        }
    }

    Row(
        modifier = modifier
            .clip(RoundedCornerShape(9999.dp))
            .background(bg)
            .padding(horizontal = 8.dp, vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Box(
            modifier = Modifier
                .size(6.dp)
                .clip(CircleShape)
                .background(dot)
        )
        Spacer(modifier = Modifier.width(6.dp))
        Text(
            text = text,
            color = txt,
            style = SnowTypography.labelSmall,
            maxLines = 1,
            softWrap = false
        )
    }
}

/**
 * Lightweight zero-dependency pull-to-refresh container compatible with Compose Material3 1.2.
 */
@Composable
fun SnowPullToRefreshBox(
    isRefreshing: Boolean,
    onRefresh: () -> Unit,
    modifier: Modifier = Modifier,
    content: @Composable BoxScope.() -> Unit
) {
    val colors = LocalSnowColors.current
    val density = LocalDensity.current
    val scope = rememberCoroutineScope()
    val thresholdPx = remember(density) { with(density) { 72.dp.toPx() } }
    val maxPullPx = remember(density) { with(density) { 108.dp.toPx() } }
    var pullDistance by remember { mutableFloatStateOf(0f) }
    val indicatorOffset = remember { Animatable(0f) }

    LaunchedEffect(isRefreshing) {
        if (!isRefreshing) {
            pullDistance = 0f
            indicatorOffset.animateTo(0f)
        } else {
            indicatorOffset.animateTo(thresholdPx * 0.7f)
        }
    }

    val nestedScrollConnection = remember(isRefreshing, thresholdPx) {
        object : NestedScrollConnection {
            override fun onPreScroll(available: Offset, source: NestedScrollSource): Offset {
                if (source == NestedScrollSource.Drag && available.y < 0f && pullDistance > 0f) {
                    val consumed = maxOf(available.y, -pullDistance)
                    pullDistance += consumed
                    scope.launch { indicatorOffset.snapTo(pullDistance) }
                    return Offset(0f, consumed)
                }
                return Offset.Zero
            }

            override fun onPostScroll(
                consumed: Offset,
                available: Offset,
                source: NestedScrollSource
            ): Offset {
                if (source == NestedScrollSource.Drag && !isRefreshing && available.y > 0f) {
                    val delta = available.y * 0.5f
                    pullDistance = (pullDistance + delta).coerceIn(0f, maxPullPx)
                    scope.launch { indicatorOffset.snapTo(pullDistance) }
                    return Offset(0f, available.y)
                }
                return Offset.Zero
            }

            override suspend fun onPreFling(available: Velocity): Velocity {
                if (!isRefreshing && pullDistance >= thresholdPx) {
                    pullDistance = 0f
                    onRefresh()
                    indicatorOffset.animateTo(thresholdPx * 0.7f)
                } else if (!isRefreshing && pullDistance > 0f) {
                    pullDistance = 0f
                    indicatorOffset.animateTo(0f)
                }
                return Velocity.Zero
            }
        }
    }

    Box(modifier = modifier.nestedScroll(nestedScrollConnection)) {
        content()
        if (isRefreshing || indicatorOffset.value > 2f) {
            Surface(
                modifier = Modifier
                    .align(Alignment.TopCenter)
                    .offset { IntOffset(0, (indicatorOffset.value - thresholdPx * 0.55f).roundToInt()) }
                    .size(36.dp)
                    .shadow(4.dp, CircleShape),
                shape = CircleShape,
                color = colors.surfaceElevated
            ) {
                Box(contentAlignment = Alignment.Center) {
                    if (isRefreshing) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(18.dp),
                            strokeWidth = 2.dp,
                            color = colors.accentCyan
                        )
                    } else {
                        val progress = (indicatorOffset.value / thresholdPx).coerceIn(0f, 1f)
                        CircularProgressIndicator(
                            progress = progress,
                            modifier = Modifier.size(18.dp),
                            strokeWidth = 2.dp,
                            color = colors.accentCyan
                        )
                    }
                }
            }
        }
    }
}

/**
 * Section header with uppercase tracking micro-label and optional trailing widget.
 */
@Composable
fun SnowSectionHeader(
    title: String,
    modifier: Modifier = Modifier,
    trailing: @Composable (() -> Unit)? = null
) {
    val colors = LocalSnowColors.current
    Row(
        modifier = modifier
            .fillMaxWidth()
            .padding(vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text(
            text = title.uppercase(),
            style = SnowTypography.labelSmall.copy(letterSpacing = 1.sp),
            color = colors.textMuted
        )
        trailing?.invoke()
    }
}

/**
 * Filter chip pill for All / PCs / Phones filter states.
 */
@Composable
fun SnowFilterChip(
    text: String,
    selected: Boolean,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    count: Int? = null,
    enabled: Boolean = true
) {
    val colors = LocalSnowColors.current
    val shape = RoundedCornerShape(9999.dp)

    val bg = if (selected) {
        if (colors.isDark) Color(0xFF242424) else Color(0xFFDBEAFE)
    } else {
        if (colors.isDark) Color(0xFF181818) else Color(0xFFF1F5F9)
    }

    val textCol = if (selected) {
        if (colors.isDark) Color.White else Color(0xFF1E3A8A)
    } else {
        colors.textSecondary
    }

    val borderStroke = if (selected && colors.isDark) {
        BorderStroke(1.dp, colors.accentCyan.copy(alpha = 0.5f))
    } else if (selected) {
        BorderStroke(1.dp, Color(0xFF93C5FD))
    } else {
        BorderStroke(1.dp, colors.borderSubtle)
    }

    Surface(
        modifier = modifier
            .clip(shape)
            .alpha(if (enabled) 1f else 0.5f)
            .border(borderStroke, shape)
            .clickable(enabled = enabled, onClick = onClick),
        shape = shape,
        color = bg
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 14.dp, vertical = 6.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                text = text,
                color = textCol,
                style = SnowTypography.labelMedium.copy(
                    fontWeight = if (selected) FontWeight.SemiBold else FontWeight.Normal
                )
            )
            if (count != null && count > 0) {
                Spacer(modifier = Modifier.width(6.dp))
                Box(
                    modifier = Modifier
                        .clip(CircleShape)
                        .background(if (selected) colors.accentBlue else colors.border)
                        .padding(horizontal = 6.dp, vertical = 2.dp)
                ) {
                    Text(
                        text = count.toString(),
                        color = Color.White,
                        style = SnowTypography.labelSmall.copy(fontSize = 10.sp)
                    )
                }
            }
        }
    }
}

/**
 * Standardized empty state.
 */
@Composable
fun SnowEmptyState(
    title: String,
    description: String,
    icon: ImageVector,
    modifier: Modifier = Modifier,
    actionText: String? = null,
    onAction: (() -> Unit)? = null
) {
    val colors = LocalSnowColors.current
    Column(
        modifier = modifier
            .fillMaxWidth()
            .padding(32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        Box(
            modifier = Modifier
                .size(64.dp)
                .clip(CircleShape)
                .background(colors.surfaceElevated),
            contentAlignment = Alignment.Center
        ) {
            Icon(
                imageVector = icon,
                contentDescription = null,
                tint = colors.textSecondary,
                modifier = Modifier.size(32.dp)
            )
        }
        Spacer(modifier = Modifier.height(16.dp))
        Text(
            text = title,
            style = SnowTypography.titleMedium,
            color = colors.textPrimary
        )
        Spacer(modifier = Modifier.height(6.dp))
        Text(
            text = description,
            style = SnowTypography.bodyMedium,
            color = colors.textSecondary
        )
        if (actionText != null && onAction != null) {
            Spacer(modifier = Modifier.height(18.dp))
            SnowTonalButton(text = actionText, onClick = onAction)
        }
    }
}
