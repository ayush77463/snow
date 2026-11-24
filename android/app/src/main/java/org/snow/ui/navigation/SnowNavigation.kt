package org.snow.ui.navigation

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Build
import androidx.compose.material.icons.filled.Devices
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.Icon
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.unit.dp
import org.snow.ui.theme.LocalSnowColors
import org.snow.ui.theme.SnowTypography

enum class SnowTab(
    val title: String,
    val icon: ImageVector
) {
    HOME("Home", Icons.Default.Home),
    DEVICES("Devices", Icons.Default.Devices),
    TOOLS("Tools", Icons.Default.Build),
    SETTINGS("Settings", Icons.Default.Settings)
}

/**
 * 4-Tab Bottom Navigation Bar matching Material 3 and Pixel/Gemini design tokens.
 * 80.dp height, flush hairline top border, active ice-blue/cyan tinted pill, label-sm.
 */
@Composable
fun SnowBottomNavigationBar(
    currentTab: SnowTab,
    onTabSelected: (SnowTab) -> Unit,
    modifier: Modifier = Modifier
) {
    val colors = LocalSnowColors.current

    Surface(
        modifier = modifier
            .fillMaxWidth()
            .height(80.dp)
            .border(width = 1.dp, color = colors.borderSubtle, shape = RoundedCornerShape(0.dp)),
        color = colors.bars
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 8.dp, vertical = 8.dp),
            horizontalArrangement = Arrangement.SpaceAround,
            verticalAlignment = Alignment.CenterVertically
        ) {
            SnowTab.values().forEach { tab ->
                val selected = currentTab == tab
                val activeBg = if (colors.isDark) Color(0xFF242424) else Color(0xFFEFF6FF)
                val activeIconTint = if (colors.isDark) colors.accentCyan else colors.accentBlue
                val inactiveTint = colors.textMuted

                Column(
                    modifier = Modifier
                        .weight(1f)
                        .clip(RoundedCornerShape(16.dp))
                        .clickable { onTabSelected(tab) }
                        .padding(vertical = 4.dp),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.Center
                ) {
                    Box(
                        modifier = Modifier
                            .clip(RoundedCornerShape(9999.dp))
                            .background(if (selected) activeBg else Color.Transparent)
                            .padding(horizontal = 16.dp, vertical = 4.dp),
                        contentAlignment = Alignment.Center
                    ) {
                        Icon(
                            imageVector = tab.icon,
                            contentDescription = tab.title,
                            tint = if (selected) activeIconTint else inactiveTint,
                            modifier = Modifier.size(24.dp)
                        )
                    }
                    Text(
                        text = tab.title,
                        style = SnowTypography.labelSmall,
                        color = if (selected) colors.textPrimary else inactiveTint
                    )
                }
            }
        }
    }
}
