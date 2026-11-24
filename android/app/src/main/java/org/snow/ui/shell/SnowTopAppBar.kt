package org.snow.ui.shell

import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Notifications
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import org.snow.R
import org.snow.network.ConnectionState
import org.snow.ui.theme.LocalSnowColors
import org.snow.ui.theme.SnowTypography

/**
 * Top App Bar with:
 * - Brand Logo & Name
 * - Center Floating Device Capsule
 * - Right Approvals & Activity Bell with cyan unread badge
 */
@Composable
fun SnowTopAppBar(
    connectionState: ConnectionState,
    connectedDeviceName: String,
    transportMode: String,
    unreadApprovalsCount: Int,
    onCapsuleClick: () -> Unit,
    onApprovalsClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    val colors = LocalSnowColors.current

    Surface(
        modifier = modifier
            .fillMaxWidth()
            .height(64.dp)
            .border(width = 1.dp, color = colors.borderSubtle, shape = RoundedCornerShape(0.dp)),
        color = colors.bars
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            // Brand Logo & Title
            Row(
                verticalAlignment = Alignment.CenterVertically
            ) {
                Image(
                    painter = painterResource(id = R.drawable.ic_snow_logo),
                    contentDescription = "SNOW Logo",
                    modifier = Modifier.size(28.dp)
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = "SNOW",
                    style = SnowTypography.titleLarge.copy(
                        fontWeight = FontWeight.Bold,
                        letterSpacing = 1.sp
                    ),
                    color = colors.textPrimary
                )
            }

            // Central Floating Device Capsule
            SnowDeviceCapsule(
                connectionState = connectionState,
                deviceName = connectedDeviceName,
                transport = transportMode,
                onClick = onCapsuleClick
            )

            // Approvals Bell
            Box(
                contentAlignment = Alignment.TopEnd
            ) {
                IconButton(onClick = onApprovalsClick) {
                    Icon(
                        imageVector = Icons.Default.Notifications,
                        contentDescription = "Approvals & Activity",
                        tint = colors.textPrimary,
                        modifier = Modifier.size(24.dp)
                    )
                }
                if (unreadApprovalsCount > 0) {
                    Box(
                        modifier = Modifier
                            .padding(top = 6.dp, end = 6.dp)
                            .size(16.dp)
                            .clip(CircleShape)
                            .background(colors.accentCyan),
                        contentAlignment = Alignment.Center
                    ) {
                        Text(
                            text = unreadApprovalsCount.toString(),
                            color = Color.Black,
                            style = SnowTypography.labelSmall.copy(
                                fontSize = 9.sp,
                                fontWeight = FontWeight.Bold
                            )
                        )
                    }
                }
            }
        }
    }
}

/**
 * Clickable Floating Device Capsule: `<Dot> <Device Name> • <Transport> ▾`
 */
@Composable
fun SnowDeviceCapsule(
    connectionState: ConnectionState,
    deviceName: String,
    transport: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    val colors = LocalSnowColors.current

    val dotColor = when (connectionState) {
        ConnectionState.CONNECTED -> colors.accentEmerald
        ConnectionState.CONNECTING, ConnectionState.RECONNECTING -> colors.accentCyan
        ConnectionState.DISCONNECTED -> colors.textMuted
    }

    val labelText = when (connectionState) {
        ConnectionState.CONNECTED -> "$deviceName • $transport"
        ConnectionState.CONNECTING -> "Connecting..."
        ConnectionState.RECONNECTING -> "Reconnecting..."
        ConnectionState.DISCONNECTED -> "No device"
    }

    val shape = RoundedCornerShape(9999.dp)

    Surface(
        modifier = modifier
            .widthIn(max = 180.dp)
            .clip(shape)
            .border(1.dp, colors.border, shape)
            .clickable(onClick = onClick),
        shape = shape,
        color = colors.surfaceElevated
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Box(
                modifier = Modifier
                    .size(6.dp)
                    .clip(CircleShape)
                    .background(dotColor)
            )
            Spacer(modifier = Modifier.width(6.dp))
            Text(
                text = labelText,
                style = SnowTypography.labelSmall,
                color = colors.textPrimary,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
                modifier = Modifier.weight(1f, fill = false)
            )
            Spacer(modifier = Modifier.width(4.dp))
            Text(
                text = "▾",
                style = SnowTypography.labelSmall,
                color = colors.textSecondary
            )
        }
    }
}
