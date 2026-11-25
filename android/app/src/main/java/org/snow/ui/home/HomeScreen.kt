package org.snow.ui.home

import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CameraAlt
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Computer
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.FileDownload
import androidx.compose.material.icons.filled.FileUpload
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material.icons.filled.Image
import androidx.compose.material.icons.filled.Link
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Notifications
import androidx.compose.material.icons.filled.NotificationsActive
import androidx.compose.material.icons.filled.PhoneAndroid
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.PushPin
import androidx.compose.material.icons.filled.QrCodeScanner
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.ScreenShare
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Send
import androidx.compose.material.icons.filled.Share
import androidx.compose.material.icons.filled.Smartphone
import androidx.compose.material.icons.filled.Terminal
import androidx.compose.material.icons.filled.Widgets
import androidx.compose.material3.Divider
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import org.snow.network.ConnectionState
import org.snow.ui.ActiveTransferInfo
import org.snow.ui.SnowUiRepository.ClipboardItemDto
import org.snow.ui.PcTelemetry
import org.snow.ui.PhoneTelemetry
import org.snow.ui.SavedDevice
import org.snow.ui.components.SnowBadgeType
import org.snow.ui.components.SnowCard
import org.snow.ui.components.SnowGradientButton
import org.snow.ui.components.SnowSectionHeader
import org.snow.ui.components.SnowStatusBadge
import org.snow.ui.components.SnowTonalButton
import org.snow.ui.navigation.SnowTab
import org.snow.ui.theme.LocalSnowColors
import org.snow.ui.theme.SnowTypography

/**
 * Flagship Home Screen handling:
 * - State A: PC Connected
 * - State B: Peer Android Connected
 * - State C: Disconnected / Searching / Reconnecting
 * - State D: Active Transfer progress
 */
@Composable
fun HomeScreen(
    connectionState: ConnectionState,
    connectedDevice: SavedDevice?,
    connectedEndpoint: String?,
    pcTelemetry: PcTelemetry,
    phoneTelemetry: PhoneTelemetry,
    activeTransfer: ActiveTransferInfo?,
    clipboardItems: List<ClipboardItemDto>,
    instantClipboardSync: Boolean,
    onToggleInstantClipboardSync: (Boolean) -> Unit,
    onLockPc: () -> Unit,
    onRingPhone: () -> Unit,
    onSendFiles: () -> Unit,
    onOpenTool: (String) -> Unit,
    onNavigateTab: (SnowTab) -> Unit,
    onOpenConnectSheet: () -> Unit,
    onCancelTransfer: () -> Unit,
    desktopWallpaper: android.graphics.Bitmap? = null,
    onRefreshWallpaper: () -> Unit = {},
    activePermissionProfile: String = "full_control",
    onSelectAccessProfile: (String) -> Unit = {},
    onApplyClipboardItem: (ClipboardItemDto) -> Unit = {},
    onShareClipboardItem: (ClipboardItemDto) -> Unit = {},
    onPinClipboardItem: (String, Boolean) -> Unit = { _, _ -> },
    onClearClipboardBuffer: () -> Unit = {},
    scrollToClipboardTrigger: Int = 0,
    modifier: Modifier = Modifier
) {
    val colors = LocalSnowColors.current
    val listState = rememberLazyListState()
    val isPhonePeer = connectedDevice?.isPhone == true

    LaunchedEffect(scrollToClipboardTrigger) {
        if (scrollToClipboardTrigger > 0) {
            val clipboardHeaderIdx = if (activeTransfer != null) 3 else 2
            listState.animateScrollToItem(clipboardHeaderIdx)
        }
    }

    LazyColumn(
        state = listState,
        modifier = modifier
            .fillMaxSize()
            .padding(horizontal = 16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        item {
            Spacer(modifier = Modifier.height(8.dp))
        }

        // Active Transfer Card (State D)
        if (activeTransfer != null) {
            item {
                ActiveTransferCard(
                    transfer = activeTransfer,
                    onCancel = onCancelTransfer
                )
            }
        }

        // Main State Card
        when (connectionState) {
            ConnectionState.CONNECTED -> {
                if (isPhonePeer) {
                    // State B: Peer Android Connected
                    item {
                        AndroidPeerHeroCard(
                            device = connectedDevice,
                            phoneTelemetry = phoneTelemetry,
                            activePermissionProfile = activePermissionProfile,
                            onSelectAccessProfile = onSelectAccessProfile,
                            onRingPhone = onRingPhone,
                            onSendFiles = onSendFiles,
                            onOpenTool = onOpenTool
                        )
                    }
                } else {
                    // State A: PC Connected
                    item {
                        PcConnectedHeroCard(
                            device = connectedDevice,
                            endpoint = connectedEndpoint,
                            pcTelemetry = pcTelemetry,
                            wallpaperBitmap = desktopWallpaper,
                            onRefreshWallpaper = onRefreshWallpaper,
                            onLockPc = onLockPc,
                            onSendFiles = onSendFiles,
                            onOpenTool = onOpenTool,
                            onNavigateTab = onNavigateTab
                        )
                    }
                }
            }
            ConnectionState.CONNECTING, ConnectionState.RECONNECTING, ConnectionState.DISCONNECTED -> {
                // State C: Disconnected / Searching
                item {
                    DisconnectedRadarCard(
                        connectionState = connectionState,
                        onConnectClick = onOpenConnectSheet
                    )
                }
            }
        }

        // Shared Clipboard Buffer Section
        item {
            SnowSectionHeader(
                title = "Shared Clipboard",
                trailing = {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        if (clipboardItems.isNotEmpty()) {
                            Text(
                                text = "Clear",
                                style = SnowTypography.labelSmall,
                                color = colors.textMuted,
                                modifier = Modifier
                                    .clip(RoundedCornerShape(4.dp))
                                    .clickable(onClick = onClearClipboardBuffer)
                                    .padding(4.dp)
                            )
                            Spacer(modifier = Modifier.width(8.dp))
                        }
                        Text(
                            text = "Sync",
                            style = SnowTypography.labelSmall,
                            color = colors.textSecondary
                        )
                        Spacer(modifier = Modifier.width(6.dp))
                        Switch(
                            checked = instantClipboardSync,
                            onCheckedChange = onToggleInstantClipboardSync,
                            colors = SwitchDefaults.colors(
                                checkedThumbColor = Color.White,
                                checkedTrackColor = colors.accentBlue,
                                uncheckedThumbColor = colors.textMuted,
                                uncheckedTrackColor = colors.surfaceElevated
                            ),
                            modifier = Modifier.scale(0.8f)
                        )
                    }
                }
            )
        }

        if (clipboardItems.isEmpty()) {
            item {
                SnowCard(
                    modifier = Modifier.fillMaxWidth(),
                    cornerRadius = 16.dp
                ) {
                    Text(
                        text = "No clipboard entries yet. Copied text on linked devices will appear here automatically.",
                        style = SnowTypography.bodySmall,
                        color = colors.textSecondary
                    )
                }
            }
        } else {
            items(clipboardItems.take(5)) { item ->
                ClipboardItemCard(
                    item = item,
                    onCopy = { onApplyClipboardItem(item) },
                    onShare = { onShareClipboardItem(item) },
                    onTogglePin = { onPinClipboardItem(item.itemId, !item.isPinned) }
                )
            }
        }

        item {
            Spacer(modifier = Modifier.height(24.dp))
        }
    }
}

/**
 * State A: PC Connected Hero Card
 */
@Composable
private fun PcConnectedHeroCard(
    device: SavedDevice?,
    endpoint: String?,
    pcTelemetry: PcTelemetry,
    wallpaperBitmap: android.graphics.Bitmap?,
    onRefreshWallpaper: () -> Unit,
    onLockPc: () -> Unit,
    onSendFiles: () -> Unit,
    onOpenTool: (String) -> Unit,
    onNavigateTab: (SnowTab) -> Unit
) {
    val colors = LocalSnowColors.current
    val hostName = device?.deviceName?.ifBlank { null } ?: pcTelemetry.hostname ?: "SNOW Desktop"
    val isUsb = endpoint?.startsWith("127.0.0.1") == true || endpoint?.startsWith("localhost") == true
    val transport = if (isUsb) "USB High-Speed" else if (endpoint?.contains("relay") == true) "Relay Tunnel" else "Local Wi-Fi"

    SnowCard(
        modifier = Modifier.fillMaxWidth(),
        cornerRadius = 24.dp
    ) {
        Column {
            // C2.1: 176.dp rounded card preview showing wallpaper or arctic gradient
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(176.dp)
                    .clip(RoundedCornerShape(18.dp))
                    .background(
                        Brush.linearGradient(
                            listOf(Color(0xFF0F172A), Color(0xFF1E293B), Color(0xFF0284C7))
                        )
                    )
            ) {
                if (wallpaperBitmap != null) {
                    Image(
                        bitmap = wallpaperBitmap.asImageBitmap(),
                        contentDescription = "Desktop Snapshot",
                        contentScale = ContentScale.Crop,
                        modifier = Modifier.fillMaxSize()
                    )
                }

                // Top-right Refresh Icon Button
                Surface(
                    modifier = Modifier
                        .align(Alignment.TopEnd)
                        .padding(10.dp)
                        .size(34.dp)
                        .clip(CircleShape)
                        .clickable(onClick = onRefreshWallpaper),
                    color = Color.Black.copy(alpha = 0.5f)
                ) {
                    Box(contentAlignment = Alignment.Center) {
                        Icon(
                            imageVector = Icons.Default.Refresh,
                            contentDescription = "Refresh Desktop",
                            tint = Color.White,
                            modifier = Modifier.size(18.dp)
                        )
                    }
                }

                // Bottom-left glass "Windows PC" tag
                Surface(
                    modifier = Modifier
                        .align(Alignment.BottomStart)
                        .padding(10.dp),
                    shape = RoundedCornerShape(8.dp),
                    color = Color.Black.copy(alpha = 0.6f)
                ) {
                    Row(
                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(
                            imageVector = Icons.Default.Computer,
                            contentDescription = null,
                            tint = Color(0xFF38BDF8),
                            modifier = Modifier.size(14.dp)
                        )
                        Spacer(modifier = Modifier.width(6.dp))
                        Text(
                            text = "Windows PC",
                            style = SnowTypography.labelSmall.copy(fontSize = 11.sp, fontWeight = FontWeight.SemiBold),
                            color = Color.White
                        )
                    }
                }
            }

            Spacer(modifier = Modifier.height(16.dp))

            // Header Row
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column {
                    Text(
                        text = hostName,
                        style = SnowTypography.titleMedium,
                        color = colors.textPrimary
                    )
                    Text(
                        text = "$transport • Active",
                        style = SnowTypography.bodySmall,
                        color = colors.textSecondary
                    )
                }

                SnowStatusBadge(text = "CONNECTED", type = SnowBadgeType.CONNECTED)
            }

            Spacer(modifier = Modifier.height(16.dp))

            // Telemetry Strip
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(14.dp))
                    .background(colors.surfaceElevated)
                    .padding(12.dp),
                horizontalArrangement = Arrangement.SpaceAround
            ) {
                val cpuVal = pcTelemetry.cpuPercent?.toInt()?.let { "$it%" } ?: "--"
                val ramVal = pcTelemetry.memoryPercent?.toInt()?.let { "$it%" } ?: "--"
                val batteryVal = pcTelemetry.batteryPercent?.let { if (it >= 0) "$it%" else "AC Power" } ?: "AC Power"
                TelemetryMetric(label = "CPU", value = cpuVal)
                TelemetryMetric(label = "RAM", value = ramVal)
                TelemetryMetric(label = "POWER", value = batteryVal)
            }

            Spacer(modifier = Modifier.height(16.dp))

            // Quick Actions: Brand gradient Send Files + Lock PC
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                SnowGradientButton(
                    text = "Send Files",
                    icon = Icons.Default.Send,
                    onClick = onSendFiles,
                    modifier = Modifier.weight(1f)
                )
                SnowTonalButton(
                    text = "Lock PC",
                    icon = Icons.Default.Lock,
                    onClick = onLockPc,
                    modifier = Modifier.weight(1f)
                )
            }

            Spacer(modifier = Modifier.height(18.dp))
            Divider(color = colors.borderSubtle)
            Spacer(modifier = Modifier.height(14.dp))

            // 5 Circular Controls: Screen, Camera, Media, Apps, Terminal
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                CircularToolButton(
                    label = "Screen",
                    icon = Icons.Default.ScreenShare,
                    onClick = { onOpenTool("media_screen") }
                )
                CircularToolButton(
                    label = "Camera",
                    icon = Icons.Default.CameraAlt,
                    onClick = { onOpenTool("media_camera") }
                )
                CircularToolButton(
                    label = "Media",
                    icon = Icons.Default.PlayArrow,
                    onClick = { onOpenTool("media_control") }
                )
                CircularToolButton(
                    label = "Apps",
                    icon = Icons.Default.Widgets,
                    onClick = { onOpenTool("apps") }
                )
                CircularToolButton(
                    label = "Terminal",
                    icon = Icons.Default.Terminal,
                    onClick = { onOpenTool("terminal") }
                )
            }
        }
    }
}

/**
 * State B: Peer Android Connected Hero Card
 */
@Composable
private fun AndroidPeerHeroCard(
    device: SavedDevice?,
    phoneTelemetry: PhoneTelemetry,
    activePermissionProfile: String,
    onSelectAccessProfile: (String) -> Unit,
    onRingPhone: () -> Unit,
    onSendFiles: () -> Unit,
    onOpenTool: (String) -> Unit
) {
    val colors = LocalSnowColors.current
    val peerName = device?.deviceName?.ifBlank { null } ?: "Android Peer"

    SnowCard(
        modifier = Modifier.fillMaxWidth(),
        cornerRadius = 24.dp
    ) {
        Column {
            // Sleek smartphone frame preview
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(110.dp)
                    .clip(RoundedCornerShape(18.dp))
                    .background(
                        Brush.linearGradient(
                            listOf(Color(0xFF0F172A), Color(0xFF1E293B), Color(0xFF0F766E))
                        )
                    )
                    .padding(12.dp)
            ) {
                // Top phone frame pill notch
                Box(
                    modifier = Modifier
                        .size(width = 44.dp, height = 6.dp)
                        .clip(RoundedCornerShape(9999.dp))
                        .background(Color.White.copy(alpha = 0.25f))
                        .align(Alignment.TopCenter)
                )

                // Phone identity and transport badge
                Row(
                    modifier = Modifier
                        .align(Alignment.BottomStart)
                        .fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            imageVector = Icons.Default.Smartphone,
                            contentDescription = null,
                            tint = colors.accentCyan,
                            modifier = Modifier.size(20.dp)
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = peerName,
                            style = SnowTypography.titleSmall,
                            color = Color.White
                        )
                    }
                    SnowStatusBadge(text = "DIRECT PEER", type = SnowBadgeType.CONNECTED)
                }
            }

            Spacer(modifier = Modifier.height(16.dp))

            // Telemetry strip: Battery, RAM, Latency
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(14.dp))
                    .background(colors.surfaceElevated)
                    .padding(12.dp),
                horizontalArrangement = Arrangement.SpaceAround
            ) {
                val bat = if (phoneTelemetry.batteryPercent >= 0) "${phoneTelemetry.batteryPercent}%" else "--"
                TelemetryMetric(label = "BATTERY", value = bat)
                val ram = if (phoneTelemetry.ramTotalBytes != null && phoneTelemetry.ramTotalBytes > 0 && phoneTelemetry.ramAvailableBytes != null) {
                    val used = phoneTelemetry.ramTotalBytes - phoneTelemetry.ramAvailableBytes
                    "${(used * 100 / phoneTelemetry.ramTotalBytes).toInt()}%"
                } else "--"
                TelemetryMetric(label = "RAM", value = ram)
                val ping = "Direct"
                TelemetryMetric(label = "LATENCY", value = ping)
            }

            Spacer(modifier = Modifier.height(16.dp))

            // Actions: Ring Phone & Send Files
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                SnowTonalButton(
                    text = "Ring Phone",
                    icon = Icons.Default.NotificationsActive,
                    onClick = onRingPhone,
                    modifier = Modifier.weight(1f)
                )
                SnowGradientButton(
                    text = "Send Files",
                    icon = Icons.Default.Send,
                    onClick = onSendFiles,
                    modifier = Modifier.weight(1f)
                )
            }

            Spacer(modifier = Modifier.height(18.dp))
            Divider(color = colors.borderSubtle)
            Spacer(modifier = Modifier.height(14.dp))

            // 2x3 capabilities grid
            Text(
                text = "PEER CAPABILITIES",
                style = SnowTypography.labelSmall.copy(letterSpacing = 1.sp),
                color = colors.textMuted
            )
            Spacer(modifier = Modifier.height(10.dp))
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                PeerCapabilityChip(label = "Clipboard", icon = Icons.Default.ContentCopy, onClick = { onOpenTool("clipboard") })
                PeerCapabilityChip(label = "Notifications", icon = Icons.Default.Notifications, onClick = { onOpenTool("notifications") })
                PeerCapabilityChip(label = "Launch Apps", icon = Icons.Default.Widgets, onClick = { onOpenTool("apps") })
            }
            Spacer(modifier = Modifier.height(8.dp))
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                PeerCapabilityChip(label = "Media", icon = Icons.Default.PlayArrow, onClick = { onOpenTool("media_control") })
                PeerCapabilityChip(label = "Browse Files", icon = Icons.Default.Folder, onClick = { onOpenTool("files") })
                PeerCapabilityChip(label = "Share Link", icon = Icons.Default.Link, onClick = { onOpenTool("share") })
            }

            Spacer(modifier = Modifier.height(18.dp))
            Divider(color = colors.borderSubtle)
            Spacer(modifier = Modifier.height(14.dp))

            // 3-Segment Access Profile card
            Text(
                text = "ACCESS PROFILE",
                style = SnowTypography.labelSmall.copy(letterSpacing = 1.sp),
                color = colors.textMuted
            )
            Spacer(modifier = Modifier.height(10.dp))
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                AccessProfilePill(
                    label = "Full Control",
                    selected = activePermissionProfile == "full_control",
                    onClick = { onSelectAccessProfile("full_control") },
                    modifier = Modifier.weight(1f)
                )
                AccessProfilePill(
                    label = "Files & Clip",
                    selected = activePermissionProfile == "files_and_clipboard",
                    onClick = { onSelectAccessProfile("files_and_clipboard") },
                    modifier = Modifier.weight(1f)
                )
                AccessProfilePill(
                    label = "Clip Only",
                    selected = activePermissionProfile == "clipboard_only",
                    onClick = { onSelectAccessProfile("clipboard_only") },
                    modifier = Modifier.weight(1f)
                )
            }
        }
    }
}

@Composable
private fun PeerCapabilityChip(
    label: String,
    icon: ImageVector,
    onClick: () -> Unit
) {
    val colors = LocalSnowColors.current
    Surface(
        modifier = Modifier
            .clip(RoundedCornerShape(12.dp))
            .border(1.dp, colors.borderSubtle, RoundedCornerShape(12.dp))
            .clickable(onClick = onClick),
        color = colors.surfaceElevated
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 10.dp, vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(
                imageVector = icon,
                contentDescription = null,
                tint = colors.accentCyan,
                modifier = Modifier.size(16.dp)
            )
            Spacer(modifier = Modifier.width(6.dp))
            Text(
                text = label,
                style = SnowTypography.labelSmall,
                color = colors.textPrimary
            )
        }
    }
}

@Composable
private fun AccessProfilePill(
    label: String,
    selected: Boolean,
    onClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    val colors = LocalSnowColors.current
    Surface(
        modifier = modifier
            .clip(RoundedCornerShape(9999.dp))
            .border(1.dp, if (selected) colors.accentBlue else colors.borderSubtle, RoundedCornerShape(9999.dp))
            .clickable(onClick = onClick),
        color = if (selected) (if (colors.isDark) Color(0xFF1E3A8A) else Color(0xFFDBEAFE)) else colors.surfaceElevated
    ) {
        Box(
            modifier = Modifier.padding(vertical = 8.dp),
            contentAlignment = Alignment.Center
        ) {
            Text(
                text = label,
                style = SnowTypography.labelSmall.copy(fontWeight = if (selected) FontWeight.Bold else FontWeight.Normal),
                color = if (selected) (if (colors.isDark) Color(0xFF93C5FD) else Color(0xFF1E3A8A)) else colors.textMuted
            )
        }
    }
}

/**
 * State C: Disconnected / Radar Searching Card
 */
@Composable
private fun DisconnectedRadarCard(
    connectionState: ConnectionState,
    onConnectClick: () -> Unit
) {
    val colors = LocalSnowColors.current

    val infiniteTransition = rememberInfiniteTransition(label = "radar")
    val pulseScale by infiniteTransition.animateFloat(
        initialValue = 0.8f,
        targetValue = 1.25f,
        animationSpec = infiniteRepeatable(
            animation = tween(1400, easing = FastOutSlowInEasing),
            repeatMode = RepeatMode.Reverse
        ),
        label = "pulse"
    )

    SnowCard(
        modifier = Modifier.fillMaxWidth(),
        cornerRadius = 24.dp
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(vertical = 12.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Box(
                modifier = Modifier.size(96.dp),
                contentAlignment = Alignment.Center
            ) {
                // Outer Pulse Ring
                Box(
                    modifier = Modifier
                        .size(80.dp)
                        .scale(pulseScale)
                        .clip(CircleShape)
                        .background(colors.accentBlue.copy(alpha = 0.12f))
                )
                // Center Icon Circle
                Box(
                    modifier = Modifier
                        .size(54.dp)
                        .clip(CircleShape)
                        .background(colors.surfaceElevated)
                        .border(1.dp, colors.border, CircleShape),
                    contentAlignment = Alignment.Center
                ) {
                    Icon(
                        imageVector = Icons.Default.Search,
                        contentDescription = null,
                        tint = colors.accentCyan,
                        modifier = Modifier.size(26.dp)
                    )
                }
            }

            Spacer(modifier = Modifier.height(12.dp))

            Text(
                text = if (connectionState == ConnectionState.RECONNECTING) "Reconnecting to Host..." else "Searching for Peers Nearby",
                style = SnowTypography.titleMedium,
                color = colors.textPrimary
            )

            Spacer(modifier = Modifier.height(6.dp))

            Text(
                text = "Ensure your PC or peer phone is running SNOW on the same Wi-Fi or connected via USB.",
                style = SnowTypography.bodySmall,
                color = colors.textSecondary,
                textAlign = androidx.compose.ui.text.style.TextAlign.Center,
                modifier = Modifier.padding(horizontal = 16.dp)
            )

            Spacer(modifier = Modifier.height(20.dp))

            SnowGradientButton(
                text = "Scan QR or Connect",
                icon = Icons.Default.QrCodeScanner,
                onClick = onConnectClick
            )
        }
    }
}

/**
 * State D: Active Transfer Progress Card
 */
@Composable
private fun ActiveTransferCard(
    transfer: ActiveTransferInfo,
    onCancel: () -> Unit
) {
    val colors = LocalSnowColors.current
    val isUpload = transfer.direction.equals("upload", ignoreCase = true)
    val progress = if (transfer.totalBytes > 0) (transfer.bytesTransferred.toFloat() / transfer.totalBytes).coerceIn(0f, 1f) else 0f

    SnowCard(
        modifier = Modifier.fillMaxWidth(),
        cornerRadius = 18.dp
    ) {
        Column {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        imageVector = if (isUpload) Icons.Default.FileUpload else Icons.Default.FileDownload,
                        contentDescription = null,
                        tint = colors.accentCyan,
                        modifier = Modifier.size(22.dp)
                    )
                    Spacer(modifier = Modifier.width(10.dp))
                    Column {
                        Text(
                            text = transfer.fileName,
                            style = SnowTypography.bodyMedium.copy(fontWeight = FontWeight.SemiBold),
                            color = colors.textPrimary
                        )
                        Text(
                            text = if (isUpload) "Uploading..." else "Downloading...",
                            style = SnowTypography.bodySmall,
                            color = colors.textSecondary
                        )
                    }
                }

                Surface(
                    modifier = Modifier
                        .size(28.dp)
                        .clip(CircleShape)
                        .clickable(onClick = onCancel),
                    color = colors.surfaceElevated
                ) {
                    Box(contentAlignment = Alignment.Center) {
                        Icon(
                            imageVector = Icons.Default.Close,
                            contentDescription = "Cancel Transfer",
                            tint = colors.textMuted,
                            modifier = Modifier.size(16.dp)
                        )
                    }
                }
            }

            Spacer(modifier = Modifier.height(12.dp))

            LinearProgressIndicator(
                progress = progress,
                modifier = Modifier
                    .fillMaxWidth()
                    .height(6.dp)
                    .clip(RoundedCornerShape(9999.dp)),
                color = colors.accentCyan,
                trackColor = colors.surfaceElevated
            )

            Spacer(modifier = Modifier.height(6.dp))

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Text(
                    text = "${(progress * 100).toInt()}%",
                    style = SnowTypography.labelSmall,
                    color = colors.textPrimary
                )
                Text(
                    text = "${transfer.bytesTransferred / (1024 * 1024)} / ${transfer.totalBytes / (1024 * 1024)} MB",
                    style = SnowTypography.labelSmall,
                    color = colors.textSecondary
                )
            }
        }
    }
}

@Composable
private fun TelemetryMetric(label: String, value: String) {
    val colors = LocalSnowColors.current
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Text(
            text = label,
            style = SnowTypography.labelSmall.copy(fontSize = 10.sp),
            color = colors.textMuted
        )
        Spacer(modifier = Modifier.height(2.dp))
        Text(
            text = value,
            style = SnowTypography.titleSmall.copy(fontWeight = FontWeight.Bold),
            color = colors.textPrimary
        )
    }
}

@Composable
private fun CircularToolButton(
    label: String,
    icon: ImageVector,
    onClick: () -> Unit
) {
    val colors = LocalSnowColors.current
    Column(
        horizontalAlignment = Alignment.CenterHorizontally,
        modifier = Modifier
            .clip(RoundedCornerShape(12.dp))
            .clickable(onClick = onClick)
            .padding(4.dp)
    ) {
        Surface(
            modifier = Modifier
                .size(48.dp)
                .clip(CircleShape)
                .border(1.dp, colors.borderSubtle, CircleShape),
            color = colors.surfaceElevated
        ) {
            Box(contentAlignment = Alignment.Center) {
                Icon(
                    imageVector = icon,
                    contentDescription = label,
                    tint = colors.textPrimary,
                    modifier = Modifier.size(22.dp)
                )
            }
        }
        Spacer(modifier = Modifier.height(6.dp))
        Text(
            text = label,
            style = SnowTypography.labelSmall.copy(fontSize = 10.sp),
            color = colors.textSecondary
        )
    }
}

@Composable
private fun ClipboardItemCard(
    item: ClipboardItemDto,
    onCopy: () -> Unit,
    onShare: () -> Unit,
    onTogglePin: () -> Unit
) {
    val colors = LocalSnowColors.current
    val isImage = item.type == "image"

    Surface(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(14.dp))
            .border(1.dp, if (item.isPinned) colors.accentCyan.copy(alpha = 0.5f) else colors.borderSubtle, RoundedCornerShape(14.dp)),
        color = colors.surface
    ) {
        Row(
            modifier = Modifier.padding(12.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            if (isImage) {
                Surface(
                    modifier = Modifier
                        .size(40.dp)
                        .clip(RoundedCornerShape(8.dp)),
                    color = colors.accentBlue.copy(alpha = 0.15f)
                ) {
                    Box(contentAlignment = Alignment.Center) {
                        Icon(
                            imageVector = Icons.Default.Image,
                            contentDescription = "Image Clipboard Item",
                            tint = colors.accentBlue,
                            modifier = Modifier.size(20.dp)
                        )
                    }
                }
                Spacer(modifier = Modifier.width(10.dp))
            }

            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = item.previewText.ifBlank { if (isImage) "[Image Clip]" else "[Empty]" },
                    style = SnowTypography.bodyMedium,
                    color = colors.textPrimary,
                    maxLines = 2
                )
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = "${if (isImage) "Image" else "Text"} • ${item.sourceDevice.ifBlank { "Remote" }} • ${item.sizeBytes} B",
                    style = SnowTypography.bodySmall,
                    color = colors.textMuted
                )
            }
            Spacer(modifier = Modifier.width(8.dp))

            // Action: Toggle Pin
            Surface(
                modifier = Modifier
                    .size(32.dp)
                    .clip(CircleShape)
                    .clickable(onClick = onTogglePin),
                color = colors.surfaceElevated
            ) {
                Box(contentAlignment = Alignment.Center) {
                    Icon(
                        imageVector = Icons.Default.PushPin,
                        contentDescription = "Pin",
                        tint = if (item.isPinned) colors.accentCyan else colors.textMuted,
                        modifier = Modifier.size(16.dp)
                    )
                }
            }

            Spacer(modifier = Modifier.width(6.dp))

            // Action: Share
            Surface(
                modifier = Modifier
                    .size(32.dp)
                    .clip(CircleShape)
                    .clickable(onClick = onShare),
                color = colors.surfaceElevated
            ) {
                Box(contentAlignment = Alignment.Center) {
                    Icon(
                        imageVector = Icons.Default.Share,
                        contentDescription = "Share",
                        tint = colors.textSecondary,
                        modifier = Modifier.size(16.dp)
                    )
                }
            }

            Spacer(modifier = Modifier.width(6.dp))

            // Action: Copy
            Surface(
                modifier = Modifier
                    .size(32.dp)
                    .clip(CircleShape)
                    .clickable(onClick = onCopy),
                color = colors.surfaceElevated
            ) {
                Box(contentAlignment = Alignment.Center) {
                    Icon(
                        imageVector = Icons.Default.ContentCopy,
                        contentDescription = "Copy",
                        tint = colors.accentCyan,
                        modifier = Modifier.size(16.dp)
                    )
                }
            }
        }
    }
}
