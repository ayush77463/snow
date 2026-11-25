package org.snow.ui.tools

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
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.ArrowUpward
import androidx.compose.material.icons.filled.Build
import androidx.compose.material.icons.filled.CameraAlt
import androidx.compose.material.icons.filled.Clear
import androidx.compose.material.icons.filled.Download
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material.icons.filled.FolderOpen
import androidx.compose.material.icons.filled.InsertDriveFile
import androidx.compose.material.icons.filled.Pause
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.ScreenShare
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.SkipNext
import androidx.compose.material.icons.filled.SkipPrevious
import androidx.compose.material.icons.filled.StopScreenShare
import androidx.compose.material.icons.filled.Terminal
import androidx.compose.material.icons.filled.Upload
import androidx.compose.material.icons.filled.VolumeDown
import androidx.compose.material.icons.filled.VolumeUp
import androidx.compose.material.icons.filled.Widgets
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Divider
import androidx.compose.material3.Icon
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import org.snow.ui.PcFileItem
import org.snow.ui.SnowUiRepository
import org.snow.ui.TerminalExecutionState
import kotlin.math.roundToInt
import org.snow.ui.components.SnowBadgeType
import org.snow.ui.components.SnowCard
import org.snow.ui.components.SnowEmptyState
import org.snow.ui.components.SnowFilterChip
import org.snow.ui.components.SnowGradientButton
import org.snow.ui.components.SnowOutlinedButton
import org.snow.ui.components.SnowSectionHeader
import org.snow.ui.components.SnowStatusBadge
import org.snow.ui.components.SnowTonalButton
import org.snow.ui.dashboard.AppLauncherBottomSheet.WindowsAppItem
import org.snow.ui.theme.LocalSnowColors
import org.snow.ui.theme.SnowTypography

enum class ToolSubTab(val title: String) {
    FILES("Files"),
    APPS("Apps"),
    MEDIA("Media"),
    TERMINAL("Terminal")
}

/**
 * Flagship Tools Screen containing 4-pill switcher: Files, Apps, Media, Terminal.
 */
@Composable
fun ToolsScreen(
    currentSubTab: ToolSubTab = ToolSubTab.FILES,
    onSubTabChanged: (ToolSubTab) -> Unit = {},
    // Files parameters
    safFolderUri: String,
    filesList: List<PcFileItem>,
    currentPath: String,
    onChangeSafFolder: () -> Unit,
    onNavigatePath: (String) -> Unit,
    onDownloadFile: (PcFileItem) -> Unit,
    onUploadFile: () -> Unit,
    // Apps parameters
    allowlistedApps: List<WindowsAppItem>,
    onLaunchApp: (target: String, friendlyName: String) -> Unit,
    // Media parameters
    isScreenSharing: Boolean,
    onToggleScreenShare: (Boolean) -> Unit,
    onTriggerCameraCapture: () -> Unit,
    onSendMediaKey: (String) -> Unit,
    onSendMediaVolume: (Int) -> Unit = {},
    cameraDelivery: SnowUiRepository.CameraDeliveryInfo = SnowUiRepository.CameraDeliveryInfo(),
    onRetryCameraUpload: () -> Unit = {},
    onDismissCameraDelivery: () -> Unit = {},
    // Terminal parameters
    terminalState: TerminalExecutionState,
    onExecuteTerminalCommand: (String) -> Unit,
    onConfirmTerminalCommand: (command: String, ticket: String) -> Unit = { _, _ -> },
    onCancelTerminalCommand: () -> Unit = {},
    onClearTerminal: () -> Unit,
    modifier: Modifier = Modifier
) {
    val colors = LocalSnowColors.current

    Column(
        modifier = modifier
            .fillMaxSize()
            .padding(horizontal = 16.dp)
    ) {
        Spacer(modifier = Modifier.height(12.dp))

        // 4-Pill Segment Selector
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .clip(RoundedCornerShape(9999.dp))
                .background(colors.surfaceElevated)
                .padding(4.dp),
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            ToolSubTab.values().forEach { tab ->
                val selected = currentSubTab == tab
                Box(
                    modifier = Modifier
                        .weight(1f)
                        .clip(RoundedCornerShape(9999.dp))
                        .background(if (selected) (if (colors.isDark) Color(0xFF282828) else Color.White) else Color.Transparent)
                        .clickable { onSubTabChanged(tab) }
                        .padding(vertical = 8.dp),
                    contentAlignment = Alignment.Center
                ) {
                    Text(
                        text = tab.title,
                        style = SnowTypography.labelMedium,
                        color = if (selected) colors.textPrimary else colors.textMuted
                    )
                }
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        // Sub-screen Content
        when (currentSubTab) {
            ToolSubTab.FILES -> {
                FilesToolView(
                    safFolderUri = safFolderUri,
                    filesList = filesList,
                    currentPath = currentPath,
                    onChangeSafFolder = onChangeSafFolder,
                    onNavigatePath = onNavigatePath,
                    onDownloadFile = onDownloadFile,
                    onUploadFile = onUploadFile
                )
            }
            ToolSubTab.APPS -> {
                AppsToolView(
                    allowlistedApps = allowlistedApps,
                    onLaunchApp = onLaunchApp
                )
            }
            ToolSubTab.MEDIA -> {
                MediaToolView(
                    isScreenSharing = isScreenSharing,
                    onToggleScreenShare = onToggleScreenShare,
                    onTriggerCameraCapture = onTriggerCameraCapture,
                    onSendMediaKey = onSendMediaKey,
                    onSendMediaVolume = onSendMediaVolume,
                    cameraDelivery = cameraDelivery,
                    onRetryCameraUpload = onRetryCameraUpload,
                    onDismissCameraDelivery = onDismissCameraDelivery
                )
            }
            ToolSubTab.TERMINAL -> {
                TerminalToolView(
                    terminalState = terminalState,
                    onExecuteCommand = onExecuteTerminalCommand,
                    onConfirmCommand = onConfirmTerminalCommand,
                    onCancelCommand = onCancelTerminalCommand,
                    onClearTerminal = onClearTerminal
                )
            }
        }
    }
}

/**
 * Files Explorer Sub-Screen
 */
@Composable
private fun FilesToolView(
    safFolderUri: String,
    filesList: List<PcFileItem>,
    currentPath: String,
    onChangeSafFolder: () -> Unit,
    onNavigatePath: (String) -> Unit,
    onDownloadFile: (PcFileItem) -> Unit,
    onUploadFile: () -> Unit
) {
    val colors = LocalSnowColors.current
    var hideHidden by remember { mutableStateOf(true) }

    val displayFiles = remember(filesList, hideHidden) {
        if (hideHidden) filesList.filter { !it.isHidden } else filesList
    }

    Column(modifier = Modifier.fillMaxSize()) {
        // SAF Destination Bar
        Surface(
            modifier = Modifier
                .fillMaxWidth()
                .clip(RoundedCornerShape(14.dp))
                .border(1.dp, colors.borderSubtle, RoundedCornerShape(14.dp)),
            color = colors.surfaceElevated
        ) {
            Row(
                modifier = Modifier.padding(12.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Row(modifier = Modifier.weight(1f), verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        imageVector = Icons.Default.FolderOpen,
                        contentDescription = null,
                        tint = colors.accentCyan,
                        modifier = Modifier.size(20.dp)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Column {
                        Text(
                            text = "SAF Destination",
                            style = SnowTypography.labelSmall.copy(fontSize = 10.sp),
                            color = colors.textMuted
                        )
                        Text(
                            text = if (safFolderUri.isNotBlank()) "Configured (${safFolderUri.takeLast(16)})" else "Default (Downloads)",
                            style = SnowTypography.bodySmall.copy(fontWeight = FontWeight.SemiBold),
                            color = colors.textPrimary,
                            maxLines = 1
                        )
                    }
                }
                SnowTonalButton(
                    text = "Change",
                    onClick = onChangeSafFolder
                )
            }
        }

        Spacer(modifier = Modifier.height(10.dp))

        // Quick Directory Chips (Desktop, Downloads, Documents) & Hide Hidden
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                SnowFilterChip(text = "Desktop", selected = false, onClick = { onNavigatePath("Desktop") })
                SnowFilterChip(text = "Downloads", selected = false, onClick = { onNavigatePath("Downloads") })
                SnowFilterChip(text = "Documents", selected = false, onClick = { onNavigatePath("Documents") })
            }

            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    text = if (hideHidden) "Hidden: Off" else "Hidden: On",
                    style = SnowTypography.labelSmall.copy(fontSize = 10.sp),
                    color = colors.textMuted
                )
                Spacer(modifier = Modifier.width(4.dp))
                androidx.compose.material3.Switch(
                    checked = hideHidden,
                    onCheckedChange = { hideHidden = it },
                    modifier = Modifier.scale(0.7f)
                )
            }
        }

        Spacer(modifier = Modifier.height(8.dp))

        // Drive Chips & Path Navigation
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                SnowFilterChip(text = "C:", selected = currentPath.startsWith("C", ignoreCase = true) || currentPath.isBlank(), onClick = { onNavigatePath("C:\\") })
                SnowFilterChip(text = "D:", selected = currentPath.startsWith("D", ignoreCase = true), onClick = { onNavigatePath("D:\\") })
            }

            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                if (currentPath.isNotBlank() && currentPath != "C:\\" && currentPath != "D:\\") {
                    Surface(
                        modifier = Modifier
                            .size(36.dp)
                            .clip(CircleShape)
                            .clickable {
                                val parent = currentPath.trimEnd('\\').substringBeforeLast('\\', "")
                                onNavigatePath(if (parent.isBlank() || parent.length <= 2) "${currentPath.take(2)}\\" else "$parent\\")
                            },
                        color = colors.surfaceElevated
                    ) {
                        Box(contentAlignment = Alignment.Center) {
                            Icon(imageVector = Icons.Default.ArrowUpward, contentDescription = "Up", tint = colors.textPrimary, modifier = Modifier.size(18.dp))
                        }
                    }
                }
                SnowTonalButton(
                    text = "Upload",
                    icon = Icons.Default.Upload,
                    onClick = onUploadFile
                )
            }
        }

        Spacer(modifier = Modifier.height(8.dp))

        Text(
            text = "Path: ${currentPath.ifBlank { "C:\\" }}",
            style = SnowTypography.monospaceSmall,
            color = colors.textSecondary,
            maxLines = 1
        )

        Spacer(modifier = Modifier.height(10.dp))

        // File List
        if (displayFiles.isEmpty()) {
            Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                Text(
                    text = "Directory empty or loading files from PC...",
                    style = SnowTypography.bodyMedium,
                    color = colors.textMuted
                )
            }
        } else {
            LazyColumn(
                modifier = Modifier.fillMaxSize(),
                verticalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                items(displayFiles) { file ->
                    FileRowItem(
                        item = file,
                        onClick = {
                            if (file.isDirectory) {
                                onNavigatePath(file.path)
                            } else {
                                onDownloadFile(file)
                            }
                        }
                    )
                }
            }
        }
    }
}

@Composable
private fun FileRowItem(
    item: PcFileItem,
    onClick: () -> Unit
) {
    val colors = LocalSnowColors.current

    Surface(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(12.dp))
            .border(1.dp, colors.borderSubtle, RoundedCornerShape(12.dp))
            .clickable(onClick = onClick),
        color = colors.surface
    ) {
        Row(
            modifier = Modifier.padding(12.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(
                imageVector = if (item.isDirectory) Icons.Default.Folder else Icons.Default.InsertDriveFile,
                contentDescription = null,
                tint = if (item.isDirectory) colors.accentCyan else colors.textSecondary,
                modifier = Modifier.size(24.dp)
            )
            Spacer(modifier = Modifier.width(12.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = item.name,
                    style = SnowTypography.bodyMedium.copy(fontWeight = FontWeight.SemiBold),
                    color = colors.textPrimary,
                    maxLines = 1
                )
                val sizeText = if (item.isDirectory) "Directory" else "${(item.size / 1024).coerceAtLeast(1)} KB"
                Text(
                    text = sizeText,
                    style = SnowTypography.bodySmall,
                    color = colors.textMuted
                )
            }
            if (!item.isDirectory) {
                Icon(
                    imageVector = Icons.Default.Download,
                    contentDescription = "Download",
                    tint = colors.accentBlue,
                    modifier = Modifier.size(20.dp)
                )
            }
        }
    }
}

/**
 * Apps Launcher Sub-Screen
 */
@Composable
private fun AppsToolView(
    allowlistedApps: List<WindowsAppItem>,
    onLaunchApp: (target: String, friendlyName: String) -> Unit
) {
    val colors = LocalSnowColors.current
    var searchQuery by remember { mutableStateOf("") }
    var customTarget by remember { mutableStateOf("") }

    val filtered = remember(allowlistedApps, searchQuery) {
        if (searchQuery.isBlank()) allowlistedApps else allowlistedApps.filter {
            it.friendlyName.contains(searchQuery, ignoreCase = true) || it.target.contains(searchQuery, ignoreCase = true)
        }
    }

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        item {
            // Search Input
            OutlinedTextField(
                value = searchQuery,
                onValueChange = { searchQuery = it },
                modifier = Modifier.fillMaxWidth(),
                placeholder = { Text("Search PC applications...") },
                leadingIcon = { Icon(Icons.Default.Search, contentDescription = null, tint = colors.textMuted) },
                singleLine = true,
                shape = RoundedCornerShape(12.dp),
                colors = OutlinedTextFieldDefaults.colors(
                    focusedBorderColor = colors.accentBlue,
                    unfocusedBorderColor = colors.border,
                    focusedTextColor = colors.textPrimary,
                    unfocusedTextColor = colors.textPrimary
                )
            )
        }

        item {
            SnowSectionHeader(title = "Allowlisted Apps (${filtered.size})")
        }

        items(filtered) { app ->
            Surface(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(14.dp))
                    .border(1.dp, colors.borderSubtle, RoundedCornerShape(14.dp))
                    .clickable { onLaunchApp(app.target, app.friendlyName) },
                color = colors.surface
            ) {
                Row(
                    modifier = Modifier.padding(14.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Column {
                        Text(
                            text = app.friendlyName,
                            style = SnowTypography.titleSmall,
                            color = colors.textPrimary
                        )
                        Text(
                            text = "Target: ${app.target}",
                            style = SnowTypography.bodySmall,
                            color = colors.textSecondary
                        )
                    }
                    SnowTonalButton(
                        text = "Launch",
                        onClick = { onLaunchApp(app.target, app.friendlyName) }
                    )
                }
            }
        }

        item {
            SnowSectionHeader(title = "Launch Custom PC Target")
            SnowCard(modifier = Modifier.fillMaxWidth(), cornerRadius = 16.dp) {
                Column {
                    OutlinedTextField(
                        value = customTarget,
                        onValueChange = { customTarget = it },
                        modifier = Modifier.fillMaxWidth(),
                        placeholder = { Text("e.g. C:\\Windows\\notepad.exe") },
                        singleLine = true,
                        shape = RoundedCornerShape(12.dp)
                    )
                    Spacer(modifier = Modifier.height(10.dp))
                    SnowTonalButton(
                        text = "Launch Custom",
                        onClick = {
                            if (customTarget.isNotBlank()) {
                                onLaunchApp(customTarget.trim(), "Custom ($customTarget)")
                                customTarget = ""
                            }
                        },
                        enabled = customTarget.isNotBlank(),
                        modifier = Modifier.fillMaxWidth()
                    )
                }
            }
        }

        item {
            Spacer(modifier = Modifier.height(24.dp))
        }
    }
}

/**
 * Media Control & Screen Sharing Sub-Screen
 */
@Composable
private fun MediaToolView(
    isScreenSharing: Boolean,
    onToggleScreenShare: (Boolean) -> Unit,
    onTriggerCameraCapture: () -> Unit,
    onSendMediaKey: (String) -> Unit,
    onSendMediaVolume: (Int) -> Unit = {},
    cameraDelivery: SnowUiRepository.CameraDeliveryInfo = SnowUiRepository.CameraDeliveryInfo(),
    onRetryCameraUpload: () -> Unit = {},
    onDismissCameraDelivery: () -> Unit = {}
) {
    val colors = LocalSnowColors.current

    Column(
        modifier = Modifier.fillMaxSize(),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        // Remote Media Playback Card
        SnowCard(modifier = Modifier.fillMaxWidth(), cornerRadius = 20.dp) {
            Column {
                Text(
                    text = "REMOTE PC MEDIA CONTROLS",
                    style = SnowTypography.labelSmall.copy(letterSpacing = 1.sp),
                    color = colors.textMuted
                )
                Spacer(modifier = Modifier.height(16.dp))

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceAround,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    MediaCircleButton(icon = Icons.Default.SkipPrevious, label = "Prev", onClick = { onSendMediaKey("prev_track") })
                    MediaCircleButton(icon = Icons.Default.PlayArrow, label = "Play/Pause", onClick = { onSendMediaKey("play_pause") }, isPrimary = true)
                    MediaCircleButton(icon = Icons.Default.SkipNext, label = "Next", onClick = { onSendMediaKey("next_track") })
                }

                Spacer(modifier = Modifier.height(18.dp))
                Divider(color = colors.borderSubtle)
                Spacer(modifier = Modifier.height(14.dp))

                // Bounded Volume Slider (0..100 dispatched on drag release) & Mute
                var volumeLevel by remember { mutableStateOf(70f) }
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(
                        imageVector = Icons.Default.VolumeDown,
                        contentDescription = null,
                        tint = colors.textMuted,
                        modifier = Modifier.size(20.dp)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    androidx.compose.material3.Slider(
                        value = volumeLevel,
                        valueRange = 0f..100f,
                        onValueChange = { volumeLevel = it.coerceIn(0f, 100f) },
                        onValueChangeFinished = {
                            onSendMediaVolume(volumeLevel.roundToInt().coerceIn(0, 100))
                        },
                        modifier = Modifier.weight(1f)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Icon(
                        imageVector = Icons.Default.VolumeUp,
                        contentDescription = null,
                        tint = colors.textMuted,
                        modifier = Modifier.size(20.dp)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    SnowTonalButton(
                        text = "Mute",
                        onClick = { onSendMediaKey("mute") }
                    )
                }

                Spacer(modifier = Modifier.height(10.dp))

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceAround
                ) {
                    SnowTonalButton(
                        text = "Volume -",
                        icon = Icons.Default.VolumeDown,
                        onClick = {
                            volumeLevel = (volumeLevel - 5f).coerceIn(0f, 100f)
                            onSendMediaKey("volume_down")
                        }
                    )
                    SnowTonalButton(
                        text = "Volume +",
                        icon = Icons.Default.VolumeUp,
                        onClick = {
                            volumeLevel = (volumeLevel + 5f).coerceIn(0f, 100f)
                            onSendMediaKey("volume_up")
                        }
                    )
                }
            }
        }

        // Screen Share & Remote Camera Card
        SnowCard(modifier = Modifier.fillMaxWidth(), cornerRadius = 20.dp) {
            Column {
                Text(
                    text = "VIDEO & STREAMING CAPABILITIES",
                    style = SnowTypography.labelSmall.copy(letterSpacing = 1.sp),
                    color = colors.textMuted
                )
                Spacer(modifier = Modifier.height(14.dp))

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            imageVector = if (isScreenSharing) Icons.Default.ScreenShare else Icons.Default.StopScreenShare,
                            contentDescription = null,
                            tint = if (isScreenSharing) colors.accentEmerald else colors.textSecondary,
                            modifier = Modifier.size(24.dp)
                        )
                        Spacer(modifier = Modifier.width(10.dp))
                        Column {
                            Text(text = "Android Screen Share", style = SnowTypography.titleSmall, color = colors.textPrimary)
                            Text(text = if (isScreenSharing) "Live stream active" else "Standby", style = SnowTypography.bodySmall, color = colors.textSecondary)
                        }
                    }

                    if (isScreenSharing) {
                        SnowOutlinedButton(text = "Stop", onClick = { onToggleScreenShare(false) })
                    } else {
                        SnowGradientButton(text = "Start", onClick = { onToggleScreenShare(true) })
                    }
                }

                Spacer(modifier = Modifier.height(16.dp))
                Divider(color = colors.borderSubtle)
                Spacer(modifier = Modifier.height(14.dp))

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            imageVector = Icons.Default.CameraAlt,
                            contentDescription = null,
                            tint = colors.accentCyan,
                            modifier = Modifier.size(24.dp)
                        )
                        Spacer(modifier = Modifier.width(10.dp))
                        Column {
                            Text(text = "Camera Photo Delivery", style = SnowTypography.titleSmall, color = colors.textPrimary)
                            Text(text = "Capture & upload photo to PC", style = SnowTypography.bodySmall, color = colors.textSecondary)
                        }
                    }

                    SnowTonalButton(
                        text = "Capture",
                        onClick = onTriggerCameraCapture,
                        enabled = cameraDelivery.status != SnowUiRepository.CameraDeliveryStatus.UPLOADING
                    )
                }

                if (cameraDelivery.status != SnowUiRepository.CameraDeliveryStatus.IDLE) {
                    Spacer(modifier = Modifier.height(14.dp))
                    Surface(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clip(RoundedCornerShape(12.dp))
                            .border(1.dp, colors.borderSubtle, RoundedCornerShape(12.dp)),
                        color = colors.surfaceElevated
                    ) {
                        Column(modifier = Modifier.padding(12.dp)) {
                            val badgeType = when (cameraDelivery.status) {
                                SnowUiRepository.CameraDeliveryStatus.DELIVERED -> SnowBadgeType.CONNECTED
                                SnowUiRepository.CameraDeliveryStatus.FAILED -> SnowBadgeType.ERROR
                                else -> SnowBadgeType.STANDBY
                            }
                            val detailText = when (cameraDelivery.status) {
                                SnowUiRepository.CameraDeliveryStatus.CAPTURING -> "Waiting for camera capture confirmation..."
                                SnowUiRepository.CameraDeliveryStatus.UPLOADING -> "Uploading photo over HTTPS..."
                                SnowUiRepository.CameraDeliveryStatus.DELIVERED -> "Delivered: ${cameraDelivery.fileName ?: "photo.jpg"}"
                                SnowUiRepository.CameraDeliveryStatus.FAILED -> "Upload failed: ${cameraDelivery.error ?: "Network error"}"
                                SnowUiRepository.CameraDeliveryStatus.IDLE -> ""
                            }
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                SnowStatusBadge(text = cameraDelivery.status.name, type = badgeType)
                                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                    if (cameraDelivery.status == SnowUiRepository.CameraDeliveryStatus.FAILED) {
                                        SnowTonalButton(text = "Retry", onClick = onRetryCameraUpload)
                                    }
                                    SnowOutlinedButton(text = "Dismiss", onClick = onDismissCameraDelivery)
                                }
                            }
                            Spacer(modifier = Modifier.height(6.dp))
                            Text(text = detailText, style = SnowTypography.bodySmall, color = colors.textSecondary)
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun MediaCircleButton(
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    label: String,
    onClick: () -> Unit,
    isPrimary: Boolean = false
) {
    val colors = LocalSnowColors.current
    Surface(
        modifier = Modifier
            .size(if (isPrimary) 56.dp else 44.dp)
            .clip(CircleShape)
            .border(1.dp, if (isPrimary) colors.accentBlue else colors.borderSubtle, CircleShape)
            .clickable(onClick = onClick),
        color = if (isPrimary) colors.accentBlue else colors.surfaceElevated
    ) {
        Box(contentAlignment = Alignment.Center) {
            Icon(
                imageVector = icon,
                contentDescription = label,
                tint = if (isPrimary) Color.White else colors.textPrimary,
                modifier = Modifier.size(if (isPrimary) 28.dp else 22.dp)
            )
        }
    }
}

/**
 * Monospace Terminal Console Sub-Screen (#0F172A background)
 */
@Composable
private fun TerminalToolView(
    terminalState: TerminalExecutionState,
    onExecuteCommand: (String) -> Unit,
    onConfirmCommand: (command: String, ticket: String) -> Unit = { _, _ -> },
    onCancelCommand: () -> Unit = {},
    onClearTerminal: () -> Unit
) {
    val colors = LocalSnowColors.current
    var commandInput by remember { mutableStateOf("") }

    if (!terminalState.pendingTicket.isNullOrBlank() && !terminalState.pendingCommand.isNullOrBlank()) {
        AlertDialog(
            onDismissRequest = onCancelCommand,
            title = {
                Text(
                    text = "Confirm Terminal Execution",
                    style = SnowTypography.titleMedium,
                    color = colors.textPrimary
                )
            },
            text = {
                Column {
                    Text(
                        text = "This command requires explicit owner confirmation on the desktop security gate:",
                        style = SnowTypography.bodySmall,
                        color = colors.textSecondary
                    )
                    Spacer(modifier = Modifier.height(10.dp))
                    Surface(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clip(RoundedCornerShape(10.dp)),
                        color = colors.surfaceElevated
                    ) {
                        Text(
                            text = terminalState.pendingCommand,
                            style = SnowTypography.monospaceSmall,
                            color = colors.accentCyan,
                            modifier = Modifier.padding(10.dp)
                        )
                    }
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        text = "Ticket: ${terminalState.pendingTicket.take(12)}...",
                        style = SnowTypography.labelSmall,
                        color = colors.textMuted
                    )
                }
            },
            confirmButton = {
                SnowGradientButton(
                    text = "Approve & Run",
                    onClick = {
                        onConfirmCommand(terminalState.pendingCommand, terminalState.pendingTicket)
                    }
                )
            },
            dismissButton = {
                SnowOutlinedButton(
                    text = "Cancel",
                    onClick = onCancelCommand
                )
            },
            containerColor = if (colors.isDark) Color(0xFF1E1E1E) else Color.White
        )
    }

    Column(modifier = Modifier.fillMaxSize()) {
        // Quick Command Chips
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(6.dp)
        ) {
            listOf("whoami", "dir", "ipconfig", "systeminfo").forEach { cmd ->
                SnowFilterChip(
                    text = cmd,
                    selected = false,
                    onClick = {
                        commandInput = cmd
                        onExecuteCommand(cmd)
                    }
                )
            }
        }

        Spacer(modifier = Modifier.height(10.dp))

        // Monospace Console Screen
        Surface(
            modifier = Modifier
                .weight(1f)
                .fillMaxWidth()
                .clip(RoundedCornerShape(16.dp))
                .border(1.dp, Color(0x33FFFFFF), RoundedCornerShape(16.dp)),
            color = Color(0xFF0F172A) // Frozen terminal console background
        ) {
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(12.dp)
            ) {
                // Terminal Header
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = "SNOW TERMINAL CONSOLE",
                        style = SnowTypography.labelSmall.copy(letterSpacing = 1.sp, color = Color(0xFF00E5FF))
                    )
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        if (terminalState.exitCode != null) {
                            Text(
                                text = "Exit: ${terminalState.exitCode}",
                                style = SnowTypography.monospaceSmall.copy(
                                    color = if (terminalState.exitCode == 0) Color(0xFF10B981) else Color(0xFFEF4444)
                                )
                            )
                            Spacer(modifier = Modifier.width(8.dp))
                        }
                        val clipboard = androidx.compose.ui.platform.LocalClipboardManager.current
                        Text(
                            text = "Copy",
                            style = SnowTypography.labelSmall.copy(color = Color(0xFF38BDF8)),
                            modifier = Modifier
                                .clip(RoundedCornerShape(4.dp))
                                .clickable {
                                    val full = terminalState.outputLines.joinToString("\n") { it.text }
                                    clipboard.setText(androidx.compose.ui.text.AnnotatedString(full))
                                }
                                .padding(4.dp)
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = "Clear",
                            style = SnowTypography.labelSmall.copy(color = Color(0xFF94A3B8)),
                            modifier = Modifier
                                .clip(RoundedCornerShape(4.dp))
                                .clickable(onClick = onClearTerminal)
                                .padding(4.dp)
                        )
                    }
                }

                Spacer(modifier = Modifier.height(8.dp))
                Divider(color = Color(0x22FFFFFF))
                Spacer(modifier = Modifier.height(8.dp))

                // Output lines
                LazyColumn(
                    modifier = Modifier.fillMaxSize(),
                    reverseLayout = false
                ) {
                    if (terminalState.outputLines.isEmpty()) {
                        item {
                            Text(
                                text = "Ready. Tap a chip above or type a command to execute on desktop.",
                                style = SnowTypography.monospaceSmall.copy(color = Color(0xFF64748B))
                            )
                        }
                    } else {
                        items(terminalState.outputLines) { line ->
                            val textColor = when {
                                line.isStderr -> Color(0xFFF87171)
                                line.isSystem -> Color(0xFF38BDF8)
                                else -> Color(0xFFF1F5F9)
                            }
                            Text(
                                text = line.text,
                                style = SnowTypography.monospaceSmall.copy(color = textColor)
                            )
                        }
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(10.dp))

        // Command Input & Execute Button
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically
        ) {
            OutlinedTextField(
                value = commandInput,
                onValueChange = { commandInput = it },
                modifier = Modifier.weight(1f),
                placeholder = { Text("Command...", style = SnowTypography.monospaceSmall) },
                singleLine = true,
                shape = RoundedCornerShape(12.dp),
                colors = OutlinedTextFieldDefaults.colors(
                    focusedBorderColor = colors.accentBlue,
                    unfocusedBorderColor = colors.border,
                    focusedTextColor = colors.textPrimary,
                    unfocusedTextColor = colors.textPrimary
                )
            )
            Spacer(modifier = Modifier.width(8.dp))
            SnowGradientButton(
                text = "Run",
                onClick = {
                    if (commandInput.isNotBlank()) {
                        onExecuteCommand(commandInput.trim())
                    }
                },
                enabled = commandInput.isNotBlank() && !terminalState.isRunning
            )
        }

        Spacer(modifier = Modifier.height(16.dp))
    }
}
