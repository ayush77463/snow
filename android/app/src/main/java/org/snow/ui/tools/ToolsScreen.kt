package org.snow.ui.tools

import android.graphics.BitmapFactory
import android.widget.Toast
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.pager.HorizontalPager
import androidx.compose.foundation.pager.rememberPagerState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.TextSelectionColors
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.ArrowUpward
import androidx.compose.material.icons.filled.Build
import androidx.compose.material.icons.filled.CameraAlt
import androidx.compose.material.icons.filled.Clear
import androidx.compose.material.icons.filled.Close
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
import androidx.compose.material3.Checkbox
import androidx.compose.material3.Divider
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.runtime.snapshotFlow
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.clipToBounds
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.launch
import org.snow.ui.ActiveTransferInfo
import org.snow.ui.PcFileItem
import org.snow.ui.SnowUiRepository
import org.snow.ui.TerminalExecutionState
import org.snow.ui.formatTransferBytes
import kotlin.math.roundToInt
import org.snow.ui.components.SnowBadgeType
import org.snow.ui.components.SnowCard
import org.snow.ui.components.SnowEmptyState
import org.snow.ui.components.SnowFilterChip
import org.snow.ui.components.SnowGradientButton
import org.snow.ui.components.SnowOutlinedButton
import org.snow.ui.components.SnowPullToRefreshBox
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
    TERMINAL("Terminal"),
    SCREEN("Screen")
}

/**
 * Flagship Tools Screen containing 5-pill switcher: Files, Apps, Media, Terminal, Screen.
 */
@OptIn(ExperimentalFoundationApi::class)
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
    isFilesRefreshing: Boolean = false,
    onRefreshFiles: () -> Unit = {},
    activeTransfer: ActiveTransferInfo? = null,
    onCancelTransfer: () -> Unit = {},
    onDismissTransfer: () -> Unit = {},
    // Apps parameters
    allowlistedApps: List<WindowsAppItem>,
    onLaunchApp: (target: String, friendlyName: String) -> Unit,
    // Media & Screen parameters
    isScreenSharing: Boolean,
    onToggleScreenShare: (Boolean) -> Unit,
    onTriggerCameraCapture: () -> Unit,
    onSendMediaKey: (String) -> Unit,
    onSendMediaVolume: (Int) -> Unit = {},
    cameraDelivery: SnowUiRepository.CameraDeliveryInfo = SnowUiRepository.CameraDeliveryInfo(),
    onRetryCameraUpload: () -> Unit = {},
    onDismissCameraDelivery: () -> Unit = {},
    incomingStreams: Map<String, SnowUiRepository.IncomingScreenStream> = emptyMap(),
    selectedIncomingSenderId: String? = null,
    onSelectIncomingSender: (String) -> Unit = {},
    onCloseIncomingViewer: () -> Unit = {},
    eligibleScreenTargets: List<SnowUiRepository.ScreenShareTarget> = emptyList(),
    onStartScreenShareWithTargets: (List<String>) -> Unit = { onToggleScreenShare(true) },
    activePermissionProfile: String = "full_control",
    // Terminal parameters
    terminalState: TerminalExecutionState,
    onExecuteTerminalCommand: (String) -> Unit,
    onConfirmTerminalCommand: (command: String, ticket: String) -> Unit = { _, _ -> },
    onCancelTerminalCommand: () -> Unit = {},
    onClearTerminal: () -> Unit,
    modifier: Modifier = Modifier
) {
    val colors = LocalSnowColors.current
    val haptic = LocalHapticFeedback.current
    val pagerScope = rememberCoroutineScope()
    val tabs = remember { ToolSubTab.values() }
    val pagerState = rememberPagerState(initialPage = currentSubTab.ordinal) { tabs.size }
    val latestCurrentSubTab by rememberUpdatedState(currentSubTab)
    val latestOnSubTabChanged by rememberUpdatedState(onSubTabChanged)

    LaunchedEffect(pagerState) {
        snapshotFlow { pagerState.settledPage }
            .distinctUntilChanged()
            .collect { settled ->
                val settledTab = tabs.getOrNull(settled) ?: return@collect
                if (settledTab != latestCurrentSubTab) {
                    latestOnSubTabChanged(settledTab)
                }
            }
    }

    LaunchedEffect(currentSubTab) {
        if (pagerState.currentPage != currentSubTab.ordinal) {
            pagerState.animateScrollToPage(currentSubTab.ordinal)
        }
    }

    Column(
        modifier = modifier
            .fillMaxSize()
            .padding(horizontal = 16.dp)
    ) {
        Spacer(modifier = Modifier.height(12.dp))

        // 5-Pill Segment Selector (single-line ellipsis safe across narrow widths)
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .clip(RoundedCornerShape(9999.dp))
                .background(colors.surfaceElevated)
                .padding(4.dp),
            horizontalArrangement = Arrangement.spacedBy(2.dp)
        ) {
            tabs.forEach { tab ->
                val selected = currentSubTab == tab
                Box(
                    modifier = Modifier
                        .weight(1f)
                        .clip(RoundedCornerShape(9999.dp))
                        .background(if (selected) (if (colors.isDark) Color(0xFF282828) else Color.White) else Color.Transparent)
                        .clickable {
                            haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                            onSubTabChanged(tab)
                            pagerScope.launch {
                                if (pagerState.currentPage != tab.ordinal) {
                                    pagerState.animateScrollToPage(tab.ordinal)
                                }
                            }
                        }
                        .padding(horizontal = 4.dp, vertical = 8.dp),
                    contentAlignment = Alignment.Center
                ) {
                    Text(
                        text = tab.title,
                        style = SnowTypography.labelMedium.copy(fontSize = 11.sp),
                        color = if (selected) colors.textPrimary else colors.textMuted,
                        maxLines = 1,
                        softWrap = false,
                        overflow = TextOverflow.Ellipsis
                    )
                }
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        // Sub-screen Content (swipeable and two-way synced with top pill bar)
        HorizontalPager(
            state = pagerState,
            beyondBoundsPageCount = 1,
            modifier = Modifier
                .weight(1f)
                .fillMaxWidth()
                .clipToBounds()
        ) { page ->
            Box(modifier = Modifier.fillMaxSize().clipToBounds()) {
            when (tabs[page]) {
                ToolSubTab.FILES -> {
                    FilesToolView(
                        safFolderUri = safFolderUri,
                        filesList = filesList,
                        currentPath = currentPath,
                        onChangeSafFolder = onChangeSafFolder,
                        onNavigatePath = onNavigatePath,
                        onDownloadFile = onDownloadFile,
                        onUploadFile = onUploadFile,
                        isRefreshing = isFilesRefreshing,
                        onRefresh = onRefreshFiles,
                        activeTransfer = activeTransfer,
                        onCancelTransfer = onCancelTransfer,
                        onDismissTransfer = onDismissTransfer
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
                ToolSubTab.SCREEN -> {
                    ScreenToolView(
                        isScreenSharing = isScreenSharing,
                        onStopScreenShare = { onToggleScreenShare(false) },
                        incomingStreams = incomingStreams,
                        selectedIncomingSenderId = selectedIncomingSenderId,
                        onSelectIncomingSender = onSelectIncomingSender,
                        onCloseIncomingViewer = onCloseIncomingViewer,
                        eligibleScreenTargets = eligibleScreenTargets,
                        onStartScreenShareWithTargets = onStartScreenShareWithTargets,
                        activePermissionProfile = activePermissionProfile
                    )
                }
            }
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
    onUploadFile: () -> Unit,
    isRefreshing: Boolean = false,
    onRefresh: () -> Unit = {},
    activeTransfer: ActiveTransferInfo? = null,
    onCancelTransfer: () -> Unit = {},
    onDismissTransfer: () -> Unit = {}
) {
    val colors = LocalSnowColors.current
    val haptic = LocalHapticFeedback.current
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
            verticalAlignment = Alignment.CenterVertically
        ) {
            Row(
                modifier = Modifier
                    .weight(1f)
                    .horizontalScroll(rememberScrollState())
                    .padding(end = 8.dp),
                horizontalArrangement = Arrangement.spacedBy(6.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
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
                    onClick = {
                        haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                        onUploadFile()
                    }
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

        if (activeTransfer != null && activeTransfer.status != "CANCELLED") {
            ToolsActiveTransferCard(
                transfer = activeTransfer,
                onActionClick = {
                    haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                    if (activeTransfer.status == "IN_PROGRESS" || activeTransfer.status == "STARTING") {
                        onCancelTransfer()
                    } else {
                        onDismissTransfer()
                    }
                }
            )
            Spacer(modifier = Modifier.height(10.dp))
        }

        // File List with Pull-to-Refresh & Bottom Bar Clearance
        SnowPullToRefreshBox(
            isRefreshing = isRefreshing,
            onRefresh = onRefresh,
            modifier = Modifier.weight(1f).fillMaxWidth()
        ) {
            if (displayFiles.isEmpty()) {
                LazyColumn(
                    modifier = Modifier.fillMaxSize(),
                    verticalArrangement = Arrangement.Center,
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    item {
                        Text(
                            text = "Directory empty or loading files from PC...",
                            style = SnowTypography.bodyMedium,
                            color = colors.textMuted
                        )
                    }
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
                                haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                                if (file.isDirectory) {
                                    onNavigatePath(file.path)
                                } else {
                                    onDownloadFile(file)
                                }
                            }
                        )
                    }
                    item {
                        Spacer(modifier = Modifier.height(96.dp))
                    }
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
                val sizeText = if (item.isDirectory) "Directory" else formatTransferBytes(item.size)
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

@Composable
private fun ToolsActiveTransferCard(
    transfer: ActiveTransferInfo,
    onActionClick: () -> Unit
) {
    val colors = LocalSnowColors.current
    val pct = if (transfer.totalBytes > 0L) {
        ((transfer.bytesTransferred * 100L) / transfer.totalBytes).toInt().coerceIn(0, 100)
    } else 0
    val isActive = transfer.status == "IN_PROGRESS" || transfer.status == "STARTING"
    val directionLabel = if (transfer.direction.equals("UPLOAD", ignoreCase = true)) "Uploading" else "Downloading"
    val statusText = when (transfer.status.uppercase()) {
        "COMPLETED" -> "Completed"
        "DUPLICATE" -> "Already on target"
        "FAILED" -> "Transfer failed"
        else -> if (transfer.totalBytes > 0L) "$pct%" else "Transferring..."
    }

    SnowCard(
        modifier = Modifier.fillMaxWidth(),
        cornerRadius = 16.dp
    ) {
        Column(modifier = Modifier.fillMaxWidth()) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = "$directionLabel • ${transfer.fileName}",
                        style = SnowTypography.titleSmall,
                        color = colors.textPrimary,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                    Surface(
                        shape = RoundedCornerShape(9999.dp),
                        color = colors.surfaceElevated
                    ) {
                        Text(
                            text = transfer.transportLabel,
                            style = SnowTypography.labelSmall.copy(fontSize = 10.sp),
                            color = colors.accentCyan,
                            modifier = Modifier.padding(horizontal = 8.dp, vertical = 2.dp)
                        )
                    }
                }
                Spacer(modifier = Modifier.width(8.dp))
                Box(
                    modifier = Modifier
                        .size(28.dp)
                        .clip(CircleShape)
                        .background(colors.surfaceElevated)
                        .clickable(onClick = onActionClick),
                    contentAlignment = Alignment.Center
                ) {
                    Icon(
                        imageVector = Icons.Default.Close,
                        contentDescription = if (isActive) "Cancel Transfer" else "Dismiss Transfer",
                        tint = colors.textSecondary,
                        modifier = Modifier.size(16.dp)
                    )
                }
            }

            Spacer(modifier = Modifier.height(10.dp))

            if (transfer.totalBytes > 0L) {
                LinearProgressIndicator(
                    progress = (transfer.bytesTransferred.toFloat() / transfer.totalBytes.toFloat()).coerceIn(0f, 1f),
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(6.dp)
                        .clip(RoundedCornerShape(9999.dp)),
                    color = if (transfer.status == "FAILED") Color(0xFFEF4444) else colors.accentBlue,
                    trackColor = colors.surfaceElevated
                )
            } else if (isActive) {
                LinearProgressIndicator(
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(6.dp)
                        .clip(RoundedCornerShape(9999.dp)),
                    color = colors.accentBlue,
                    trackColor = colors.surfaceElevated
                )
            }

            Spacer(modifier = Modifier.height(8.dp))

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                val totalLabel = if (transfer.totalBytes > 0L) formatTransferBytes(transfer.totalBytes) else "--"
                Text(
                    text = "${formatTransferBytes(transfer.bytesTransferred)} / $totalLabel",
                    style = SnowTypography.labelSmall,
                    color = colors.textMuted
                )
                Text(
                    text = statusText,
                    style = SnowTypography.labelSmall.copy(fontWeight = FontWeight.SemiBold),
                    color = if (transfer.status == "FAILED") Color(0xFFEF4444) else colors.textSecondary
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
    val haptic = LocalHapticFeedback.current
    var searchQuery by rememberSaveable { mutableStateOf("") }
    var customTarget by rememberSaveable { mutableStateOf("") }

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
                        onClick = {
                            haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                            onLaunchApp(app.target, app.friendlyName)
                        }
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
 * Media Control & Camera Delivery Sub-Screen (Screen share & capture moved cleanly to Screen tab).
 */
@Composable
private fun MediaToolView(
    onTriggerCameraCapture: () -> Unit,
    onSendMediaKey: (String) -> Unit,
    onSendMediaVolume: (Int) -> Unit = {},
    cameraDelivery: SnowUiRepository.CameraDeliveryInfo = SnowUiRepository.CameraDeliveryInfo(),
    onRetryCameraUpload: () -> Unit = {},
    onDismissCameraDelivery: () -> Unit = {}
) {
    val colors = LocalSnowColors.current
    val haptic = LocalHapticFeedback.current

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
                    MediaCircleButton(icon = Icons.Default.SkipPrevious, label = "Prev", onClick = {
                        haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                        onSendMediaKey("prev_track")
                    })
                    MediaCircleButton(icon = Icons.Default.PlayArrow, label = "Play/Pause", onClick = {
                        haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                        onSendMediaKey("play_pause")
                    }, isPrimary = true)
                    MediaCircleButton(icon = Icons.Default.SkipNext, label = "Next", onClick = {
                        haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                        onSendMediaKey("next_track")
                    })
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

        // Camera Photo Delivery Card (Screen capabilities now reside cleanly in Screen tab)
        SnowCard(modifier = Modifier.fillMaxWidth(), cornerRadius = 20.dp) {
            Column {
                Text(
                    text = "CAMERA CAPTURE",
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
                        onClick = {
                            haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                            onTriggerCameraCapture()
                        },
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

/**
 * Dedicated Screen Sub-Screen consolidating Universal Any-to-Any Screen Sharing & Capture.
 */
@Composable
private fun ScreenToolView(
    isScreenSharing: Boolean,
    onStopScreenShare: () -> Unit,
    incomingStreams: Map<String, SnowUiRepository.IncomingScreenStream>,
    selectedIncomingSenderId: String?,
    onSelectIncomingSender: (String) -> Unit,
    onCloseIncomingViewer: () -> Unit,
    eligibleScreenTargets: List<SnowUiRepository.ScreenShareTarget>,
    onStartScreenShareWithTargets: (List<String>) -> Unit,
    activePermissionProfile: String
) {
    val colors = LocalSnowColors.current
    val context = LocalContext.current
    val haptic = LocalHapticFeedback.current

    var showTargetPicker by remember { mutableStateOf(false) }
    var selectedTargetIds by remember(eligibleScreenTargets) {
        mutableStateOf(
            eligibleScreenTargets.firstOrNull()?.deviceId?.let { setOf(it) } ?: emptySet()
        )
    }
    var isFullscreenViewer by remember { mutableStateOf(false) }

    val activeStream = remember(incomingStreams, selectedIncomingSenderId) {
        when {
            incomingStreams.isEmpty() -> null
            selectedIncomingSenderId != null && incomingStreams.containsKey(selectedIncomingSenderId) ->
                incomingStreams[selectedIncomingSenderId]
            else -> incomingStreams.values.firstOrNull()
        }
    }

    LaunchedEffect(activeStream) {
        if (activeStream == null) {
            isFullscreenViewer = false
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        // 1. Dynamic Incoming Live Screen Viewer: ONLY shown when at least 1 remote sender is streaming
        if (activeStream != null) {
            val frameBitmap = remember(activeStream.frameBytes) {
                try {
                    BitmapFactory.decodeByteArray(activeStream.frameBytes, 0, activeStream.frameBytes.size)
                } catch (_: Exception) {
                    null
                }
            }

            SnowCard(modifier = Modifier.fillMaxWidth(), cornerRadius = 20.dp) {
                Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = "INCOMING LIVE SCREEN",
                                style = SnowTypography.labelSmall.copy(letterSpacing = 1.sp),
                                color = colors.textMuted
                            )
                            Spacer(modifier = Modifier.height(2.dp))
                            Text(
                                text = activeStream.senderName,
                                style = SnowTypography.titleSmall,
                                color = colors.textPrimary,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis
                            )
                        }
                        SnowStatusBadge(
                            text = activeStream.routeBadge.ifBlank { "Live" },
                            type = SnowBadgeType.CONNECTED
                        )
                    }

                    if (incomingStreams.size > 1) {
                        LazyRow(
                            horizontalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            items(incomingStreams.values.toList(), key = { it.senderId }) { sender ->
                                SnowFilterChip(
                                    text = sender.senderName,
                                    selected = sender.senderId == activeStream.senderId,
                                    onClick = { onSelectIncomingSender(sender.senderId) }
                                )
                            }
                        }
                    }

                    if (frameBitmap != null) {
                        val ratio = if (frameBitmap.height > 0) {
                            (frameBitmap.width.toFloat() / frameBitmap.height.toFloat()).coerceIn(0.45f, 2.2f)
                        } else 16f / 9f
                        Box(
                            modifier = Modifier
                                .fillMaxWidth()
                                .aspectRatio(ratio)
                                .clip(RoundedCornerShape(14.dp))
                                .background(Color(0xFF0B0F17))
                                .clickable { isFullscreenViewer = true },
                            contentAlignment = Alignment.Center
                        ) {
                            Image(
                                bitmap = frameBitmap.asImageBitmap(),
                                contentDescription = "Live screen from ${activeStream.senderName}",
                                modifier = Modifier.fillMaxSize(),
                                contentScale = ContentScale.Fit
                            )
                        }
                    }

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = buildString {
                                append(String.format(java.util.Locale.US, "%.1f FPS", activeStream.fps))
                                if (activeStream.width > 0 && activeStream.height > 0) {
                                    append("  •  ${activeStream.width}x${activeStream.height}")
                                }
                            },
                            style = SnowTypography.bodySmall,
                            color = colors.textSecondary
                        )
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            SnowTonalButton(
                                text = "Fullscreen",
                                onClick = { isFullscreenViewer = true }
                            )
                            SnowOutlinedButton(
                                text = "Close",
                                onClick = onCloseIncomingViewer
                            )
                        }
                    }
                }
            }
        }

        // 2. Outbound Phone Screen Share Card
        SnowCard(modifier = Modifier.fillMaxWidth(), cornerRadius = 20.dp) {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = "SHARE THIS PHONE SCREEN",
                        style = SnowTypography.labelSmall.copy(letterSpacing = 1.sp),
                        color = colors.textMuted
                    )
                    SnowStatusBadge(
                        text = if (isScreenSharing) "Live Stream" else "Standby",
                        type = if (isScreenSharing) SnowBadgeType.CONNECTED else SnowBadgeType.STANDBY
                    )
                }

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Row(
                        modifier = Modifier.weight(1f),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(
                            imageVector = if (isScreenSharing) Icons.Default.ScreenShare else Icons.Default.StopScreenShare,
                            contentDescription = null,
                            tint = if (isScreenSharing) colors.accentEmerald else colors.textSecondary,
                            modifier = Modifier.size(24.dp)
                        )
                        Spacer(modifier = Modifier.width(10.dp))
                        Column {
                            Text(
                                text = "Live Screen Share",
                                style = SnowTypography.titleSmall,
                                color = colors.textPrimary
                            )
                            Text(
                                text = when {
                                    isScreenSharing -> "Broadcasting over authenticated media transport"
                                    activePermissionProfile.trim().lowercase() != "full_control" ->
                                        "Blocked: Full Control permission profile required"
                                    eligibleScreenTargets.isEmpty() ->
                                        "Connect an authorized Full Control device first"
                                    else -> "Ready (${eligibleScreenTargets.size} eligible target)"
                                },
                                style = SnowTypography.bodySmall,
                                color = colors.textSecondary
                            )
                        }
                    }

                    Spacer(modifier = Modifier.width(8.dp))
                    if (isScreenSharing) {
                        SnowOutlinedButton(
                            text = "Stop Sharing",
                            onClick = {
                                haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                                onStopScreenShare()
                            }
                        )
                    } else {
                        SnowGradientButton(
                            text = "Start Sharing",
                            onClick = {
                                haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                                if (activePermissionProfile.trim().lowercase() != "full_control") {
                                    Toast.makeText(
                                        context,
                                        "Screen sharing requires Full Control permission profile.",
                                        Toast.LENGTH_SHORT
                                    ).show()
                                } else if (eligibleScreenTargets.isEmpty()) {
                                    Toast.makeText(
                                        context,
                                        "Connect an authorized Full Control device to share your screen.",
                                        Toast.LENGTH_SHORT
                                    ).show()
                                } else {
                                    selectedTargetIds = setOf(eligibleScreenTargets.first().deviceId)
                                    showTargetPicker = true
                                }
                            }
                        )
                    }
                }
            }
        }

        // 3. One-Time Screen Capture Card (consolidated cleanly from Media into Screen)
        SnowCard(modifier = Modifier.fillMaxWidth(), cornerRadius = 20.dp) {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    text = "ONE-TIME SCREEN CAPTURE",
                    style = SnowTypography.labelSmall.copy(letterSpacing = 1.sp),
                    color = colors.textMuted
                )
                Text(
                    text = "Screen Snapshot Consent",
                    style = SnowTypography.titleSmall,
                    color = colors.textPrimary
                )
                Text(
                    text = "One-time screen captures requested by an authorized PC or peer host prompt explicitly via Android MediaProjection before capturing a single PNG over HTTPS.",
                    style = SnowTypography.bodySmall,
                    color = colors.textSecondary
                )
            }
        }

        Spacer(modifier = Modifier.height(16.dp))
    }

    if (showTargetPicker) {
        AlertDialog(
            onDismissRequest = { showTargetPicker = false },
            title = {
                Text(
                    text = "Select devices to share with",
                    style = SnowTypography.titleMedium,
                    color = colors.textPrimary
                )
            },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    eligibleScreenTargets.forEach { target ->
                        val checked = selectedTargetIds.contains(target.deviceId)
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clip(RoundedCornerShape(12.dp))
                                .border(1.dp, colors.borderSubtle, RoundedCornerShape(12.dp))
                                .clickable {
                                    selectedTargetIds = if (checked) {
                                        selectedTargetIds - target.deviceId
                                    } else {
                                        selectedTargetIds + target.deviceId
                                    }
                                }
                                .padding(horizontal = 10.dp, vertical = 8.dp),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.SpaceBetween
                        ) {
                            Row(
                                modifier = Modifier.weight(1f),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Checkbox(
                                    checked = checked,
                                    onCheckedChange = { isChecked ->
                                        selectedTargetIds = if (isChecked) {
                                            selectedTargetIds + target.deviceId
                                        } else {
                                            selectedTargetIds - target.deviceId
                                        }
                                    }
                                )
                                Column {
                                    Text(
                                        text = target.deviceName,
                                        style = SnowTypography.bodyMedium.copy(fontWeight = FontWeight.SemiBold),
                                        color = colors.textPrimary
                                    )
                                    Text(
                                        text = target.routeBadge,
                                        style = SnowTypography.bodySmall,
                                        color = colors.textSecondary
                                    )
                                }
                            }
                        }
                    }
                }
            },
            confirmButton = {
                SnowGradientButton(
                    text = "Start Sharing",
                    onClick = {
                        val picked = selectedTargetIds.toList()
                        if (picked.isNotEmpty()) {
                            showTargetPicker = false
                            onStartScreenShareWithTargets(picked)
                        }
                    },
                    enabled = selectedTargetIds.isNotEmpty()
                )
            },
            dismissButton = {
                SnowOutlinedButton(
                    text = "Cancel",
                    onClick = { showTargetPicker = false }
                )
            },
            containerColor = colors.surface
        )
    }

    if (isFullscreenViewer && activeStream != null) {
        val fullBitmap = remember(activeStream.frameBytes) {
            try {
                BitmapFactory.decodeByteArray(activeStream.frameBytes, 0, activeStream.frameBytes.size)
            } catch (_: Exception) {
                null
            }
        }
        Dialog(
            onDismissRequest = { isFullscreenViewer = false },
            properties = DialogProperties(usePlatformDefaultWidth = false)
        ) {
            Surface(
                modifier = Modifier.fillMaxSize(),
                color = Color(0xFF090C12)
            ) {
                Column(modifier = Modifier.fillMaxSize()) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 16.dp, vertical = 12.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column {
                            Text(
                                text = activeStream.senderName,
                                style = SnowTypography.titleMedium,
                                color = Color.White
                            )
                            Text(
                                text = activeStream.routeBadge,
                                style = SnowTypography.bodySmall,
                                color = Color(0xFF94A3B8)
                            )
                        }
                        SnowOutlinedButton(
                            text = "Close",
                            onClick = { isFullscreenViewer = false }
                        )
                    }
                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .weight(1f),
                        contentAlignment = Alignment.Center
                    ) {
                        if (fullBitmap != null) {
                            Image(
                                bitmap = fullBitmap.asImageBitmap(),
                                contentDescription = "Fullscreen view of ${activeStream.senderName}",
                                modifier = Modifier.fillMaxSize(),
                                contentScale = ContentScale.Fit
                            )
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
 * Monospace Terminal Console Sub-Screen using SNOW theme terminal semantic tokens.
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
    var commandInput by rememberSaveable { mutableStateOf("") }

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
                            color = colors.terminalHeader,
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
                    },
                    isLoading = terminalState.isRunning
                )
            },
            dismissButton = {
                SnowOutlinedButton(
                    text = "Cancel",
                    onClick = onCancelCommand,
                    enabled = !terminalState.isRunning
                )
            },
            containerColor = colors.surface
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
                    enabled = !terminalState.isRunning,
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
                .border(1.dp, colors.terminalBorder, RoundedCornerShape(16.dp)),
            color = colors.terminalBg
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
                        style = SnowTypography.labelSmall.copy(letterSpacing = 1.sp, color = colors.terminalHeader)
                    )
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        if (terminalState.exitCode != null) {
                            Text(
                                text = "Exit: ${terminalState.exitCode}",
                                style = SnowTypography.monospaceSmall.copy(
                                    color = if (terminalState.exitCode == 0) colors.terminalExitSuccess else colors.terminalExitError
                                )
                            )
                            Spacer(modifier = Modifier.width(8.dp))
                        }
                        val clipboard = androidx.compose.ui.platform.LocalClipboardManager.current
                        Text(
                            text = "Copy",
                            style = SnowTypography.labelSmall.copy(color = colors.terminalSystem),
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
                            style = SnowTypography.labelSmall.copy(color = colors.terminalPlaceholder),
                            modifier = Modifier
                                .clip(RoundedCornerShape(4.dp))
                                .clickable(enabled = !terminalState.isRunning, onClick = onClearTerminal)
                                .padding(4.dp)
                        )
                    }
                }

                Spacer(modifier = Modifier.height(8.dp))
                Divider(color = colors.terminalDivider)
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
                                style = SnowTypography.monospaceSmall.copy(color = colors.terminalPlaceholder)
                            )
                        }
                    } else {
                        items(terminalState.outputLines) { line ->
                            val textColor = when {
                                line.isStderr -> colors.terminalStderr
                                line.isSystem -> colors.terminalSystem
                                else -> colors.terminalStdout
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
                placeholder = { Text("Command...", style = SnowTypography.monospaceSmall, color = colors.terminalPlaceholder) },
                singleLine = true,
                shape = RoundedCornerShape(12.dp),
                colors = OutlinedTextFieldDefaults.colors(
                    focusedBorderColor = colors.accentCyan,
                    unfocusedBorderColor = colors.border,
                    focusedTextColor = colors.textPrimary,
                    unfocusedTextColor = colors.textPrimary,
                    cursorColor = colors.terminalHeader,
                    selectionColors = TextSelectionColors(
                        handleColor = colors.terminalHeader,
                        backgroundColor = colors.terminalHeader.copy(alpha = 0.25f)
                    )
                )
            )
            Spacer(modifier = Modifier.width(8.dp))
            val terminalHaptic = LocalHapticFeedback.current
            SnowGradientButton(
                text = if (terminalState.isRunning) "Running" else "Run",
                onClick = {
                    if (commandInput.isNotBlank() && !terminalState.isRunning) {
                        terminalHaptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                        onExecuteCommand(commandInput.trim())
                    }
                },
                enabled = commandInput.isNotBlank() && !terminalState.isRunning,
                isLoading = terminalState.isRunning
            )
        }

        Spacer(modifier = Modifier.height(16.dp))
    }
}
