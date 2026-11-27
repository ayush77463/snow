package org.snow.ui

import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import android.widget.Toast
import androidx.appcompat.app.AppCompatDelegate
import androidx.core.content.ContextCompat
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Icon
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLifecycleOwner
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.repeatOnLifecycle
import com.google.zxing.BarcodeFormat
import com.google.zxing.qrcode.QRCodeWriter
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import org.snow.network.ConnectionState
import org.snow.network.DiscoveredPeer
import org.snow.network.PeerHostState
import org.snow.ui.PcFileItem
import org.snow.ui.components.SnowGradientButton
import org.snow.ui.components.SnowOutlinedButton
import org.snow.ui.components.SnowTonalButton
import org.snow.ui.theme.SnowTypography
import org.snow.ui.PendingApprovalItem
import org.snow.ui.SavedDevice
import org.snow.ui.connect.SnowConnectSheet
import org.snow.ui.dashboard.AppLauncherBottomSheet
import org.snow.ui.devices.DevicesScreen
import org.snow.ui.home.HomeScreen
import org.snow.ui.navigation.SnowBottomNavigationBar
import org.snow.ui.navigation.SnowTab
import org.snow.ui.settings.SettingsScreen
import org.snow.ui.settings.SettingsViewModel
import org.snow.ui.shell.SnowApprovalsSheet
import org.snow.ui.shell.SnowDeviceSelectorIsland
import org.snow.ui.shell.SnowTopAppBar
import org.snow.ui.theme.LocalSnowColors
import org.snow.ui.theme.SnowTheme
import org.snow.ui.tools.ToolSubTab
import org.snow.ui.tools.ToolsScreen

/**
 * Root Composable orchestrating the SNOW V5 Material 3 Flagship UI.
 */
@Composable
fun SnowApp(
    repository: SnowUiRepository,
    onLaunchQrScanner: () -> Unit,
    onPickFilesToUpload: () -> Unit,
    onPickSafFolder: () -> Unit,
    onToggleScreenShareConsent: () -> Unit,
    themeMode: Int,
    onThemeModeChanged: (Int) -> Unit,
    onLaunchCameraCapture: () -> Unit = {},
    onRequestScreenshotPermission: ((Boolean) -> Unit) -> Unit = { it(false) },
    onSyncSystemBars: (Boolean) -> Unit = {}
) {
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current
    val scope = rememberCoroutineScope()

    // State observation from SnowUiRepository (UI connected ONLY when transport is CONNECTED AND Authenticated)
    val connectionState by repository.uiConnectionState.collectAsState()
    val authState by repository.authState.collectAsState()
    val connectedEndpoint by repository.connectedEndpoint.collectAsState()
    val revocationNotice by repository.revocationNotice.collectAsState()
    val savedDevices by repository.savedDevices.collectAsState()
    val transportSnapshots by repository.transportSnapshots.collectAsState()
    val discoveredPeers by repository.discoveredPeers.collectAsState()
    val activeTransfer by repository.activeTransfer.collectAsState()
    val pendingApprovalsCount by repository.pendingApprovalsCount.collectAsState()
    val phoneTelemetry by repository.phoneTelemetry.collectAsState()
    val pcTelemetry by repository.pcTelemetry.collectAsState()
    val terminalState by repository.terminalState.collectAsState()
    val logs by repository.logs.collectAsState()
    val clipboardItems by repository.clipboardBufferItems.collectAsState()
    val clipboardThumbnailVersion by repository.clipboardThumbnailVersion.collectAsState()
    val peerHostState by repository.peerHostState.collectAsState()
    val adoptedNetworkId by repository.adoptedNetworkId.collectAsState()
    val pendingNetworkDecision by repository.pendingNetworkDecision.collectAsState()
    val desktopWallpaper by repository.desktopWallpaper.collectAsState()
    val activePermissionProfile by repository.permissionProfileState.collectAsState()
    val cameraDelivery by repository.cameraDelivery.collectAsState()
    val screenShareState by repository.screenShareState.collectAsState()
    val isScreenSharing = screenShareState == org.snow.capabilities.LiveScreenStreamHandler.StreamState.STREAMING
    val incomingStreams by repository.incomingScreenStreams.collectAsState()
    val selectedIncomingSenderId by repository.selectedIncomingSenderId.collectAsState()
    val eligibleScreenTargets = remember(savedDevices, connectedEndpoint, authState, activePermissionProfile) {
        repository.getEligibleScreenTargets()
    }

    // Navigation and Modal Visibility States
    var currentTab by remember { mutableStateOf(SnowTab.HOME) }
    var currentToolSubTab by remember { mutableStateOf(ToolSubTab.FILES) }
    var showDeviceIsland by remember { mutableStateOf(false) }
    var showApprovalsSheet by remember { mutableStateOf(false) }
    var approvalsInitialTab by remember { mutableIntStateOf(0) }
    var showConnectSheet by remember { mutableStateOf(false) }
    var showPeerHostQrDialog by remember { mutableStateOf(false) }
    var peerHostQrJson by remember { mutableStateOf<String?>(null) }
    var connectQrJson by remember { mutableStateOf<String?>(null) }
    var connectQrError by remember { mutableStateOf<String?>(null) }
    var isPreparingConnectQr by remember { mutableStateOf(false) }
    var isHomeRefreshing by remember { mutableStateOf(false) }
    var isDevicesRefreshing by remember { mutableStateOf(false) }
    var isFilesRefreshing by remember { mutableStateOf(false) }
    var generatedFederationCode by remember { mutableStateOf<String?>(null) }
    var updateInfo by remember { mutableStateOf<org.snow.transfer.FileTransferClient.AppUpdateInfo?>(null) }
    var updateDownloadProgress by remember { mutableStateOf<Int?>(null) }
    var isCheckingUpdate by remember { mutableStateOf(false) }
    var isGeneratingFederationCode by remember { mutableStateOf(false) }
    var isJoiningFederation by remember { mutableStateOf(false) }
    var isFederationActionInFlight by remember { mutableStateOf(false) }
    var busyClipboardItemId by remember { mutableStateOf<String?>(null) }
    var connectErrorMessage by remember { mutableStateOf<String?>(null) }
    var isConnectingByInput by remember { mutableStateOf(false) }
    var showShareDialog by remember { mutableStateOf(false) }
    var shareInput by remember { mutableStateOf("") }
    var scrollToClipboardTrigger by remember { mutableIntStateOf(0) }

    // Files state
    var currentPcPath by remember { mutableStateOf("C:\\") }
    var pcFilesList by remember { mutableStateOf<List<PcFileItem>>(emptyList()) }
    val safFolderUri = repository.safFolderManager.getDestinationDisplayName()

    // Approvals state (observed directly from shared repository StateFlow)
    val pendingApprovalsList by repository.pendingApprovals.collectAsState()

    // Federation grants state
    var federationGrantsList by remember { mutableStateOf<List<Map<String, Any?>>>(emptyList()) }

    // App updates status
    var appUpdateStatusText by remember { mutableStateOf("") }

    // Preferences
    val prefs = remember { context.getSharedPreferences(SnowUiRepository.PREFS_SETTINGS, android.content.Context.MODE_PRIVATE) }
    var instantClipboardSync by remember {
        mutableStateOf(prefs.getBoolean(SnowUiRepository.PREF_KEY_INSTANT_SYNC, true))
    }
    var autoSyncScreenshots by remember {
        mutableStateOf(prefs.getBoolean(SnowUiRepository.PREF_KEY_AUTO_SYNC_SCREENSHOTS, false))
    }
    var autoConnectNearby by remember {
        mutableStateOf(prefs.getBoolean(SnowUiRepository.PREF_KEY_AUTO_CONNECT_ENABLED, true))
    }
    var alwaysOnRemoteAccess by remember {
        mutableStateOf(repository.isRemoteRelayEnabled())
    }

    LaunchedEffect(revocationNotice) {
        val msg = revocationNotice
        if (!msg.isNullOrBlank()) {
            Toast.makeText(context, msg, Toast.LENGTH_LONG).show()
            repository.clearRevocationNotice()
        }
    }

    // Determine currently active authenticated device reactively
    val activeAuth = authState as? org.snow.network.AuthState.Authenticated
    val activeHostFromEndpoint = remember(connectedEndpoint, connectionState, authState) {
        if (SnowUiRepository.isSessionTrulyConnected(connectionState, authState)) {
            connectedEndpoint?.substringBeforeLast(":")?.trim().orEmpty()
        } else {
            ""
        }
    }
    val activeDevice = remember(savedDevices, activeHostFromEndpoint, activeAuth, connectionState) {
        if (!SnowUiRepository.isSessionTrulyConnected(connectionState, authState)) {
            null
        } else {
            savedDevices.find { dev ->
                (activeAuth?.peerSnowId != null && dev.snowId == activeAuth.peerSnowId) ||
                    (activeAuth?.peerDeviceId != null && dev.deviceId == activeAuth.peerDeviceId) ||
                    (activeHostFromEndpoint.isNotBlank() && (dev.host == activeHostFromEndpoint || (activeHostFromEndpoint == "127.0.0.1" && dev.host == "127.0.0.1")))
            }
        }
    }

    val activeDeviceName = activeDevice?.deviceName?.ifBlank { null }
        ?: activeAuth?.peerDeviceName?.ifBlank { null }
        ?: pcTelemetry.hostname
        ?: if (SnowUiRepository.isSessionTrulyConnected(connectionState, authState)) "SNOW Core" else "No device"

    val transport = remember(connectedEndpoint) {
        val ep = connectedEndpoint ?: ""
        when {
            ep.isBlank() -> "Auto"
            else -> org.snow.network.TransportClassifier.classifyRoute(host = ep).shortLabel
        }
    }

    // Refresh files when navigating to Tools Files tab, or screen streams on Screen tab
    LaunchedEffect(currentTab, currentToolSubTab, currentPcPath, connectionState) {
        if (currentTab == SnowTab.TOOLS && currentToolSubTab == ToolSubTab.FILES && connectionState == ConnectionState.CONNECTED) {
            repository.listPcDirectory(currentPcPath) { files, err ->
                if (files != null) {
                    pcFilesList = files
                }
            }
        } else if (currentTab == SnowTab.TOOLS && currentToolSubTab == ToolSubTab.SCREEN && connectionState == ConnectionState.CONNECTED) {
            repository.refreshIncomingStreamsOnce()
        }
    }

    // Refresh approvals list when opening approvals sheet
    LaunchedEffect(showApprovalsSheet) {
        if (showApprovalsSheet && connectionState == ConnectionState.CONNECTED) {
            repository.refreshPendingApprovals(force = true)
        }
    }

    // Refresh federation grants when on devices tab or opening floating device selector island
    LaunchedEffect(currentTab, showDeviceIsland, connectionState) {
        if ((currentTab == SnowTab.DEVICES || showDeviceIsland) && connectionState == ConnectionState.CONNECTED) {
            repository.listFederationGrants { success, grants, _ ->
                if (success && grants != null) {
                    federationGrantsList = grants
                }
            }
        }
    }

    // Lifecycle-aware 3s auto-refresh ticker when Activity is STARTED/resumed
    LaunchedEffect(lifecycleOwner, connectionState, currentTab, currentToolSubTab, currentPcPath) {
        lifecycleOwner.lifecycle.repeatOnLifecycle(Lifecycle.State.STARTED) {
            while (true) {
                repository.refreshPhoneTelemetry()
                if (connectionState == ConnectionState.CONNECTED) {
                    repository.queryPcStatus()
                    repository.fetchClipboardBuffer()
                    repository.refreshPendingApprovals()
                    if (currentTab == SnowTab.TOOLS && currentToolSubTab == ToolSubTab.FILES) {
                        repository.listPcDirectory(currentPcPath) { files, _ ->
                            if (files != null) pcFilesList = files
                        }
                    }
                }
                delay(3000L)
            }
        }
    }

    val isDark = when (themeMode) {
        AppCompatDelegate.MODE_NIGHT_YES -> true
        AppCompatDelegate.MODE_NIGHT_NO -> false
        else -> androidx.compose.foundation.isSystemInDarkTheme()
    }

    SideEffect {
        onSyncSystemBars(isDark)
    }

    SnowTheme(darkTheme = isDark) {
        val colors = LocalSnowColors.current

        Scaffold(
            modifier = Modifier
                .fillMaxSize()
                .background(colors.canvas)
                .statusBarsPadding()
                .navigationBarsPadding(),
            topBar = {
                Column {
                    SnowTopAppBar(
                        connectionState = connectionState,
                        connectedDeviceName = activeDeviceName,
                        transportMode = transport,
                        unreadApprovalsCount = pendingApprovalsCount,
                        onCapsuleClick = { showDeviceIsland = true },
                        onApprovalsClick = {
                            approvalsInitialTab = 0
                            showApprovalsSheet = true
                        }
                    )
                    if (isScreenSharing) {
                        Surface(
                            modifier = Modifier.fillMaxWidth(),
                            color = colors.accentEmerald.copy(alpha = 0.16f)
                        ) {
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(horizontal = 16.dp, vertical = 6.dp),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Text(
                                    text = "Sharing Screen",
                                    style = SnowTypography.labelMedium.copy(fontWeight = FontWeight.SemiBold),
                                    color = colors.accentEmerald
                                )
                                SnowOutlinedButton(
                                    text = "Stop",
                                    onClick = { repository.stopScreenShare() }
                                )
                            }
                        }
                    }
                }
            },
            bottomBar = {
                SnowBottomNavigationBar(
                    currentTab = currentTab,
                    onTabSelected = { currentTab = it }
                )
            },
            floatingActionButton = {
                if (currentTab == SnowTab.HOME || currentTab == SnowTab.DEVICES) {
                    Surface(
                        modifier = Modifier
                            .clip(RoundedCornerShape(16.dp))
                            .clickable { showConnectSheet = true },
                        shape = RoundedCornerShape(16.dp),
                        color = Color.Transparent,
                        shadowElevation = 8.dp
                    ) {
                        Box(
                            modifier = Modifier
                                .background(
                                    Brush.linearGradient(
                                        listOf(Color(0xFF2563EB), Color(0xFF00E5FF))
                                    )
                                )
                                .padding(horizontal = 20.dp, vertical = 14.dp),
                            contentAlignment = Alignment.Center
                        ) {
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.Center
                            ) {
                                Icon(
                                    imageVector = Icons.Default.Add,
                                    contentDescription = "Connect Device",
                                    tint = Color.White,
                                    modifier = Modifier.size(20.dp)
                                )
                                Spacer(modifier = Modifier.width(8.dp))
                                Text(
                                    text = "Connect",
                                    style = SnowTypography.titleSmall.copy(
                                        fontWeight = FontWeight.Bold,
                                        color = Color.White
                                    )
                                )
                            }
                        }
                    }
                }
            },
            containerColor = colors.canvas
        ) { innerPadding ->
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(innerPadding)
            ) {
                when (currentTab) {
                    SnowTab.HOME -> {
                        HomeScreen(
                            connectionState = connectionState,
                            connectedDevice = activeDevice,
                            connectedEndpoint = connectedEndpoint,
                            pcTelemetry = pcTelemetry,
                            phoneTelemetry = phoneTelemetry,
                            activeTransfer = activeTransfer,
                            clipboardItems = clipboardItems,
                            instantClipboardSync = instantClipboardSync,
                            onToggleInstantClipboardSync = { checked ->
                                instantClipboardSync = checked
                                prefs.edit().putBoolean(SnowUiRepository.PREF_KEY_INSTANT_SYNC, checked).apply()
                                repository.toggleInstantClipboardSync(checked)
                            },
                            onLockPc = {
                                repository.lockPc { success, err ->
                                    Toast.makeText(context, if (success) "PC Locked" else "Lock failed: $err", Toast.LENGTH_SHORT).show()
                                }
                            },
                            onRingPhone = {
                                repository.ringPeerPhone { success, err ->
                                    Toast.makeText(context, if (success) "Ringing peer phone..." else "Ring failed: $err", Toast.LENGTH_SHORT).show()
                                }
                            },
                            onSendFiles = onPickFilesToUpload,
                            onOpenTool = { toolId ->
                                when (toolId) {
                                    "clipboard" -> {
                                        scrollToClipboardTrigger++
                                        repository.fetchClipboardBuffer()
                                    }
                                    "notifications" -> {
                                        currentTab = SnowTab.SETTINGS
                                    }
                                    "share" -> {
                                        shareInput = ""
                                        showShareDialog = true
                                    }
                                    "terminal" -> {
                                        currentTab = SnowTab.TOOLS
                                        currentToolSubTab = ToolSubTab.TERMINAL
                                    }
                                    "media_screen" -> {
                                        currentTab = SnowTab.TOOLS
                                        currentToolSubTab = ToolSubTab.SCREEN
                                    }
                                    "media_camera", "media_control" -> {
                                        currentTab = SnowTab.TOOLS
                                        currentToolSubTab = ToolSubTab.MEDIA
                                    }
                                    "apps" -> {
                                        currentTab = SnowTab.TOOLS
                                        currentToolSubTab = ToolSubTab.APPS
                                    }
                                    else -> {
                                        currentTab = SnowTab.TOOLS
                                        currentToolSubTab = ToolSubTab.FILES
                                    }
                                }
                            },
                            onNavigateTab = { currentTab = it },
                            onOpenConnectSheet = { showConnectSheet = true },
                            onCancelTransfer = {
                                repository.cancelActiveTransfer()
                            },
                            desktopWallpaper = desktopWallpaper,
                            onRefreshWallpaper = { repository.refreshDesktopWallpaper() },
                            activePermissionProfile = activePermissionProfile,
                            onSelectAccessProfile = { repository.setAccessProfile(it) },
                            onApplyClipboardItem = { item ->
                                if (busyClipboardItemId == item.itemId) return@HomeScreen
                                busyClipboardItemId = item.itemId
                                repository.applyBufferItemToClipboard(item) { success, msg ->
                                    if (busyClipboardItemId == item.itemId) busyClipboardItemId = null
                                    Toast.makeText(
                                        context,
                                        formatApplyClipboardFeedback(success, msg),
                                        Toast.LENGTH_SHORT
                                    ).show()
                                }
                            },
                            onShareClipboardItem = { item ->
                                repository.shareClipboardItem(item) { ok, err ->
                                    if (!ok && !err.isNullOrBlank()) {
                                        Toast.makeText(context, err, Toast.LENGTH_SHORT).show()
                                    }
                                }
                            },
                            onPinClipboardItem = { itemId, pinned ->
                                repository.pinClipboardBufferItem(itemId, pinned)
                            },
                            onClearClipboardBuffer = {
                                repository.clearClipboardBuffer()
                            },
                            scrollToClipboardTrigger = scrollToClipboardTrigger,
                            clipboardThumbnailVersion = clipboardThumbnailVersion,
                            findCachedClipboardImage = { id -> repository.getCachedClipboardImageFile(id) },
                            autoSyncScreenshots = autoSyncScreenshots,
                            isRefreshing = isHomeRefreshing,
                            busyClipboardItemId = busyClipboardItemId,
                            onRefresh = {
                                isHomeRefreshing = true
                                repository.refreshPhoneTelemetry()
                                if (connectionState == ConnectionState.CONNECTED) {
                                    repository.queryPcStatus()
                                    repository.refreshDesktopWallpaper()
                                    repository.fetchClipboardBuffer()
                                }
                                scope.launch {
                                    delay(500L)
                                    isHomeRefreshing = false
                                }
                            }
                        )
                    }
                    SnowTab.DEVICES -> {
                        val shareCodeAvailability = remember(connectionState, authState) {
                            SnowUiRepository.evaluateShareCodeEligibility(connectionState, authState)
                        }
                        DevicesScreen(
                            savedDevices = savedDevices,
                            discoveredPeers = discoveredPeers,
                            activeHost = activeHostFromEndpoint,
                            federationGrants = federationGrantsList,
                            onConnectDevice = { dev: SavedDevice ->
                                repository.connect(dev.host, dev.port)
                            },
                            onDisconnectDevice = {
                                repository.disconnect()
                            },
                            onUnpairDevice = { dev: SavedDevice ->
                                repository.unpairDevice(dev)
                                Toast.makeText(context, "Unpaired ${dev.deviceName}", Toast.LENGTH_SHORT).show()
                            },
                            onUpdateTrustTier = { deviceId, tier ->
                                repository.updateDeviceTrustTier(deviceId, tier)
                            },
                            onUpdatePermissionProfile = { deviceId, profile ->
                                val canonical = SnowUiRepository.normalizeAccessProfile(profile)
                                repository.updateDevicePermissionProfile(deviceId, canonical)
                                val targetDev = savedDevices.find { it.deviceId == deviceId }
                                val isActiveDevice = targetDev != null && SnowUiRepository.isSessionTrulyConnected(connectionState, authState) && (
                                    (activeAuth?.peerSnowId != null && targetDev.snowId == activeAuth.peerSnowId) ||
                                        (activeAuth?.peerDeviceId != null && targetDev.deviceId == activeAuth.peerDeviceId) ||
                                        (activeHostFromEndpoint.isNotBlank() && targetDev.host == activeHostFromEndpoint)
                                    )
                                if (isActiveDevice) {
                                    repository.setAccessProfile(canonical)
                                }
                            },
                            onPairDiscoveredPeer = { peer ->
                                repository.connect(peer.ipAddress, peer.port)
                            },
                            canShareCode = shareCodeAvailability.allowed,
                            shareCodeDisabledReason = shareCodeAvailability.reason,
                            isConnectionBusy = connectionState == ConnectionState.CONNECTING || connectionState == ConnectionState.RECONNECTING,
                            isGeneratingFederationCode = isGeneratingFederationCode,
                            isJoiningFederation = isJoiningFederation,
                            isFederationActionInFlight = isFederationActionInFlight,
                            myNetworkId = adoptedNetworkId,
                            pendingNetworkDecision = pendingNetworkDecision,
                            onResolveNetworkDecision = { merge ->
                                repository.resolvePendingNetworkDecision(merge) { _, msg ->
                                    if (!msg.isNullOrBlank()) {
                                        Toast.makeText(context, msg, Toast.LENGTH_SHORT).show()
                                    }
                                }
                            },
                            transportSnapshots = transportSnapshots,
                            onSwitchDeviceTransport = { devId, mode ->
                                scope.launch {
                                    val (ok, msg) = repository.switchDeviceTransport(devId, mode)
                                    if (!ok || msg.isNotBlank()) {
                                        Toast.makeText(context, msg, Toast.LENGTH_SHORT).show()
                                    }
                                }
                            },
                            onGenerateFederationCode = {
                                if (isGeneratingFederationCode) return@DevicesScreen
                                isGeneratingFederationCode = true
                                repository.createFederationInvite { success, resMap, msg ->
                                    isGeneratingFederationCode = false
                                    if (success && resMap != null) {
                                        val code = resMap["invite_code"] as? String ?: (resMap["code"] as? String)
                                        if (code != null) {
                                            generatedFederationCode = code
                                        }
                                    } else {
                                        Toast.makeText(context, "Failed creating invite: $msg", Toast.LENGTH_SHORT).show()
                                    }
                                }
                            },
                            onAcceptFederationCode = { code ->
                                if (isJoiningFederation) return@DevicesScreen
                                isJoiningFederation = true
                                repository.connectByInput(code) { success, msg, _ ->
                                    isJoiningFederation = false
                                    Toast.makeText(context, if (success) "Federation connected!" else "Failed: $msg", Toast.LENGTH_SHORT).show()
                                }
                            },
                            onRevokeFederationGrant = { grantId ->
                                if (isFederationActionInFlight) return@DevicesScreen
                                isFederationActionInFlight = true
                                repository.revokeFederationGrant(grantId) { success, msg ->
                                    isFederationActionInFlight = false
                                    Toast.makeText(context, if (success) "Grant revoked" else "Failed: $msg", Toast.LENGTH_SHORT).show()
                                    if (success) {
                                        repository.listFederationGrants { _, grants, _ ->
                                            if (grants != null) federationGrantsList = grants
                                        }
                                    }
                                }
                            },
                            onFederationKillSwitch = {
                                if (isFederationActionInFlight) return@DevicesScreen
                                isFederationActionInFlight = true
                                repository.federationKillSwitch { success, msg ->
                                    isFederationActionInFlight = false
                                    Toast.makeText(context, if (success) "Federation kill switch triggered" else "Failed: $msg", Toast.LENGTH_SHORT).show()
                                }
                            },
                            onOpenConnectSheet = { showConnectSheet = true },
                            generatedFederationInvite = generatedFederationCode,
                            onDismissFederationInvite = { generatedFederationCode = null },
                            isConnected = SnowUiRepository.isSessionTrulyConnected(connectionState, authState) || peerHostState.isActive,
                            autoConnectNearby = autoConnectNearby,
                            onToggleAutoConnect = { checked ->
                                autoConnectNearby = checked
                                repository.setAutoReconnectEnabled(checked)
                            },
                            onDisconnectAll = {
                                repository.disconnectAll()
                                Toast.makeText(context, "All sessions disconnected", Toast.LENGTH_SHORT).show()
                            },
                            isRefreshing = isDevicesRefreshing,
                            onRefresh = {
                                isDevicesRefreshing = true
                                repository.refreshPhoneTelemetry()
                                repository.refreshDiscovery(resumeUdp = true)
                                if (connectionState == ConnectionState.CONNECTED) {
                                    repository.listFederationGrants { ok, grants, _ ->
                                        if (ok && grants != null) federationGrantsList = grants
                                    }
                                }
                                scope.launch {
                                    delay(500L)
                                    isDevicesRefreshing = false
                                }
                            }
                        )
                    }
                    SnowTab.TOOLS -> {
                        ToolsScreen(
                            currentSubTab = currentToolSubTab,
                            onSubTabChanged = { currentToolSubTab = it },
                            safFolderUri = safFolderUri,
                            filesList = pcFilesList,
                            currentPath = currentPcPath,
                            onChangeSafFolder = onPickSafFolder,
                            onNavigatePath = { newPath ->
                                currentPcPath = newPath
                                repository.listPcDirectory(newPath) { files, _ ->
                                    if (files != null) pcFilesList = files
                                }
                            },
                            onDownloadFile = { file ->
                                repository.startFileDownload(file) { _, _ -> }
                            },
                            onUploadFile = onPickFilesToUpload,
                            isFilesRefreshing = isFilesRefreshing,
                            onRefreshFiles = {
                                isFilesRefreshing = true
                                repository.listPcDirectory(currentPcPath) { files, _ ->
                                    if (files != null) pcFilesList = files
                                    isFilesRefreshing = false
                                }
                            },
                            activeTransfer = activeTransfer,
                            onCancelTransfer = { repository.cancelActiveTransfer() },
                            onDismissTransfer = { repository.dismissActiveTransfer() },
                            allowlistedApps = AppLauncherBottomSheet.ALLOWLISTED_WINDOWS_APPS,
                            onLaunchApp = { target, friendlyName ->
                                repository.launchWindowsApp(target) { success, err ->
                                    Toast.makeText(context, if (success) "Launched $friendlyName" else "Launch failed: $err", Toast.LENGTH_SHORT).show()
                                }
                            },
                            isScreenSharing = isScreenSharing,
                            onToggleScreenShare = { start ->
                                if (start) {
                                    onToggleScreenShareConsent()
                                } else {
                                    repository.stopScreenShare()
                                }
                            },
                            incomingStreams = incomingStreams,
                            selectedIncomingSenderId = selectedIncomingSenderId,
                            onSelectIncomingSender = { senderId -> repository.selectIncomingSender(senderId) },
                            onCloseIncomingViewer = { repository.closeIncomingViewer() },
                            eligibleScreenTargets = eligibleScreenTargets,
                            onStartScreenShareWithTargets = { targetIds ->
                                repository.setPendingScreenShareTargets(targetIds)
                                onToggleScreenShareConsent()
                            },
                            activePermissionProfile = activePermissionProfile,
                            onTriggerCameraCapture = onLaunchCameraCapture,
                            onSendMediaKey = { key ->
                                repository.sendMediaKey(key) { success, err ->
                                    if (!success) Toast.makeText(context, "Media key failed: $err", Toast.LENGTH_SHORT).show()
                                }
                            },
                            onSendMediaVolume = { vol ->
                                repository.sendMediaKey("volume_set", vol) { success, err ->
                                    if (!success) Toast.makeText(context, "Volume set failed: $err", Toast.LENGTH_SHORT).show()
                                }
                            },
                            cameraDelivery = cameraDelivery,
                            onRetryCameraUpload = {
                                repository.retryCameraUpload { ok, err ->
                                    Toast.makeText(context, if (ok) "Photo delivered: $err" else "Retry failed: $err", Toast.LENGTH_SHORT).show()
                                }
                            },
                            onDismissCameraDelivery = {
                                repository.dismissCameraDelivery()
                            },
                            terminalState = terminalState,
                            onExecuteTerminalCommand = { cmd ->
                                repository.executeTerminalCommand(cmd)
                            },
                            onConfirmTerminalCommand = { cmd, ticket ->
                                repository.executeTerminalCommand(cmd, ticket)
                            },
                            onCancelTerminalCommand = {
                                repository.cancelTerminalCommand()
                            },
                            onClearTerminal = {
                                repository.clearTerminalOutput()
                            }
                        )
                    }
                    SnowTab.SETTINGS -> {
                        SettingsScreen(
                            currentThemeMode = themeMode,
                            onThemeModeChanged = { mode ->
                                onThemeModeChanged(mode)
                                prefs.edit().putInt(SettingsViewModel.KEY_THEME_MODE, mode).apply()
                                AppCompatDelegate.setDefaultNightMode(mode)
                            },
                            alwaysOnRemoteAccess = alwaysOnRemoteAccess,
                            onToggleAlwaysOnRemoteAccess = { enabled ->
                                val ep = repository.getEffectiveRelayEndpointForHub()
                                alwaysOnRemoteAccess = enabled
                                repository.updateRemoteRelayConfig(enabled, ep)
                                if (enabled) {
                                    Toast.makeText(
                                        context,
                                        "Render Hub remote access enabled.",
                                        Toast.LENGTH_SHORT
                                    ).show()
                                }
                            },
                            instantClipboardSync = instantClipboardSync,
                            onToggleInstantClipboardSync = { checked ->
                                instantClipboardSync = checked
                                prefs.edit().putBoolean(SnowUiRepository.PREF_KEY_INSTANT_SYNC, checked).apply()
                                repository.toggleInstantClipboardSync(checked)
                            },
                            autoSyncScreenshots = autoSyncScreenshots,
                            onToggleAutoSyncScreenshots = { checked ->
                                if (checked) {
                                    val perm = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                                        Manifest.permission.READ_MEDIA_IMAGES
                                    } else {
                                        Manifest.permission.READ_EXTERNAL_STORAGE
                                    }
                                    if (ContextCompat.checkSelfPermission(context, perm) == PackageManager.PERMISSION_GRANTED) {
                                        autoSyncScreenshots = true
                                        prefs.edit().putBoolean(SnowUiRepository.PREF_KEY_AUTO_SYNC_SCREENSHOTS, true).apply()
                                        repository.screenshotObserver.register()
                                    } else {
                                        onRequestScreenshotPermission { granted ->
                                            autoSyncScreenshots = granted
                                            prefs.edit().putBoolean(SnowUiRepository.PREF_KEY_AUTO_SYNC_SCREENSHOTS, granted).apply()
                                            if (granted) {
                                                repository.screenshotObserver.register()
                                            } else {
                                                Toast.makeText(context, "Media permission required to auto-sync screenshots.", Toast.LENGTH_LONG).show()
                                            }
                                        }
                                    }
                                } else {
                                    autoSyncScreenshots = false
                                    prefs.edit().putBoolean(SnowUiRepository.PREF_KEY_AUTO_SYNC_SCREENSHOTS, false).apply()
                                    repository.screenshotObserver.unregister()
                                }
                            },
                            autoConnectNearby = autoConnectNearby,
                            onToggleAutoConnectNearby = { checked ->
                                autoConnectNearby = checked
                                repository.setAutoReconnectEnabled(checked)
                            },
                            mySnowId = repository.canonicalSnowId,
                            myDeviceId = repository.identity.deviceId,
                            myNetworkId = adoptedNetworkId.orEmpty(),
                            permanentDeviceSnowId = repository.permanentDeviceSnowId.collectAsState().value,
                            permanentDeviceMcpUrl = repository.permanentDeviceMcpUrl.collectAsState().value,
                            identityError = repository.identityError.collectAsState().value,
                            onExportRecoveryKey = { confirmed -> repository.exportDeviceRecoveryKeyWithConsent(confirmed) },
                            onExportEncryptedBackupToUri = { uri, pass -> repository.exportEncryptedIdentityBackupToSaf(uri, pass) },
                            onRestoreDeviceIdentity = { rawInput, pass -> repository.restoreDeviceIdentityFromRecovery(rawInput, pass, true) },
                            androidRemoteMcpEnabled = repository.androidRemoteMcpEnabled.collectAsState().value,
                            onToggleAndroidRemoteMcp = { enabled -> repository.setAndroidRemoteMcpEnabled(enabled) },
                            androidMcpConnected = repository.androidMcpTunnelState.collectAsState().value.connected,
                            androidMcpError = repository.androidMcpTunnelState.collectAsState().value.lastError,
                            authorizedOAuthClients = repository.authorizedOAuthClients.collectAsState().value,
                            onRevokeOAuthClient = { cid -> repository.revokeAuthorizedOAuthClient(cid) },
                            remoteAiLinkUrl = repository.getRemoteAiLinkDiagnostics().first,
                            remoteAiLinkStatus = repository.getRemoteAiLinkDiagnostics().second,
                            relayEndpoint = repository.getRemoteRelayEndpoint(),
                            onUpdateRelayEndpoint = { ep ->
                                repository.setRemoteRelayEndpoint(ep)
                                if (alwaysOnRemoteAccess) {
                                    repository.updateRemoteRelayConfig(true, ep)
                                }
                            },
                            onCheckAppUpdate = {
                                if (isCheckingUpdate) return@SettingsScreen
                                isCheckingUpdate = true
                                appUpdateStatusText = "Checking..."
                                repository.checkAppUpdate { info ->
                                    isCheckingUpdate = false
                                    updateInfo = info
                                    appUpdateStatusText = if (info?.available == true) "Update available: v${info.versionName}" else "v7.0.0 • Up to date"
                                }
                            },
                            updateStatusText = appUpdateStatusText,
                            isUpdateAvailable = updateInfo?.available == true,
                            updateVersionName = updateInfo?.versionName ?: "",
                            updateDownloadProgress = updateDownloadProgress,
                            isCheckingUpdate = isCheckingUpdate,
                            onInstallUpdate = {
                                updateInfo?.let { info ->
                                    updateDownloadProgress = 0
                                    repository.downloadAndInstallUpdate(
                                        info,
                                        onProgress = { pct -> updateDownloadProgress = pct },
                                        onComplete = { success, msg ->
                                            updateDownloadProgress = null
                                            Toast.makeText(context, if (success) "Update downloaded" else "Failed: $msg", Toast.LENGTH_SHORT).show()
                                        }
                                    )
                                }
                            },
                            logs = logs,
                            onConnectManualIp = { ip ->
                                repository.connectByInput(ip) { success, msg, _ ->
                                    Toast.makeText(context, if (success) "Connected!" else "Failed: $msg", Toast.LENGTH_SHORT).show()
                                }
                            },
                            onResetTrust = {
                                repository.resetTrust()
                                Toast.makeText(context, "All trust and pairings reset", Toast.LENGTH_SHORT).show()
                            },
                            onClearLogs = {
                                repository.clearLogs()
                            },
                            onCopyLogs = {
                                val text = logs.joinToString("\n") { "[${it.timestamp}] [${it.tag}] ${it.message}" }
                                val cm = context.getSystemService(android.content.Context.CLIPBOARD_SERVICE) as android.content.ClipboardManager
                                cm.setPrimaryClip(android.content.ClipData.newPlainText("SNOW Logs", text))
                                Toast.makeText(context, "Logs copied to clipboard", Toast.LENGTH_SHORT).show()
                            }
                        )
                    }
                }

                // Modal Overlays
                SnowDeviceSelectorIsland(
                    visible = showDeviceIsland,
                    onDismiss = { showDeviceIsland = false },
                    localDeviceName = repository.identity.deviceName,
                    localSnowId = repository.canonicalSnowId,
                    peerHostActive = peerHostState.isActive,
                    pairedDevices = savedDevices,
                    activeDeviceHost = repository.currentTargetHost,
                    onSelectDevice = { dev: SavedDevice ->
                        repository.connect(dev.host, dev.port)
                    },
                    onJoinAnotherNetwork = {
                        showConnectSheet = true
                    },
                    federationGrants = federationGrantsList,
                    onFederationGrantClick = {
                        currentTab = SnowTab.DEVICES
                    },
                    localPhoneTelemetry = phoneTelemetry
                )

                SnowApprovalsSheet(
                    visible = showApprovalsSheet,
                    onDismiss = { showApprovalsSheet = false },
                    pendingApprovals = pendingApprovalsList,
                    logs = logs,
                    onResolveApproval = { reqId, decision ->
                        repository.resolveApproval(reqId, decision) { }
                    },
                    initialTab = approvalsInitialTab
                )

                if (showShareDialog) {
                    AlertDialog(
                        onDismissRequest = { showShareDialog = false },
                        title = {
                            Text(
                                text = "Share Link or Note",
                                style = SnowTypography.titleMedium,
                                color = colors.textPrimary
                            )
                        },
                        text = {
                            Column {
                                Text(
                                    text = "Send an HTTP/HTTPS URL or text note directly to the connected device:",
                                    style = SnowTypography.bodySmall,
                                    color = colors.textSecondary
                                )
                                Spacer(modifier = Modifier.height(10.dp))
                                OutlinedTextField(
                                    value = shareInput,
                                    onValueChange = { shareInput = it },
                                    modifier = Modifier.fillMaxWidth(),
                                    placeholder = { Text("https://example.com or quick note...") },
                                    singleLine = false,
                                    shape = RoundedCornerShape(12.dp)
                                )
                            }
                        },
                        confirmButton = {
                            SnowGradientButton(
                                text = "Send",
                                onClick = {
                                    val clean = shareInput.trim()
                                    if (clean.isNotEmpty()) {
                                        val isHttpUrl = clean.startsWith("https://", ignoreCase = true) ||
                                            clean.startsWith("http://", ignoreCase = true)
                                        repository.shareLink(
                                            url = if (isHttpUrl) clean else null,
                                            text = if (!isHttpUrl) clean else null
                                        ) { ok, err ->
                                            Toast.makeText(
                                                context,
                                                if (ok) "Shared successfully" else "Share failed: ${err ?: "Rejected"}",
                                                Toast.LENGTH_SHORT
                                            ).show()
                                        }
                                        showShareDialog = false
                                    }
                                }
                            )
                        },
                        dismissButton = {
                            SnowOutlinedButton(
                                text = "Cancel",
                                onClick = { showShareDialog = false }
                            )
                        },
                        containerColor = if (colors.isDark) Color(0xFF1E1E1E) else Color.White
                    )
                }

                SnowConnectSheet(
                    visible = showConnectSheet,
                    onDismiss = {
                        showConnectSheet = false
                        connectErrorMessage = null
                    },
                    onScanQr = onLaunchQrScanner,
                    onConnectInput = { input ->
                        isConnectingByInput = true
                        connectErrorMessage = null
                        repository.connectByInput(input) { success, msg, _ ->
                            isConnectingByInput = false
                            if (success) {
                                showConnectSheet = false
                                Toast.makeText(context, "Connected successfully", Toast.LENGTH_SHORT).show()
                            } else {
                                connectErrorMessage = msg
                            }
                        }
                    },
                    mySnowId = repository.canonicalSnowId,
                    myDeviceId = repository.identity.deviceId,
                    isConnecting = isConnectingByInput,
                    errorMessage = connectErrorMessage,
                    peerHostState = peerHostState,
                    pairingQrJson = connectQrJson,
                    pairingQrError = connectQrError,
                    isPreparingPairingQr = isPreparingConnectQr,
                    onPreparePairingQr = {
                        isPreparingConnectQr = true
                        connectQrError = null
                        repository.preparePeerHostPairingQr { qrJson, err ->
                            isPreparingConnectQr = false
                            connectQrJson = qrJson
                            connectQrError = err
                        }
                    },
                    onRegeneratePairingPin = {
                        repository.generatePeerHostPin()
                        connectQrJson = repository.generatePeerHostQrJson()
                    },
                    onCancelPairingPin = {
                        repository.cancelPeerHostPairing()
                        connectQrJson = null
                    },
                    myNetworkId = adoptedNetworkId
                )

                val activeMergeDecision = pendingNetworkDecision
                if (activeMergeDecision != null) {
                    AlertDialog(
                        onDismissRequest = {
                            repository.resolvePendingNetworkDecision(false) { _, _ -> }
                        },
                        title = {
                            Text(
                                text = "Separate SNOW Networks Detected",
                                style = SnowTypography.titleMedium
                            )
                        },
                        text = {
                            Text(
                                text = "${activeMergeDecision.peerDeviceName} belongs to ${activeMergeDecision.remoteNetworkId}, while this device belongs to ${activeMergeDecision.localNetworkId}. Merge both into one shared network (requires mutual owner approval) or keep them separate?",
                                style = SnowTypography.bodySmall
                            )
                        },
                        confirmButton = {
                            SnowTonalButton(
                                text = "Merge Networks",
                                onClick = {
                                    repository.resolvePendingNetworkDecision(true) { _, msg ->
                                        if (!msg.isNullOrBlank()) {
                                            Toast.makeText(context, msg, Toast.LENGTH_SHORT).show()
                                        }
                                    }
                                }
                            )
                        },
                        dismissButton = {
                            SnowOutlinedButton(
                                text = "Keep Separate",
                                onClick = {
                                    repository.resolvePendingNetworkDecision(false) { _, msg ->
                                        if (!msg.isNullOrBlank()) {
                                            Toast.makeText(context, msg, Toast.LENGTH_SHORT).show()
                                        }
                                    }
                                }
                            )
                        }
                    )
                }

                // Phase 27 Peer Host Mode Pairing QR Dialog
                if (showPeerHostQrDialog && !peerHostQrJson.isNullOrBlank()) {
                    val qrBmp = remember(peerHostQrJson) {
                        try {
                            val bitMatrix = QRCodeWriter().encode(peerHostQrJson, BarcodeFormat.QR_CODE, 512, 512)
                            val w = bitMatrix.width
                            val h = bitMatrix.height
                            val bmp = android.graphics.Bitmap.createBitmap(w, h, android.graphics.Bitmap.Config.RGB_565)
                            for (x in 0 until w) {
                                for (y in 0 until h) {
                                    bmp.setPixel(x, y, if (bitMatrix.get(x, y)) android.graphics.Color.BLACK else android.graphics.Color.WHITE)
                                }
                            }
                            bmp
                        } catch (_: Exception) {
                            null
                        }
                    }

                    AlertDialog(
                        onDismissRequest = { showPeerHostQrDialog = false },
                        title = {
                            Text(
                                text = "Peer Pairing QR",
                                style = SnowTypography.titleMedium,
                                color = colors.textPrimary
                            )
                        },
                        text = {
                            Column(horizontalAlignment = Alignment.CenterHorizontally, modifier = Modifier.fillMaxWidth()) {
                                Text(
                                    text = "Scan this QR code from another SNOW Android device to establish a direct phone-to-phone peer link:",
                                    style = SnowTypography.bodySmall,
                                    color = colors.textSecondary
                                )
                                Spacer(modifier = Modifier.height(16.dp))
                                if (qrBmp != null) {
                                    Image(
                                        bitmap = qrBmp.asImageBitmap(),
                                        contentDescription = "Peer Pairing QR",
                                        modifier = Modifier
                                            .size(200.dp)
                                            .clip(RoundedCornerShape(12.dp))
                                    )
                                }
                            }
                        },
                        confirmButton = {
                            SnowTonalButton(
                                text = "Close",
                                onClick = { showPeerHostQrDialog = false }
                            )
                        },
                        containerColor = if (colors.isDark) Color(0xFF1E1E1E) else Color.White
                    )
                }
            }
        }
    }
}
