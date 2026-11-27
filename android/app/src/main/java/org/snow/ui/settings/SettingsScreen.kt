package org.snow.ui.settings

import android.Manifest
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.PowerManager
import android.provider.Settings
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatDelegate
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
import androidx.compose.material.icons.filled.BatteryChargingFull
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.ChevronRight
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.DarkMode
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.FolderOpen
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.LightMode
import androidx.compose.material.icons.filled.LockReset
import androidx.compose.material.icons.filled.Notifications
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.SettingsBrightness
import androidx.compose.material.icons.filled.Sync
import androidx.compose.material.icons.filled.SystemUpdate
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Divider
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLifecycleOwner
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import org.snow.capabilities.ActionNotificationHelper
import org.snow.service.SnowForegroundService
import org.snow.ui.components.SnowBadgeType
import org.snow.ui.components.SnowCard
import org.snow.ui.components.SnowFilterChip
import org.snow.ui.components.SnowGradientButton
import org.snow.ui.components.SnowOutlinedButton
import org.snow.ui.components.SnowSectionHeader
import org.snow.ui.components.SnowStatusBadge
import org.snow.ui.components.SnowTonalButton
import org.snow.ui.files.SafFolderManager
import org.snow.ui.theme.LocalSnowColors
import org.snow.ui.theme.SnowTypography

/**
 * Flagship Settings Screen handling:
 * - Appearance Mode (System, Light, Dark)
 * - Always-On Remote Access & Background Sync
 * - Permissions & Setup (Android 14+ Notification guide, Storage, Battery, QS Tiles)
 * - Connectivity & Sync switches
 * - App Updates check
 * - Advanced Diagnostics & Security controls
 */
@Composable
fun SettingsScreen(
    currentThemeMode: Int,
    onThemeModeChanged: (Int) -> Unit,
    alwaysOnRemoteAccess: Boolean,
    onToggleAlwaysOnRemoteAccess: (Boolean) -> Unit,
    instantClipboardSync: Boolean,
    onToggleInstantClipboardSync: (Boolean) -> Unit,
    autoSyncScreenshots: Boolean,
    onToggleAutoSyncScreenshots: (Boolean) -> Unit,
    autoConnectNearby: Boolean,
    onToggleAutoConnectNearby: (Boolean) -> Unit,
    mySnowId: String,
    myDeviceId: String,
    myNetworkId: String = "",
    remoteAiLinkUrl: String? = null,
    remoteAiLinkStatus: String = "Not linked to a PC host yet",
    relayEndpoint: String,
    onUpdateRelayEndpoint: (String) -> Unit,
    onCheckAppUpdate: () -> Unit,
    updateStatusText: String,
    isUpdateAvailable: Boolean = false,
    updateVersionName: String = "",
    updateDownloadProgress: Int? = null,
    onInstallUpdate: () -> Unit = {},
    isCheckingUpdate: Boolean = false,
    logs: List<org.snow.ui.UiLogEntry> = emptyList(),
    onConnectManualIp: (String) -> Unit = {},
    onResetTrust: () -> Unit,
    onClearLogs: () -> Unit,
    onCopyLogs: () -> Unit,
    permanentDeviceSnowId: String = "",
    permanentDeviceMcpUrl: String = "",
    identityError: String? = null,
    onExportRecoveryKey: (Boolean) -> Pair<Boolean, String> = { false to "Unavailable" },
    onExportEncryptedBackupToUri: (Uri, String) -> Pair<Boolean, String> = { _, _ -> false to "Unavailable" },
    onRestoreDeviceIdentity: (String, String?) -> Pair<Boolean, String> = { _, _ -> false to "Unavailable" },
    androidRemoteMcpEnabled: Boolean = true,
    onToggleAndroidRemoteMcp: (Boolean) -> Unit = {},
    androidMcpConnected: Boolean = false,
    androidMcpError: String? = null,
    authorizedOAuthClients: List<org.snow.mcp.AuthorizedOAuthClientSummary> = emptyList(),
    onRevokeOAuthClient: (String) -> Unit = {},
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current
    val colors = LocalSnowColors.current
    val clipboardManager = LocalClipboardManager.current
    var showNotificationGuide by remember { mutableStateOf(false) }
    var showAdvancedDiagnostics by remember { mutableStateOf(false) }
    var showResetConfirm by remember { mutableStateOf(false) }
    var showRecoveryExportWarning by remember { mutableStateOf(false) }
    var revealedRecoveryKey by remember { mutableStateOf<String?>(null) }
    var showEncryptedBackupDialog by remember { mutableStateOf(false) }
    var backupPassphrase by remember { mutableStateOf("") }
    var showRestoreDialog by remember { mutableStateOf(false) }
    var restoreInput by remember { mutableStateOf("") }
    var restorePassphrase by remember { mutableStateOf("") }
    var recoveryFeedback by remember { mutableStateOf<String?>(null) }
    var relayInput by remember { mutableStateOf(relayEndpoint) }
    var manualConnectInput by remember { mutableStateOf("") }

    val encryptedBackupSafLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.CreateDocument("application/json")
    ) { pickedUri ->
        val pass = backupPassphrase
        backupPassphrase = ""
        if (pickedUri != null) {
            val (_, msg) = onExportEncryptedBackupToUri(pickedUri, pass)
            recoveryFeedback = msg
        }
    }

    fun queryNotificationAccess(): Boolean =
        androidx.core.app.NotificationManagerCompat.getEnabledListenerPackages(context).contains(context.packageName)

    fun refreshPermissionSnapshot(): SettingsPermissionSnapshot =
        SettingsPermissionInspector.inspect(
            context = context,
            listenerGranted = queryNotificationAccess()
        )

    var permSnapshot by remember { mutableStateOf(refreshPermissionSnapshot()) }
    var isNotificationAccessGranted by remember { mutableStateOf(permSnapshot.notificationListenerGranted) }
    val isServiceRunning by SnowForegroundService.isServiceRunningFlow.collectAsState()

    val safPickerLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocumentTree()
    ) { pickedUri ->
        if (pickedUri != null) {
            val saved = SafFolderManager(context).persistFolderUri(pickedUri)
            permSnapshot = refreshPermissionSnapshot()
            isNotificationAccessGranted = permSnapshot.notificationListenerGranted
            val msg = if (saved) {
                "Transfer folder updated: ${permSnapshot.safFolderName}"
            } else {
                "Could not persist folder permission. Previous folder kept."
            }
            try {
                android.widget.Toast.makeText(context, msg, android.widget.Toast.LENGTH_SHORT).show()
            } catch (_: Exception) {
            }
        }
    }

    DisposableEffect(lifecycleOwner) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_RESUME) {
                permSnapshot = refreshPermissionSnapshot()
                isNotificationAccessGranted = permSnapshot.notificationListenerGranted
            }
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
    }

    LazyColumn(
        modifier = modifier
            .fillMaxSize()
            .padding(horizontal = 16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        item {
            Spacer(modifier = Modifier.height(8.dp))
        }

        // Appearance Mode Section
        item {
            SnowSectionHeader(title = "Appearance")
            SnowCard(modifier = Modifier.fillMaxWidth(), cornerRadius = 20.dp) {
                Column {
                    Text(
                        text = "Theme",
                        style = SnowTypography.titleSmall,
                        color = colors.textPrimary
                    )
                    Spacer(modifier = Modifier.height(12.dp))

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        ThemeOptionPill(
                            label = "System",
                            icon = Icons.Default.SettingsBrightness,
                            selected = currentThemeMode == AppCompatDelegate.MODE_NIGHT_FOLLOW_SYSTEM,
                            onClick = { onThemeModeChanged(AppCompatDelegate.MODE_NIGHT_FOLLOW_SYSTEM) },
                            modifier = Modifier.weight(1f)
                        )
                        ThemeOptionPill(
                            label = "Light",
                            icon = Icons.Default.LightMode,
                            selected = currentThemeMode == AppCompatDelegate.MODE_NIGHT_NO,
                            onClick = { onThemeModeChanged(AppCompatDelegate.MODE_NIGHT_NO) },
                            modifier = Modifier.weight(1f)
                        )
                        ThemeOptionPill(
                            label = "Dark",
                            icon = Icons.Default.DarkMode,
                            selected = currentThemeMode == AppCompatDelegate.MODE_NIGHT_YES,
                            onClick = { onThemeModeChanged(AppCompatDelegate.MODE_NIGHT_YES) },
                            modifier = Modifier.weight(1f)
                        )
                    }
                }
            }
        }

        // Always-On Remote Access & Sync Switches
        item {
            SnowSectionHeader(title = "Sync & Background Services")
            SnowCard(modifier = Modifier.fillMaxWidth(), cornerRadius = 20.dp) {
                Column {
                    SettingsSwitchRow(
                        title = "Always-On Remote Access",
                        checked = alwaysOnRemoteAccess,
                        onCheckedChange = onToggleAlwaysOnRemoteAccess
                    )

                    Divider(color = colors.borderSubtle, modifier = Modifier.padding(vertical = 10.dp))

                    SettingsSwitchRow(
                        title = "Auto-Connect Nearby",
                        checked = autoConnectNearby,
                        onCheckedChange = onToggleAutoConnectNearby
                    )

                    Divider(color = colors.borderSubtle, modifier = Modifier.padding(vertical = 10.dp))

                    SettingsSwitchRow(
                        title = "Instant Clipboard Sync",
                        checked = instantClipboardSync,
                        onCheckedChange = onToggleInstantClipboardSync
                    )

                    Divider(color = colors.borderSubtle, modifier = Modifier.padding(vertical = 10.dp))

                    SettingsSwitchRow(
                        title = "Auto-Sync Screenshots",
                        checked = autoSyncScreenshots,
                        onCheckedChange = onToggleAutoSyncScreenshots
                    )
                }
            }
        }

        // Permissions & Setup Guide
        item {
            SnowSectionHeader(title = "Permissions & System Setup")
            SnowCard(modifier = Modifier.fillMaxWidth(), cornerRadius = 20.dp) {
                Column {
                    PermissionRowItem(
                        icon = Icons.Default.Notifications,
                        title = "Post Notifications",
                        subtitle = if (permSnapshot.postNotificationsGranted) {
                            "Foreground bridge status & background tap-to-open notifications ready."
                        } else {
                            "Required for persistent foreground bridge & tap-to-open app notifications."
                        },
                        statusText = if (permSnapshot.postNotificationsGranted) "GRANTED" else "REQUIRED",
                        isGranted = permSnapshot.postNotificationsGranted,
                        onClick = {
                            context.startActivity(createAppNotificationSettingsIntent(context.packageName))
                        }
                    )

                    Divider(color = colors.borderSubtle, modifier = Modifier.padding(vertical = 10.dp))

                    PermissionRowItem(
                        icon = Icons.Default.Notifications,
                        title = "Notification Sync & Listener",
                        subtitle = "App launching from background & folder transfers use Android Notifications & SAF folders.",
                        statusText = if (isNotificationAccessGranted) "GRANTED" else "SETUP",
                        isGranted = isNotificationAccessGranted,
                        onClick = { showNotificationGuide = true }
                    )

                    Divider(color = colors.borderSubtle, modifier = Modifier.padding(vertical = 10.dp))

                    PermissionRowItem(
                        icon = Icons.Default.FolderOpen,
                        title = "Transfer Folder (SAF)",
                        subtitle = if (permSnapshot.safFolderConfigured) {
                            "Active folder: ${permSnapshot.safFolderName}"
                        } else {
                            "Default: Downloads/SNOW (Tap to authorize a custom folder)"
                        },
                        statusText = if (permSnapshot.safFolderConfigured) "CONFIGURED" else "DEFAULT",
                        isGranted = permSnapshot.safFolderConfigured,
                        onClick = {
                            safPickerLauncher.launch(SafFolderManager(context).getDestinationUri())
                        }
                    )

                    Divider(color = colors.borderSubtle, modifier = Modifier.padding(vertical = 10.dp))

                    val liveBg = permSnapshot.copy(isForegroundServiceRunning = isServiceRunning || permSnapshot.isForegroundServiceRunning)
                    PermissionRowItem(
                        icon = Icons.Default.BatteryChargingFull,
                        title = "Background Activity & Service",
                        subtitle = liveBg.backgroundSummaryText(),
                        statusText = liveBg.backgroundBadgeText(),
                        isGranted = liveBg.isBackgroundFullyHealthy(),
                        onClick = {
                            org.snow.ui.SnowUiRepository.openBatteryOptimizationSettings(context)
                        }
                    )
                }
            }
        }

        // App Updates Card
        item {
            SnowSectionHeader(title = "Application Updates")
            SnowCard(modifier = Modifier.fillMaxWidth(), cornerRadius = 20.dp) {
                Column {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = "SNOW Flagship",
                                style = SnowTypography.titleSmall,
                                color = colors.textPrimary
                            )
                            Text(
                                text = updateStatusText.ifBlank { "v7.0.0 • Up to date" },
                                style = SnowTypography.bodySmall,
                                color = colors.textSecondary
                            )
                        }
                        if (isUpdateAvailable) {
                            SnowGradientButton(
                                text = "Download & Install v$updateVersionName",
                                icon = Icons.Default.SystemUpdate,
                                onClick = onInstallUpdate,
                                enabled = updateDownloadProgress == null
                            )
                        } else {
                            SnowTonalButton(
                                text = if (isCheckingUpdate) "Checking..." else "Check",
                                icon = Icons.Default.SystemUpdate,
                                onClick = onCheckAppUpdate,
                                enabled = !isCheckingUpdate,
                                isLoading = isCheckingUpdate
                            )
                        }
                    }
                    if (updateDownloadProgress != null) {
                        Spacer(modifier = Modifier.height(12.dp))
                        LinearProgressIndicator(
                            progress = (updateDownloadProgress.coerceIn(0, 100) / 100f),
                            modifier = Modifier
                                .fillMaxWidth()
                                .height(6.dp)
                                .clip(RoundedCornerShape(9999.dp)),
                            color = colors.accentCyan,
                            trackColor = colors.surfaceElevated
                        )
                        Spacer(modifier = Modifier.height(4.dp))
                        Text(
                            text = "Downloading signed update... ${updateDownloadProgress.coerceIn(0, 100)}%",
                            style = SnowTypography.labelSmall,
                            color = colors.accentCyan
                        )
                    }
                }
            }
        }

        // Collapsible Advanced Diagnostics & Reset
        item {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(8.dp))
                    .clickable { showAdvancedDiagnostics = !showAdvancedDiagnostics }
                    .padding(vertical = 4.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                SnowSectionHeader(title = "Security & Advanced Diagnostics")
                Text(
                    text = if (showAdvancedDiagnostics) "Hide ▲" else "Show ▼",
                    style = SnowTypography.labelSmall.copy(fontWeight = FontWeight.Bold),
                    color = colors.accentCyan
                )
            }

            if (showAdvancedDiagnostics) {
                Spacer(modifier = Modifier.height(8.dp))
                SnowCard(modifier = Modifier.fillMaxWidth(), cornerRadius = 20.dp) {
                    Column {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Column(modifier = Modifier.weight(1f)) {
                                Text(text = "My SNOW ID", style = SnowTypography.labelSmall, color = colors.textMuted)
                                Text(
                                    text = permanentDeviceSnowId.ifBlank { mySnowId.ifBlank { myDeviceId } },
                                    style = SnowTypography.monospaceSmall.copy(fontWeight = FontWeight.Bold),
                                    color = colors.textPrimary
                                )
                            }
                            SnowTonalButton(
                                text = "Copy",
                                icon = Icons.Default.ContentCopy,
                                onClick = {
                                    clipboardManager.setText(AnnotatedString(permanentDeviceSnowId.ifBlank { mySnowId.ifBlank { myDeviceId } }))
                                }
                            )
                        }

                        if (permanentDeviceMcpUrl.isNotBlank()) {
                            Divider(color = colors.borderSubtle, modifier = Modifier.padding(vertical = 12.dp))
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Column(modifier = Modifier.weight(1f)) {
                                    Text(text = "Permanent Android MCP URL", style = SnowTypography.labelSmall, color = colors.textMuted)
                                    Text(
                                        text = permanentDeviceMcpUrl,
                                        style = SnowTypography.monospaceSmall,
                                        color = colors.accentCyan
                                    )
                                }
                                SnowTonalButton(
                                    text = "Copy",
                                    icon = Icons.Default.ContentCopy,
                                    onClick = { clipboardManager.setText(AnnotatedString(permanentDeviceMcpUrl)) }
                                )
                            }
                        }

                        if (!identityError.isNullOrBlank()) {
                            Spacer(modifier = Modifier.height(8.dp))
                            Text(
                                text = identityError,
                                style = SnowTypography.bodySmall,
                                color = Color(0xFFEF4444)
                            )
                        }

                        Divider(color = colors.borderSubtle, modifier = Modifier.padding(vertical = 12.dp))
                        SettingsSwitchRow(
                            title = "Standalone Android MCP Endpoint",
                            subtitle = when {
                                !androidRemoteMcpEnabled -> "Disabled by owner — remote AI clients cannot connect"
                                androidMcpConnected -> "Connected directly to Render Hub (/u/$permanentDeviceSnowId/mcp)"
                                !androidMcpError.isNullOrBlank() -> "Reconnecting: $androidMcpError"
                                else -> "Enabled by default — connecting standalone without Windows PC"
                            },
                            checked = androidRemoteMcpEnabled,
                            onCheckedChange = onToggleAndroidRemoteMcp
                        )

                        if (authorizedOAuthClients.isNotEmpty()) {
                            Spacer(modifier = Modifier.height(10.dp))
                            Text(
                                text = "Authorized AI Clients (${authorizedOAuthClients.size})",
                                style = SnowTypography.labelSmall,
                                color = colors.textMuted
                            )
                            Spacer(modifier = Modifier.height(6.dp))
                            authorizedOAuthClients.forEach { oauthClient ->
                                Row(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .padding(vertical = 4.dp),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Column(modifier = Modifier.weight(1f)) {
                                        Text(
                                            text = oauthClient.clientName,
                                            style = SnowTypography.bodySmall.copy(fontWeight = FontWeight.SemiBold),
                                            color = colors.textPrimary
                                        )
                                        Text(
                                            text = "${oauthClient.scopes.joinToString(" ")} • ${oauthClient.clientId}",
                                            style = SnowTypography.monospaceSmall,
                                            color = colors.textMuted
                                        )
                                    }
                                    SnowOutlinedButton(
                                        text = "Revoke",
                                        onClick = { onRevokeOAuthClient(oauthClient.clientId) }
                                    )
                                }
                            }
                        }

                        Divider(color = colors.borderSubtle, modifier = Modifier.padding(vertical = 12.dp))
                        Text(
                            text = "Cryptographic Identity Recovery",
                            style = SnowTypography.labelSmall,
                            color = colors.textMuted
                        )
                        Spacer(modifier = Modifier.height(6.dp))
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            SnowTonalButton(
                                text = "Export Key",
                                onClick = { showRecoveryExportWarning = true },
                                modifier = Modifier.weight(1f)
                            )
                            SnowOutlinedButton(
                                text = "Encrypted Backup",
                                onClick = { showEncryptedBackupDialog = true },
                                modifier = Modifier.weight(1f)
                            )
                        }
                        Spacer(modifier = Modifier.height(6.dp))
                        SnowOutlinedButton(
                            text = "Restore From Recovery Key / Backup",
                            icon = Icons.Default.Security,
                            onClick = { showRestoreDialog = true },
                            modifier = Modifier.fillMaxWidth()
                        )
                        if (!recoveryFeedback.isNullOrBlank()) {
                            Spacer(modifier = Modifier.height(6.dp))
                            Text(
                                text = recoveryFeedback.orEmpty(),
                                style = SnowTypography.bodySmall,
                                color = colors.accentCyan
                            )
                        }

                        Divider(color = colors.borderSubtle, modifier = Modifier.padding(vertical = 12.dp))

                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Column(modifier = Modifier.weight(1f)) {
                                Text(text = "My Network ID", style = SnowTypography.labelSmall, color = colors.textMuted)
                                Text(
                                    text = myNetworkId.ifBlank { "Not linked to a PC host yet" },
                                    style = SnowTypography.monospaceSmall.copy(fontWeight = FontWeight.Bold),
                                    color = if (myNetworkId.isNotBlank()) colors.accentCyan else colors.textSecondary
                                )
                            }
                            if (myNetworkId.isNotBlank()) {
                                SnowTonalButton(
                                    text = "Copy",
                                    icon = Icons.Default.ContentCopy,
                                    onClick = {
                                        clipboardManager.setText(AnnotatedString(myNetworkId))
                                    }
                                )
                            }
                        }

                        Divider(color = colors.borderSubtle, modifier = Modifier.padding(vertical = 12.dp))

                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Column(modifier = Modifier.weight(1f)) {
                                Text(text = "Remote AI Link (MCP URL)", style = SnowTypography.labelSmall, color = colors.textMuted)
                                Text(
                                    text = remoteAiLinkUrl ?: remoteAiLinkStatus,
                                    style = SnowTypography.monospaceSmall,
                                    color = if (!remoteAiLinkUrl.isNullOrBlank()) colors.textPrimary else colors.textSecondary
                                )
                            }
                            if (!remoteAiLinkUrl.isNullOrBlank()) {
                                SnowTonalButton(
                                    text = "Copy",
                                    icon = Icons.Default.ContentCopy,
                                    onClick = {
                                        clipboardManager.setText(AnnotatedString(remoteAiLinkUrl))
                                    }
                                )
                            }
                        }

                        Divider(color = colors.borderSubtle, modifier = Modifier.padding(vertical = 12.dp))

                        // Default Hub / Remote Relay Endpoint Configuration
                        Text(text = "Default Hub / Relay Endpoint", style = SnowTypography.labelSmall, color = colors.textMuted)
                        Spacer(modifier = Modifier.height(6.dp))
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            OutlinedTextField(
                                value = relayInput,
                                onValueChange = { relayInput = it },
                                placeholder = { Text("https://snow-relay.onrender.com", style = SnowTypography.monospaceSmall) },
                                modifier = Modifier.weight(1f),
                                singleLine = true,
                                shape = RoundedCornerShape(10.dp)
                            )
                            Spacer(modifier = Modifier.width(8.dp))
                            SnowTonalButton(
                                text = "Save",
                                onClick = {
                                    val norm = org.snow.ui.SnowUiRepository.normalizeRelayUrl(relayInput)
                                    relayInput = norm
                                    onUpdateRelayEndpoint(norm)
                                }
                            )
                        }

                        Divider(color = colors.borderSubtle, modifier = Modifier.padding(vertical = 12.dp))

                        // Manual Direct Connect by IP:Port
                        Text(text = "Manual Direct Connect", style = SnowTypography.labelSmall, color = colors.textMuted)
                        Spacer(modifier = Modifier.height(6.dp))
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            OutlinedTextField(
                                value = manualConnectInput,
                                onValueChange = { manualConnectInput = it },
                                placeholder = { Text("192.168.1.100:8765", style = SnowTypography.monospaceSmall) },
                                modifier = Modifier.weight(1f),
                                singleLine = true,
                                shape = RoundedCornerShape(10.dp)
                            )
                            Spacer(modifier = Modifier.width(8.dp))
                            SnowTonalButton(
                                text = "Connect",
                                onClick = {
                                    if (manualConnectInput.isNotBlank()) {
                                        onConnectManualIp(manualConnectInput.trim())
                                    }
                                }
                            )
                        }

                        SnowOutlinedButton(
                            text = "Reset Trust & Unpair All",
                            icon = Icons.Default.LockReset,
                            onClick = { showResetConfirm = true },
                            modifier = Modifier.fillMaxWidth()
                        )

                        Divider(color = colors.borderSubtle, modifier = Modifier.padding(vertical = 12.dp))

                        Text(
                            text = "OAuth Approvals",
                            style = SnowTypography.labelSmall,
                            color = colors.textMuted
                        )
                        Spacer(modifier = Modifier.height(4.dp))
                        Text(
                            text = "Review and approve AI OAuth authorization requests directly using the Pending Approvals bell in the top bar. Android never requires or receives the Windows local IPC secret.",
                            style = SnowTypography.bodySmall,
                            color = colors.textSecondary
                        )
                    }
                }
            }
        }

        item {
            Spacer(modifier = Modifier.height(96.dp))
        }
    }

    // Android 14–17 / ColorOS 17 Restricted Settings & Background Execution Guide Dialog
    if (showNotificationGuide) {
        AlertDialog(
            onDismissRequest = { showNotificationGuide = false },
            title = {
                Text(
                    text = "Android / ColorOS Setup Guide",
                    style = SnowTypography.titleMedium,
                    color = colors.textPrimary
                )
            },
            text = {
                Column {
                    Text(
                        text = "Sideloaded apps on Android 14-17 and ColorOS 17 require explicit user approval in Android Settings before restricted features can run:",
                        style = SnowTypography.bodySmall,
                        color = colors.textSecondary
                    )
                    Spacer(modifier = Modifier.height(10.dp))
                    Text(text = "1. Restricted Settings: Open App Info -> Menu (3 dots) -> Allow restricted settings.", style = SnowTypography.bodySmall, color = colors.textPrimary)
                    Text(text = "2. Notifications: Grant Notification permission and enable SNOW in Notification Listener settings.", style = SnowTypography.bodySmall, color = colors.textPrimary)
                    Text(text = "3. Battery Optimization: Set Battery usage to Unrestricted / Allow background activity.", style = SnowTypography.bodySmall, color = colors.textPrimary)
                    Text(text = "4. Auto-Launch (ColorOS): Enable Allow auto-launch under App Info -> Battery usage.", style = SnowTypography.bodySmall, color = colors.textPrimary)
                }
            },
            confirmButton = {
                SnowTonalButton(
                    text = "Open App Info",
                    onClick = {
                        val intent = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
                            data = Uri.parse("package:${context.packageName}")
                        }
                        context.startActivity(intent)
                        showNotificationGuide = false
                    }
                )
            },
            dismissButton = {
                SnowOutlinedButton(
                    text = "Notification Settings",
                    onClick = {
                        context.startActivity(createNotificationListenerSettingsIntent())
                        showNotificationGuide = false
                    }
                )
            },
            containerColor = if (colors.isDark) Color(0xFF1E1E1E) else Color.White
        )
    }

    // Reset Trust Confirmation Dialog
    if (showResetConfirm) {
        AlertDialog(
            onDismissRequest = { showResetConfirm = false },
            title = {
                Text(text = "Reset All Trust & Certificates?", style = SnowTypography.titleMedium, color = colors.textPrimary)
            },
            text = {
                Text(
                    text = "This will clear all pinned TLS certificates, authentication tokens, and paired device records. You will need to pair all devices again.",
                    style = SnowTypography.bodySmall,
                    color = colors.textSecondary
                )
            },
            confirmButton = {
                SnowTonalButton(
                    text = "Confirm Reset",
                    onClick = {
                        onResetTrust()
                        showResetConfirm = false
                    }
                )
            },
            dismissButton = {
                SnowOutlinedButton(
                    text = "Cancel",
                    onClick = { showResetConfirm = false }
                )
            },
            containerColor = if (colors.isDark) Color(0xFF1E1E1E) else Color.White
        )
    }

    if (showRecoveryExportWarning) {
        AlertDialog(
            onDismissRequest = {
                showRecoveryExportWarning = false
                revealedRecoveryKey = null
            },
            title = {
                Text(text = "Export Device Recovery Key?", style = SnowTypography.titleMedium, color = colors.textPrimary)
            },
            text = {
                Column {
                    Text(
                        text = "WARNING: Anyone holding your SNW-REC-V1 recovery key can impersonate this device on SNOW. Store it offline and never share it.",
                        style = SnowTypography.bodySmall,
                        color = colors.textSecondary
                    )
                    if (!revealedRecoveryKey.isNullOrBlank()) {
                        Spacer(modifier = Modifier.height(10.dp))
                        Text(
                            text = revealedRecoveryKey.orEmpty(),
                            style = SnowTypography.monospaceSmall.copy(fontWeight = FontWeight.Bold),
                            color = colors.accentCyan
                        )
                    }
                }
            },
            confirmButton = {
                if (revealedRecoveryKey.isNullOrBlank()) {
                    SnowTonalButton(
                        text = "Reveal Recovery Key",
                        onClick = {
                            val (ok, res) = onExportRecoveryKey(true)
                            if (ok) revealedRecoveryKey = res else recoveryFeedback = res
                        }
                    )
                } else {
                    SnowTonalButton(
                        text = "Copy Key",
                        onClick = {
                            clipboardManager.setText(AnnotatedString(revealedRecoveryKey.orEmpty()))
                        }
                    )
                }
            },
            dismissButton = {
                SnowOutlinedButton(
                    text = "Close",
                    onClick = {
                        showRecoveryExportWarning = false
                        revealedRecoveryKey = null
                    }
                )
            },
            containerColor = if (colors.isDark) Color(0xFF1E1E1E) else Color.White
        )
    }

    if (showEncryptedBackupDialog) {
        AlertDialog(
            onDismissRequest = {
                showEncryptedBackupDialog = false
                backupPassphrase = ""
            },
            title = { Text("Save AES-GCM Encrypted Backup", style = SnowTypography.titleMedium, color = colors.textPrimary) },
            text = {
                Column {
                    Text(
                        text = "Choose a strong passphrase (minimum 10 characters) to encrypt your device identity via PBKDF2-SHA256 + AES-256-GCM before saving via SAF.",
                        style = SnowTypography.bodySmall,
                        color = colors.textSecondary
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    OutlinedTextField(
                        value = backupPassphrase,
                        onValueChange = { backupPassphrase = it },
                        placeholder = { Text("Passphrase (min 10 chars)") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth()
                    )
                }
            },
            confirmButton = {
                SnowTonalButton(
                    text = "Choose Location (SAF)",
                    onClick = {
                        val snowTag = permanentDeviceSnowId.ifBlank { "snow-device" }
                        showEncryptedBackupDialog = false
                        encryptedBackupSafLauncher.launch("$snowTag-backup.snowkey.json")
                    }
                )
            },
            dismissButton = {
                SnowOutlinedButton(
                    text = "Cancel",
                    onClick = {
                        showEncryptedBackupDialog = false
                        backupPassphrase = ""
                    }
                )
            },
            containerColor = if (colors.isDark) Color(0xFF1E1E1E) else Color.White
        )
    }

    if (showRestoreDialog) {
        AlertDialog(
            onDismissRequest = {
                showRestoreDialog = false
                restoreInput = ""
                restorePassphrase = ""
            },
            title = { Text("Restore Device Identity", style = SnowTypography.titleMedium, color = colors.textPrimary) },
            text = {
                Column {
                    Text(
                        text = "Restoring recovers ONLY your cryptographic identity and permanent URL. All existing peer pairing credentials, TLS pins, and active OAuth sessions will be wiped.",
                        style = SnowTypography.bodySmall,
                        color = colors.textSecondary
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    OutlinedTextField(
                        value = restoreInput,
                        onValueChange = { restoreInput = it },
                        placeholder = { Text("SNW-REC-V1-... or encrypted JSON") },
                        modifier = Modifier.fillMaxWidth()
                    )
                    Spacer(modifier = Modifier.height(6.dp))
                    OutlinedTextField(
                        value = restorePassphrase,
                        onValueChange = { restorePassphrase = it },
                        placeholder = { Text("Passphrase (if encrypted backup)") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth()
                    )
                }
            },
            confirmButton = {
                SnowTonalButton(
                    text = "Restore & Reset Trust",
                    onClick = {
                        val (_, msg) = onRestoreDeviceIdentity(restoreInput, restorePassphrase.takeIf { it.isNotEmpty() })
                        recoveryFeedback = msg
                        restoreInput = ""
                        restorePassphrase = ""
                        showRestoreDialog = false
                    }
                )
            },
            dismissButton = {
                SnowOutlinedButton(
                    text = "Cancel",
                    onClick = {
                        showRestoreDialog = false
                        restoreInput = ""
                        restorePassphrase = ""
                    }
                )
            },
            containerColor = if (colors.isDark) Color(0xFF1E1E1E) else Color.White
        )
    }
}

fun createNotificationListenerSettingsIntent(): Intent =
    Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS)

fun createAppNotificationSettingsIntent(packageName: String): Intent =
    Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS).apply {
        putExtra(Settings.EXTRA_APP_PACKAGE, packageName)
    }

fun createBatteryOptimizationSettingsIntent(): Intent =
    Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS)

data class SettingsPermissionSnapshot(
    val postNotificationsGranted: Boolean,
    val notificationListenerGranted: Boolean,
    val safFolderConfigured: Boolean,
    val safFolderName: String,
    val isBatteryUnrestricted: Boolean,
    val isForegroundServiceRunning: Boolean
) {
    fun backgroundBadgeText(): String = when {
        isBatteryUnrestricted && isForegroundServiceRunning -> "UNRESTRICTED"
        isBatteryUnrestricted || isForegroundServiceRunning -> "PARTIAL"
        else -> "OPTIMIZED"
    }

    fun isBackgroundFullyHealthy(): Boolean =
        isBatteryUnrestricted && postNotificationsGranted && isForegroundServiceRunning

    fun backgroundSummaryText(): String {
        val bat = if (isBatteryUnrestricted) "Battery: Unrestricted" else "Battery: Optimized"
        val svc = if (isForegroundServiceRunning) "Service: Running" else "Service: Stopped"
        val notif = if (postNotificationsGranted) "Notifications: Ready" else "Notifications: Off"
        return "$bat • $svc • $notif"
    }
}

object SettingsPermissionInspector {
    fun inspect(
        context: Context,
        listenerGranted: Boolean? = null,
        postNotificationsOverride: Boolean? = null,
        safConfiguredOverride: Boolean? = null,
        safFolderNameOverride: String? = null,
        batteryUnrestrictedOverride: Boolean? = null,
        serviceRunningOverride: Boolean? = null
    ): SettingsPermissionSnapshot {
        val postGranted = postNotificationsOverride ?: try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED
            } else {
                ActionNotificationHelper.canPostNotifications(context)
            }
        } catch (_: Throwable) {
            false
        }

        val listenerOk = listenerGranted ?: try {
            androidx.core.app.NotificationManagerCompat
                .getEnabledListenerPackages(context)
                .contains(context.packageName)
        } catch (_: Throwable) {
            false
        }

        val safManager = try {
            SafFolderManager(context)
        } catch (_: Throwable) {
            null
        }
        val safOk = safConfiguredOverride ?: (safManager?.hasValidPersistedFolderUri() == true)
        val safName = safFolderNameOverride ?: (safManager?.getDestinationDisplayName() ?: "Default: Downloads/SNOW")

        val batUnrestricted = batteryUnrestrictedOverride ?: try {
            val pm = context.getSystemService(Context.POWER_SERVICE) as? PowerManager
            pm?.isIgnoringBatteryOptimizations(context.packageName) == true
        } catch (_: Throwable) {
            false
        }

        val svcRunning = serviceRunningOverride ?: SnowForegroundService.isServiceRunning()

        return SettingsPermissionSnapshot(
            postNotificationsGranted = postGranted,
            notificationListenerGranted = listenerOk,
            safFolderConfigured = safOk,
            safFolderName = safName,
            isBatteryUnrestricted = batUnrestricted,
            isForegroundServiceRunning = svcRunning
        )
    }
}

@Composable
private fun ThemeOptionPill(
    label: String,
    icon: ImageVector,
    selected: Boolean,
    onClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    val colors = LocalSnowColors.current
    Surface(
        modifier = modifier
            .clip(RoundedCornerShape(12.dp))
            .border(1.dp, if (selected) colors.accentBlue else colors.borderSubtle, RoundedCornerShape(12.dp))
            .clickable(onClick = onClick),
        color = if (selected) (if (colors.isDark) Color(0xFF1E3A8A) else Color(0xFFDBEAFE)) else colors.surfaceElevated
    ) {
        Row(
            modifier = Modifier.padding(vertical = 10.dp, horizontal = 12.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.Center
        ) {
            Icon(
                imageVector = icon,
                contentDescription = null,
                tint = if (selected) (if (colors.isDark) Color(0xFF93C5FD) else Color(0xFF1E3A8A)) else colors.textSecondary,
                modifier = Modifier.size(18.dp)
            )
            Spacer(modifier = Modifier.width(6.dp))
            Text(
                text = label,
                style = SnowTypography.labelMedium,
                color = if (selected) (if (colors.isDark) Color(0xFF93C5FD) else Color(0xFF1E3A8A)) else colors.textPrimary
            )
        }
    }
}

@Composable
private fun SettingsSwitchRow(
    title: String,
    subtitle: String? = null,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit
) {
    val colors = LocalSnowColors.current
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(text = title, style = SnowTypography.titleSmall, color = colors.textPrimary)
            if (!subtitle.isNullOrBlank()) {
                Text(text = subtitle, style = SnowTypography.bodySmall, color = colors.textSecondary)
            }
        }
        Switch(
            checked = checked,
            onCheckedChange = onCheckedChange,
            colors = SwitchDefaults.colors(
                checkedThumbColor = Color.White,
                checkedTrackColor = colors.accentBlue,
                uncheckedThumbColor = colors.textMuted,
                uncheckedTrackColor = colors.surfaceElevated
            ),
            modifier = Modifier.scale(0.85f)
        )
    }
}

@Composable
private fun PermissionRowItem(
    icon: ImageVector,
    title: String,
    subtitle: String? = null,
    statusText: String,
    isGranted: Boolean,
    onClick: () -> Unit
) {
    val colors = LocalSnowColors.current
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Row(modifier = Modifier.weight(1f), verticalAlignment = Alignment.CenterVertically) {
            Box(
                modifier = Modifier
                    .size(36.dp)
                    .clip(CircleShape)
                    .background(colors.surfaceElevated),
                contentAlignment = Alignment.Center
            ) {
                Icon(imageVector = icon, contentDescription = null, tint = colors.accentCyan, modifier = Modifier.size(20.dp))
            }
            Spacer(modifier = Modifier.width(12.dp))
            Column {
                Text(text = title, style = SnowTypography.titleSmall, color = colors.textPrimary)
                if (!subtitle.isNullOrBlank()) {
                    Text(text = subtitle, style = SnowTypography.bodySmall, color = colors.textSecondary)
                }
            }
        }
        Row(verticalAlignment = Alignment.CenterVertically) {
            SnowStatusBadge(
                text = statusText,
                type = if (isGranted) SnowBadgeType.CONNECTED else SnowBadgeType.STANDBY
            )
            Spacer(modifier = Modifier.width(6.dp))
            Icon(imageVector = Icons.Default.ChevronRight, contentDescription = null, tint = colors.textMuted, modifier = Modifier.size(18.dp))
        }
    }
}
