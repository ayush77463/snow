package org.snow.ui.settings

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.provider.Settings
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
import androidx.compose.material.icons.filled.BatteryAlert
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.ChevronRight
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.DarkMode
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.FolderShared
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Layers
import androidx.compose.material.icons.filled.LightMode
import androidx.compose.material.icons.filled.LockReset
import androidx.compose.material.icons.filled.Notifications
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.SettingsBrightness
import androidx.compose.material.icons.filled.Sync
import androidx.compose.material.icons.filled.SystemUpdate
import androidx.compose.material.icons.filled.ViewQuilt
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
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import org.snow.service.AutoConnectTileService
import org.snow.service.ClipSyncTileService
import org.snow.ui.components.SnowBadgeType
import org.snow.ui.components.SnowCard
import org.snow.ui.components.SnowFilterChip
import org.snow.ui.components.SnowGradientButton
import org.snow.ui.components.SnowOutlinedButton
import org.snow.ui.components.SnowSectionHeader
import org.snow.ui.components.SnowStatusBadge
import org.snow.ui.components.SnowTonalButton
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
    relayEndpoint: String,
    onUpdateRelayEndpoint: (String) -> Unit,
    onCheckAppUpdate: () -> Unit,
    updateStatusText: String,
    isUpdateAvailable: Boolean = false,
    updateVersionName: String = "",
    updateDownloadProgress: Int? = null,
    onInstallUpdate: () -> Unit = {},
    logs: List<org.snow.ui.UiLogEntry> = emptyList(),
    onConnectManualIp: (String) -> Unit = {},
    onResetTrust: () -> Unit,
    onClearLogs: () -> Unit,
    onCopyLogs: () -> Unit,
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current
    val colors = LocalSnowColors.current
    val clipboardManager = LocalClipboardManager.current
    var showNotificationGuide by remember { mutableStateOf(false) }
    var showAdvancedDiagnostics by remember { mutableStateOf(false) }
    var showResetConfirm by remember { mutableStateOf(false) }
    var relayInput by remember { mutableStateOf(relayEndpoint) }
    var manualConnectInput by remember { mutableStateOf("") }

    fun queryNotificationAccess(): Boolean =
        androidx.core.app.NotificationManagerCompat.getEnabledListenerPackages(context).contains(context.packageName)

    fun queryAllFilesAccess(): Boolean =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) Environment.isExternalStorageManager() else true

    fun queryBatteryOptIgnored(): Boolean {
        val powerManager = context.getSystemService(Context.POWER_SERVICE) as? android.os.PowerManager
        return powerManager?.isIgnoringBatteryOptimizations(context.packageName) == true
    }

    fun queryOverlayGranted(): Boolean {
        return try {
            Build.VERSION.SDK_INT < Build.VERSION_CODES.M || Settings.canDrawOverlays(context)
        } catch (_: Throwable) {
            false
        }
    }

    var isNotificationAccessGranted by remember { mutableStateOf(queryNotificationAccess()) }
    var isAllFilesGranted by remember { mutableStateOf(queryAllFilesAccess()) }
    var isBatteryOptIgnored by remember { mutableStateOf(queryBatteryOptIgnored()) }
    var isOverlayGranted by remember { mutableStateOf(queryOverlayGranted()) }

    DisposableEffect(lifecycleOwner) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_RESUME) {
                isNotificationAccessGranted = queryNotificationAccess()
                isAllFilesGranted = queryAllFilesAccess()
                isBatteryOptIgnored = queryBatteryOptIgnored()
                isOverlayGranted = queryOverlayGranted()
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
                        title = "Notification Sync & Listener",
                        statusText = if (isNotificationAccessGranted) "GRANTED" else "SETUP",
                        isGranted = isNotificationAccessGranted,
                        onClick = { showNotificationGuide = true }
                    )

                    Divider(color = colors.borderSubtle, modifier = Modifier.padding(vertical = 10.dp))

                    PermissionRowItem(
                        icon = Icons.Default.FolderShared,
                        title = "All Files Access",
                        statusText = if (isAllFilesGranted) "GRANTED" else "SETUP",
                        isGranted = isAllFilesGranted,
                        onClick = {
                            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                                try {
                                    val intent = Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION).apply {
                                        data = Uri.parse("package:${context.packageName}")
                                    }
                                    context.startActivity(intent)
                                } catch (_: Exception) {
                                    context.startActivity(Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION))
                                }
                            }
                        }
                    )

                    Divider(color = colors.borderSubtle, modifier = Modifier.padding(vertical = 10.dp))

                    PermissionRowItem(
                        icon = Icons.Default.BatteryAlert,
                        title = "Battery Optimization Exemption",
                        statusText = if (isBatteryOptIgnored) "GRANTED" else "ALLOW",
                        isGranted = isBatteryOptIgnored,
                        onClick = {
                            try {
                                val intent = Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS).apply {
                                    data = Uri.parse("package:${context.packageName}")
                                }
                                context.startActivity(intent)
                            } catch (_: Exception) {
                                try {
                                    context.startActivity(Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS))
                                } catch (_: Exception) { }
                            }
                        }
                    )

                    Divider(color = colors.borderSubtle, modifier = Modifier.padding(vertical = 10.dp))

                    PermissionRowItem(
                        icon = Icons.Default.Layers,
                        title = "Background App Launch",
                        statusText = if (isOverlayGranted) "GRANTED" else "ALLOW",
                        isGranted = isOverlayGranted,
                        onClick = {
                            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                                try {
                                    val intent = Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION).apply {
                                        data = Uri.parse("package:${context.packageName}")
                                    }
                                    context.startActivity(intent)
                                } catch (_: Exception) {
                                    try {
                                        context.startActivity(Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION))
                                    } catch (_: Exception) { }
                                }
                            }
                        }
                    )

                    Divider(color = colors.borderSubtle, modifier = Modifier.padding(vertical = 10.dp))

                    fun requestQuickSettingsTile(serviceClass: Class<*>, label: String, iconRes: Int) {
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                            try {
                                val statusBarManager = context.getSystemService(android.app.StatusBarManager::class.java)
                                statusBarManager?.requestAddTileService(
                                    android.content.ComponentName(context, serviceClass),
                                    label,
                                    android.graphics.drawable.Icon.createWithResource(context, iconRes),
                                    context.mainExecutor
                                ) { _ -> }
                            } catch (_: Exception) {
                                android.widget.Toast.makeText(
                                    context,
                                    "Open Quick Settings edit mode to add the $label tile.",
                                    android.widget.Toast.LENGTH_LONG
                                ).show()
                            }
                        } else {
                            android.widget.Toast.makeText(
                                context,
                                "Swipe down Quick Settings and tap edit pencil to add $label",
                                android.widget.Toast.LENGTH_LONG
                            ).show()
                        }
                    }

                    PermissionRowItem(
                        icon = Icons.Default.ViewQuilt,
                        title = "Quick Settings: SNOW Connect",
                        statusText = "ADD",
                        isGranted = false,
                        onClick = {
                            requestQuickSettingsTile(
                                AutoConnectTileService::class.java,
                                "SNOW Connect",
                                org.snow.R.drawable.ic_qs_snow
                            )
                        }
                    )

                    Divider(color = colors.borderSubtle, modifier = Modifier.padding(vertical = 10.dp))

                    PermissionRowItem(
                        icon = Icons.Default.ContentCopy,
                        title = "Quick Settings: SNOW Clip",
                        statusText = "ADD",
                        isGranted = false,
                        onClick = {
                            requestQuickSettingsTile(
                                ClipSyncTileService::class.java,
                                "SNOW Clip",
                                org.snow.R.drawable.ic_qs_clip
                            )
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
                                text = updateStatusText.ifBlank { "v5.1.0 • Up to date" },
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
                                text = "Check",
                                icon = Icons.Default.SystemUpdate,
                                onClick = onCheckAppUpdate
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
                                    text = mySnowId.ifBlank { myDeviceId },
                                    style = SnowTypography.monospaceSmall.copy(fontWeight = FontWeight.Bold),
                                    color = colors.textPrimary
                                )
                            }
                            SnowTonalButton(
                                text = "Copy",
                                icon = Icons.Default.ContentCopy,
                                onClick = {
                                    clipboardManager.setText(AnnotatedString(mySnowId.ifBlank { myDeviceId }))
                                }
                            )
                        }

                        Divider(color = colors.borderSubtle, modifier = Modifier.padding(vertical = 12.dp))

                        // Remote Relay Endpoint Configuration
                        Text(text = "Remote Relay Endpoint", style = SnowTypography.labelSmall, color = colors.textMuted)
                        Spacer(modifier = Modifier.height(6.dp))
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            OutlinedTextField(
                                value = relayInput,
                                onValueChange = { relayInput = it },
                                placeholder = { Text("wss://relay.example.com", style = SnowTypography.monospaceSmall) },
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
                    }
                }
            }
        }

        item {
            Spacer(modifier = Modifier.height(96.dp))
        }
    }

    // Android 14+ Restricted Settings Guide Dialog
    if (showNotificationGuide) {
        AlertDialog(
            onDismissRequest = { showNotificationGuide = false },
            title = {
                Text(
                    text = "Notification Access Setup",
                    style = SnowTypography.titleMedium,
                    color = colors.textPrimary
                )
            },
            text = {
                Column {
                    Text(
                        text = "On Android 13 and 14+, side-loaded apps require restricted settings authorization before notification access can be granted:",
                        style = SnowTypography.bodySmall,
                        color = colors.textSecondary
                    )
                    Spacer(modifier = Modifier.height(10.dp))
                    Text(text = "1. Open App Info for SNOW in Android Settings", style = SnowTypography.bodySmall, color = colors.textPrimary)
                    Text(text = "2. Tap the 3 dots (⋮) in the top-right corner", style = SnowTypography.bodySmall, color = colors.textPrimary)
                    Text(text = "3. Select 'Allow restricted settings' and confirm", style = SnowTypography.bodySmall, color = colors.textPrimary)
                    Text(text = "4. Return here and tap 'Open Notification Settings'", style = SnowTypography.bodySmall, color = colors.textPrimary)
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
                        val intent = Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS)
                        context.startActivity(intent)
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
