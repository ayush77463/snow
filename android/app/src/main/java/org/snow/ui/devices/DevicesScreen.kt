package org.snow.ui.devices

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
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Computer
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.NearMe
import androidx.compose.material.icons.filled.PhoneAndroid
import androidx.compose.material.icons.filled.QrCode
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Share
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Divider
import androidx.compose.material3.Icon
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import org.snow.network.DiscoveredPeer
import org.snow.ui.SavedDevice
import org.snow.ui.SnowUiRepository
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
import org.snow.ui.theme.LocalSnowColors
import org.snow.ui.theme.SnowTypography

enum class DeviceFilter {
    ALL, PCS, PHONES
}

/**
 * Devices Management Screen handling:
 * - Filter chips (All, PCs, Phones)
 * - Linked Devices List with Trust Tier profiles
 * - Connection Control (Auto-Reconnect & Disconnect All)
 * - Nearby Peer Discovery
 * - Cross-Network Sharing with 9-digit codes and active grants
 */
@Composable
fun DevicesScreen(
    savedDevices: List<SavedDevice>,
    discoveredPeers: List<DiscoveredPeer>,
    activeHost: String,
    federationGrants: List<Map<String, Any?>>,
    onConnectDevice: (SavedDevice) -> Unit,
    onDisconnectDevice: () -> Unit,
    onUnpairDevice: (SavedDevice) -> Unit,
    onUpdateTrustTier: (deviceId: String, tier: String) -> Unit,
    onPairDiscoveredPeer: (DiscoveredPeer) -> Unit,
    onGenerateFederationCode: () -> Unit,
    onAcceptFederationCode: (String) -> Unit,
    onRevokeFederationGrant: (String) -> Unit,
    onUpdatePermissionProfile: (deviceId: String, profile: String) -> Unit = onUpdateTrustTier,
    canShareCode: Boolean = true,
    shareCodeDisabledReason: String? = null,
    onFederationKillSwitch: () -> Unit = {},
    onOpenConnectSheet: () -> Unit = {},
    generatedFederationInvite: String? = null,
    onDismissFederationInvite: () -> Unit = {},
    isConnected: Boolean = false,
    autoConnectNearby: Boolean = true,
    onToggleAutoConnect: (Boolean) -> Unit = {},
    onDisconnectAll: () -> Unit = {},
    isRefreshing: Boolean = false,
    onRefresh: () -> Unit = {},
    isConnectionBusy: Boolean = false,
    isGeneratingFederationCode: Boolean = false,
    isJoiningFederation: Boolean = false,
    isFederationActionInFlight: Boolean = false,
    myNetworkId: String? = null,
    pendingNetworkDecision: org.snow.ui.PendingNetworkDecision? = null,
    onResolveNetworkDecision: (merge: Boolean) -> Unit = {},
    transportSnapshots: Map<String, org.snow.network.DeviceTransportSnapshot> = emptyMap(),
    onSwitchDeviceTransport: (deviceId: String, mode: String) -> Unit = { _, _ -> },
    modifier: Modifier = Modifier
) {
    val colors = LocalSnowColors.current
    val haptic = LocalHapticFeedback.current
    var selectedFilter by remember { mutableStateOf(DeviceFilter.ALL) }

    val pcsCount = savedDevices.count { it.isPc }
    val phonesCount = savedDevices.count { it.isPhone }

    val filteredDevices = remember(savedDevices, selectedFilter) {
        when (selectedFilter) {
            DeviceFilter.ALL -> savedDevices
            DeviceFilter.PCS -> savedDevices.filter { it.isPc }
            DeviceFilter.PHONES -> savedDevices.filter { it.isPhone }
        }
    }

    SnowPullToRefreshBox(
        isRefreshing = isRefreshing,
        onRefresh = onRefresh,
        modifier = modifier.fillMaxSize()
    ) {
    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        item {
            Spacer(modifier = Modifier.height(8.dp))
        }

        // Network Identity & Pending Merge Conflict Banner
        item {
            SnowCard(
                modifier = Modifier.fillMaxWidth(),
                cornerRadius = 16.dp
            ) {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(
                        text = myNetworkId?.takeIf { it.isNotBlank() }?.let { "Shared Network: $it" }
                            ?: "Standalone (not in a shared network yet)",
                        style = SnowTypography.labelMedium.copy(fontWeight = FontWeight.SemiBold),
                        color = if (!myNetworkId.isNullOrBlank()) colors.accentCyan else colors.textSecondary
                    )
                    if (pendingNetworkDecision != null) {
                        Text(
                            text = "Network conflict with ${pendingNetworkDecision.peerDeviceName}: ${pendingNetworkDecision.localNetworkId} vs ${pendingNetworkDecision.remoteNetworkId}",
                            style = SnowTypography.bodySmall,
                            color = colors.textPrimary
                        )
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            SnowTonalButton(
                                text = "Merge Networks",
                                onClick = { onResolveNetworkDecision(true) },
                                modifier = Modifier.weight(1f)
                            )
                            SnowOutlinedButton(
                                text = "Keep Separate",
                                onClick = { onResolveNetworkDecision(false) },
                                modifier = Modifier.weight(1f)
                            )
                        }
                    }
                }
            }
        }

        // Filter Chips Row
        item {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                SnowFilterChip(
                    text = "All Devices",
                    selected = selectedFilter == DeviceFilter.ALL,
                    onClick = { selectedFilter = DeviceFilter.ALL },
                    count = savedDevices.size
                )
                SnowFilterChip(
                    text = "PCs",
                    selected = selectedFilter == DeviceFilter.PCS,
                    onClick = { selectedFilter = DeviceFilter.PCS },
                    count = pcsCount
                )
                SnowFilterChip(
                    text = "Phones",
                    selected = selectedFilter == DeviceFilter.PHONES,
                    onClick = { selectedFilter = DeviceFilter.PHONES },
                    count = phonesCount
                )
            }
        }

        // Linked Devices Section
        item {
            SnowSectionHeader(
                title = "Linked Devices (${filteredDevices.size})",
                trailing = {
                    Text(
                        text = "+ Connect",
                        style = SnowTypography.labelSmall.copy(fontWeight = FontWeight.SemiBold),
                        color = colors.accentCyan,
                        modifier = Modifier
                            .clip(RoundedCornerShape(6.dp))
                            .clickable(onClick = onOpenConnectSheet)
                            .padding(4.dp)
                    )
                }
            )
        }

        if (filteredDevices.isEmpty()) {
            item {
                SnowCard(
                    modifier = Modifier.fillMaxWidth(),
                    cornerRadius = 16.dp
                ) {
                    Text(
                        text = "No linked devices in this category. Tap + Connect to pair a new PC or phone.",
                        style = SnowTypography.bodySmall,
                        color = colors.textSecondary
                    )
                }
            }
        } else {
            items(filteredDevices, key = { it.deviceId.ifBlank { it.snowId ?: it.host } }) { dev ->
                val isActive = isConnected && (
                    (!activeHost.isNullOrBlank() && dev.host == activeHost) ||
                    (activeHost == "127.0.0.1" && dev.host == "127.0.0.1")
                )
                DeviceListItem(
                    device = dev,
                    isActive = isActive,
                    isBusy = isConnectionBusy,
                    transportSnapshot = transportSnapshots[dev.deviceId],
                    onConnect = { onConnectDevice(dev) },
                    onDisconnect = onDisconnectDevice,
                    onUnpair = { onUnpairDevice(dev) },
                    onUpdateTier = { profile -> onUpdatePermissionProfile(dev.deviceId, profile) },
                    onSelectTransport = { mode -> onSwitchDeviceTransport(dev.deviceId, mode) }
                )
            }
        }

        // Connection Control Card
        item {
            SnowSectionHeader(title = "Connection Control")
            ConnectionControlCard(
                isConnected = isConnected,
                autoConnectNearby = autoConnectNearby,
                onToggleAutoConnect = { checked ->
                    haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                    onToggleAutoConnect(checked)
                },
                onDisconnectAll = {
                    haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                    onDisconnectAll()
                }
            )
        }

        // Nearby Discovered Peers
        if (discoveredPeers.isNotEmpty()) {
            item {
                SnowSectionHeader(title = "Nearby Peers (${discoveredPeers.size})")
            }
            items(discoveredPeers) { peer ->
                DiscoveredPeerCard(
                    peer = peer,
                    onPair = { onPairDiscoveredPeer(peer) }
                )
            }
        }

        item {
            Spacer(modifier = Modifier.height(96.dp))
        }
    }
    }
}

@Composable
private fun DeviceListItem(
    device: SavedDevice,
    isActive: Boolean,
    isBusy: Boolean = false,
    transportSnapshot: org.snow.network.DeviceTransportSnapshot? = null,
    onConnect: () -> Unit,
    onDisconnect: () -> Unit,
    onUnpair: () -> Unit,
    onUpdateTier: (String) -> Unit,
    onSelectTransport: (String) -> Unit = {}
) {
    val colors = LocalSnowColors.current
    val isPhone = device.isPhone
    val transportLabel = transportSnapshot?.activeBadge ?: when {
        isPhone -> "Direct Peer"
        else -> when (
            org.snow.network.TransportClassifier.classifyRoute(
                transport = transportSnapshot?.activeRoute?.wireName,
                host = device.host,
                mode = device.connectionMode
            )
        ) {
            org.snow.network.TransportRoute.USB -> "USB • Zero Data"
            org.snow.network.TransportRoute.HOTSPOT -> "Hotspot • Zero Data"
            org.snow.network.TransportRoute.WIFI_LAN -> "Wi-Fi • Zero Data"
            org.snow.network.TransportRoute.REMOTE_RELAY -> "Remote • Uses Data"
        }
    }

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
                    Box(
                        modifier = Modifier
                            .size(40.dp)
                            .clip(CircleShape)
                            .background(if (isActive) colors.accentBlue.copy(alpha = 0.15f) else colors.surfaceElevated),
                        contentAlignment = Alignment.Center
                    ) {
                        Icon(
                            imageVector = if (isPhone) Icons.Default.PhoneAndroid else Icons.Default.Computer,
                            contentDescription = null,
                            tint = if (isActive) colors.accentBlue else colors.textSecondary,
                            modifier = Modifier.size(22.dp)
                        )
                    }
                    Spacer(modifier = Modifier.width(12.dp))
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = device.deviceName.ifBlank { device.host },
                            style = SnowTypography.titleSmall,
                            color = colors.textPrimary,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                        val trustLabel = if (SnowUiRepository.normalizeTrustTier(device.trustTier) == "owner") "Owner" else "Peer"
                        val relTag = if (device.relationship.equals("external_network", ignoreCase = true)) " • External" else ""
                        Text(
                            text = "${if (isPhone) "Phone" else "PC"} • $transportLabel • $trustLabel$relTag",
                            style = SnowTypography.bodySmall,
                            color = colors.textSecondary
                        )
                    }
                }

                if (isActive) {
                    SnowStatusBadge(text = "ACTIVE", type = SnowBadgeType.CONNECTED)
                } else {
                    SnowStatusBadge(text = "STANDBY", type = SnowBadgeType.STANDBY)
                }
            }

            Spacer(modifier = Modifier.height(14.dp))
            Divider(color = colors.borderSubtle)
            Spacer(modifier = Modifier.height(10.dp))

            // Canonical 5-Tier Access Profile Pills (separated from device trustTier)
            val currentProfile = SnowUiRepository.normalizeAccessProfile(device.permissionProfile)
            Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    TrustTierPill(
                        label = "Full Control",
                        selected = currentProfile == "full_control",
                        onClick = { onUpdateTier("full_control") }
                    )
                    TrustTierPill(
                        label = "Files & Clip",
                        selected = currentProfile == "files_and_clipboard",
                        onClick = { onUpdateTier("files_and_clipboard") }
                    )
                    TrustTierPill(
                        label = "Files Only",
                        selected = currentProfile == "files_only",
                        onClick = { onUpdateTier("files_only") }
                    )
                }
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    TrustTierPill(
                        label = "Clip Only",
                        selected = currentProfile == "clipboard_only",
                        onClick = { onUpdateTier("clipboard_only") }
                    )
                    TrustTierPill(
                        label = "Not Allowed",
                        selected = currentProfile == "not_allowed",
                        onClick = { onUpdateTier("not_allowed") }
                    )
                }

                // Transport Route Controls: Auto (Best) vs Verified Manual Single-Route Overrides
                val currentModeWire = transportSnapshot?.mode?.wireName ?: device.connectionMode.ifBlank { "auto" }
                val routeMap = transportSnapshot?.routes?.associateBy { it.route } ?: emptyMap()
                val routeChoices = listOf(
                    Triple("auto", "Auto", true),
                    Triple("usb", "USB", routeMap[org.snow.network.TransportRoute.USB]?.verified == true || (isActive && device.host == "127.0.0.1")),
                    Triple("hotspot", "Hotspot", routeMap[org.snow.network.TransportRoute.HOTSPOT]?.verified == true || (isActive && org.snow.network.TransportClassifier.isHotspotHostOrHint(device.host))),
                    Triple("wifi_lan", "Wi-Fi", routeMap[org.snow.network.TransportRoute.WIFI_LAN]?.verified == true || (isActive && !org.snow.network.TransportClassifier.isHotspotHostOrHint(device.host) && device.host != "127.0.0.1" && !device.host.contains("relay"))),
                    Triple("remote_relay", "Remote", routeMap[org.snow.network.TransportRoute.REMOTE_RELAY]?.verified == true || device.connectionMode == "remote_only" || device.connectionMode == "remote_relay")
                )
                Spacer(modifier = Modifier.height(4.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    routeChoices.forEach { (key, label, isVerified) ->
                        val isSwitching = transportSnapshot?.switching == true
                        TrustTierPill(
                            label = if (isSwitching && currentModeWire == key) "..." else label,
                            selected = currentModeWire.equals(key, ignoreCase = true),
                            enabled = (key == "auto" || isVerified) && !isSwitching,
                            onClick = { onSelectTransport(key) }
                        )
                    }
                }
                transportSnapshot?.lastSwitchReason?.takeIf { it.isNotBlank() }?.let { reason ->
                    Text(
                        text = reason,
                        style = SnowTypography.bodySmall.copy(fontSize = 10.sp),
                        color = colors.textMuted,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }
            }

            Spacer(modifier = Modifier.height(10.dp))

            val haptic = LocalHapticFeedback.current
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp, Alignment.End),
                verticalAlignment = Alignment.CenterVertically
            ) {
                if (isActive) {
                    SnowOutlinedButton(
                        text = "Disconnect",
                        enabled = !isBusy,
                        isLoading = isBusy,
                        onClick = {
                            haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                            onDisconnect()
                        }
                    )
                } else {
                    SnowTonalButton(
                        text = if (isBusy) "Connecting..." else "Reconnect",
                        enabled = !isBusy,
                        isLoading = isBusy,
                        onClick = {
                            haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                            onConnect()
                        }
                    )
                }
                Surface(
                    modifier = Modifier
                        .size(36.dp)
                        .clip(CircleShape)
                        .clickable {
                            haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                            onUnpair()
                        },
                    color = colors.surfaceElevated
                ) {
                    Box(contentAlignment = Alignment.Center) {
                        Icon(
                            imageVector = Icons.Default.Delete,
                            contentDescription = "Unpair",
                            tint = Color(0xFFEF4444),
                            modifier = Modifier.size(18.dp)
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun TrustTierPill(
    label: String,
    selected: Boolean,
    enabled: Boolean = true,
    onClick: () -> Unit
) {
    val colors = LocalSnowColors.current
    Surface(
        modifier = Modifier
            .alpha(if (enabled) 1f else 0.42f)
            .clip(RoundedCornerShape(9999.dp))
            .border(1.dp, if (selected) colors.accentCyan else colors.borderSubtle, RoundedCornerShape(9999.dp))
            .clickable(enabled = enabled, onClick = onClick),
        color = if (selected) (if (colors.isDark) Color(0xFF1E3A8A) else Color(0xFFEFF6FF)) else Color.Transparent
    ) {
        Text(
            text = label,
            style = SnowTypography.labelSmall.copy(fontSize = 10.sp),
            color = if (selected) (if (colors.isDark) Color(0xFF93C5FD) else Color(0xFF1D4ED8)) else colors.textMuted,
            modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp)
        )
    }
}

@Composable
private fun ConnectionControlCard(
    isConnected: Boolean,
    autoConnectNearby: Boolean,
    onToggleAutoConnect: (Boolean) -> Unit,
    onDisconnectAll: () -> Unit
) {
    val colors = LocalSnowColors.current

    SnowCard(
        modifier = Modifier.fillMaxWidth(),
        cornerRadius = 20.dp
    ) {
        Column {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = "Auto-Reconnect",
                        style = SnowTypography.titleSmall,
                        color = colors.textPrimary
                    )
                    Text(
                        text = "Reconnect automatically on USB or trusted Wi-Fi",
                        style = SnowTypography.bodySmall,
                        color = colors.textSecondary
                    )
                }

                Spacer(modifier = Modifier.width(12.dp))

                Switch(
                    checked = autoConnectNearby,
                    onCheckedChange = onToggleAutoConnect,
                    colors = SwitchDefaults.colors(
                        checkedThumbColor = Color.White,
                        checkedTrackColor = colors.accentEmerald,
                        uncheckedThumbColor = colors.textMuted,
                        uncheckedTrackColor = colors.surfaceElevated
                    ),
                    modifier = Modifier.scale(0.85f)
                )
            }

            Spacer(modifier = Modifier.height(12.dp))
            Divider(color = colors.borderSubtle)
            Spacer(modifier = Modifier.height(12.dp))

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = if (isConnected) "Active sessions linked" else "Sessions standing by",
                        style = SnowTypography.bodySmall,
                        color = colors.textSecondary
                    )
                }
                SnowOutlinedButton(
                    text = "Disconnect All",
                    icon = Icons.Default.Close,
                    onClick = onDisconnectAll
                )
            }
        }
    }
}

@Composable
private fun DiscoveredPeerCard(
    peer: DiscoveredPeer,
    onPair: () -> Unit
) {
    val colors = LocalSnowColors.current

    Surface(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(14.dp))
            .border(1.dp, colors.borderSubtle, RoundedCornerShape(14.dp)),
        color = colors.surface
    ) {
        Row(
            modifier = Modifier.padding(12.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(
                imageVector = Icons.Default.NearMe,
                contentDescription = null,
                tint = colors.accentCyan,
                modifier = Modifier.size(22.dp)
            )
            Spacer(modifier = Modifier.width(12.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = peer.deviceName.ifBlank { peer.ipAddress },
                    style = SnowTypography.bodyMedium.copy(fontWeight = FontWeight.SemiBold),
                    color = colors.textPrimary
                )
                Text(
                    text = "${peer.ipAddress}:${peer.port}",
                    style = SnowTypography.bodySmall,
                    color = colors.textSecondary
                )
            }
            SnowTonalButton(
                text = "Pair",
                onClick = onPair
            )
        }
    }
}
