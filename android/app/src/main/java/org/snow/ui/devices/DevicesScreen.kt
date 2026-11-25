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
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import org.snow.network.DiscoveredPeer
import org.snow.network.PeerHostState
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
 * - Nearby Peer Discovery
 * - Phone-to-Phone Host Mode with live PIN
 * - Cross-Network Sharing with 9-digit codes and active grants
 */
@Composable
fun DevicesScreen(
    savedDevices: List<SavedDevice>,
    discoveredPeers: List<DiscoveredPeer>,
    peerHostState: PeerHostState,
    activeHost: String,
    federationGrants: List<Map<String, Any?>>,
    onConnectDevice: (SavedDevice) -> Unit,
    onDisconnectDevice: () -> Unit,
    onUnpairDevice: (SavedDevice) -> Unit,
    onUpdateTrustTier: (deviceId: String, tier: String) -> Unit,
    onPairDiscoveredPeer: (DiscoveredPeer) -> Unit,
    onTogglePeerHost: (Boolean) -> Unit,
    onShowPeerHostQr: () -> Unit = {},
    onGenerateFederationCode: () -> Unit,
    onAcceptFederationCode: (String) -> Unit,
    onRevokeFederationGrant: (String) -> Unit,
    onFederationKillSwitch: () -> Unit = {},
    onOpenConnectSheet: () -> Unit = {},
    generatedFederationInvite: String? = null,
    onDismissFederationInvite: () -> Unit = {},
    isRefreshing: Boolean = false,
    onRefresh: () -> Unit = {},
    modifier: Modifier = Modifier
) {
    val colors = LocalSnowColors.current
    val clipboardManager = androidx.compose.ui.platform.LocalClipboardManager.current
    var selectedFilter by remember { mutableStateOf(DeviceFilter.ALL) }
    var showJoinDialog by remember { mutableStateOf(false) }
    var showKillSwitchConfirm by remember { mutableStateOf(false) }
    var joinCodeInput by remember { mutableStateOf("") }

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
            items(filteredDevices, key = { it.deviceId.ifBlank { it.host } }) { dev ->
                val isActive = dev.host == activeHost || (activeHost == "127.0.0.1" && dev.host == "127.0.0.1")
                DeviceListItem(
                    device = dev,
                    isActive = isActive,
                    onConnect = { onConnectDevice(dev) },
                    onDisconnect = onDisconnectDevice,
                    onUnpair = { onUnpairDevice(dev) },
                    onUpdateTier = { tier -> onUpdateTrustTier(dev.deviceId, tier) }
                )
            }
        }

        // Phone-to-Phone Host Mode Card
        item {
            SnowSectionHeader(title = "Phone-to-Phone Host Mode")
            PeerHostModeCard(
                peerHostState = peerHostState,
                onToggle = onTogglePeerHost,
                onShowQr = onShowPeerHostQr
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

        // Cross-Network Sharing Section
        item {
            SnowSectionHeader(title = "Cross-Network Sharing")
            CrossNetworkSharingCard(
                grants = federationGrants,
                onGenerateCode = onGenerateFederationCode,
                onJoinCode = { showJoinDialog = true },
                onRevokeGrant = onRevokeFederationGrant,
                onKillSwitch = { showKillSwitchConfirm = true }
            )
        }

        item {
            Spacer(modifier = Modifier.height(96.dp))
        }
    }
    }

    // Join Network Dialog
    if (showJoinDialog) {
        AlertDialog(
            onDismissRequest = { showJoinDialog = false },
            title = {
                Text(
                    text = "Join Cross-Network Session",
                    style = SnowTypography.titleMedium,
                    color = colors.textPrimary
                )
            },
            text = {
                Column {
                    Text(
                        text = "Enter the 9-digit session code provided by the remote host.",
                        style = SnowTypography.bodySmall,
                        color = colors.textSecondary
                    )
                    Spacer(modifier = Modifier.height(12.dp))
                    OutlinedTextField(
                        value = joinCodeInput,
                        onValueChange = { joinCodeInput = it },
                        modifier = Modifier.fillMaxWidth(),
                        placeholder = { Text("e.g. 000 000 000") },
                        singleLine = true,
                        shape = RoundedCornerShape(12.dp)
                    )
                }
            },
            confirmButton = {
                SnowTonalButton(
                    text = "Connect",
                    onClick = {
                        if (joinCodeInput.isNotBlank()) {
                            onAcceptFederationCode(joinCodeInput.trim())
                            showJoinDialog = false
                            joinCodeInput = ""
                        }
                    }
                )
            },
            dismissButton = {
                SnowOutlinedButton(
                    text = "Cancel",
                    onClick = { showJoinDialog = false }
                )
            },
            containerColor = if (colors.isDark) Color(0xFF1E1E1E) else Color.White
        )
    }

    // Generated Federation Invite Code Dialog
    if (!generatedFederationInvite.isNullOrBlank()) {
        AlertDialog(
            onDismissRequest = onDismissFederationInvite,
            title = {
                Text(
                    text = "Session Invite Code",
                    style = SnowTypography.titleMedium,
                    color = colors.textPrimary
                )
            },
            text = {
                Column {
                    Text(
                        text = "Share this 9-digit code with your peer to establish an end-to-end encrypted federation link:",
                        style = SnowTypography.bodySmall,
                        color = colors.textSecondary
                    )
                    Spacer(modifier = Modifier.height(14.dp))
                    Surface(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clip(RoundedCornerShape(12.dp)),
                        color = colors.surfaceElevated
                    ) {
                        Box(
                            modifier = Modifier.padding(16.dp),
                            contentAlignment = Alignment.Center
                        ) {
                            Text(
                                text = generatedFederationInvite,
                                style = SnowTypography.titleLarge.copy(
                                    fontWeight = FontWeight.Bold,
                                    letterSpacing = 2.sp
                                ),
                                color = colors.accentCyan
                            )
                        }
                    }
                }
            },
            confirmButton = {
                SnowGradientButton(
                    text = "Copy Code",
                    icon = Icons.Default.Share,
                    onClick = {
                        clipboardManager.setText(AnnotatedString(generatedFederationInvite))
                        onDismissFederationInvite()
                    }
                )
            },
            dismissButton = {
                SnowOutlinedButton(
                    text = "Close",
                    onClick = onDismissFederationInvite
                )
            },
            containerColor = if (colors.isDark) Color(0xFF1E1E1E) else Color.White
        )
    }

    // Emergency Kill Switch Confirmation Dialog
    if (showKillSwitchConfirm) {
        AlertDialog(
            onDismissRequest = { showKillSwitchConfirm = false },
            title = {
                Text(
                    text = "Activate Emergency Kill Switch?",
                    style = SnowTypography.titleMedium,
                    color = Color(0xFFEF4444)
                )
            },
            text = {
                Text(
                    text = "This will immediately revoke all active cross-network federation grants and disconnect all active peer sessions.",
                    style = SnowTypography.bodySmall,
                    color = colors.textSecondary
                )
            },
            confirmButton = {
                SnowTonalButton(
                    text = "Activate Kill Switch",
                    onClick = {
                        onFederationKillSwitch()
                        showKillSwitchConfirm = false
                    }
                )
            },
            dismissButton = {
                SnowOutlinedButton(
                    text = "Cancel",
                    onClick = { showKillSwitchConfirm = false }
                )
            },
            containerColor = if (colors.isDark) Color(0xFF1E1E1E) else Color.White
        )
    }
}

@Composable
private fun DeviceListItem(
    device: SavedDevice,
    isActive: Boolean,
    onConnect: () -> Unit,
    onDisconnect: () -> Unit,
    onUnpair: () -> Unit,
    onUpdateTier: (String) -> Unit
) {
    val colors = LocalSnowColors.current
    val isPhone = device.isPhone
    val transportLabel = when {
        isPhone -> "Direct Peer"
        device.host == "127.0.0.1" || device.host == "localhost" -> "USB"
        device.host.contains("relay") || device.host.contains("tunnel") || device.connectionMode == "remote_only" -> "Remote"
        else -> "Wi-Fi"
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
                        Text(
                            text = "${if (isPhone) "Phone" else "PC"} • $transportLabel",
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

            // Canonical Access Profile Pills & Actions
            val currentProfile = SnowUiRepository.normalizeAccessProfile(device.trustTier)
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
                    label = "Clip Only",
                    selected = currentProfile == "clipboard_only",
                    onClick = { onUpdateTier("clipboard_only") }
                )
            }

            Spacer(modifier = Modifier.height(10.dp))

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp, Alignment.End),
                verticalAlignment = Alignment.CenterVertically
            ) {
                if (isActive) {
                    SnowOutlinedButton(text = "Disconnect", onClick = onDisconnect)
                } else {
                    SnowTonalButton(text = "Connect", onClick = onConnect)
                }
                Surface(
                    modifier = Modifier
                        .size(36.dp)
                        .clip(CircleShape)
                        .clickable(onClick = onUnpair),
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
    onClick: () -> Unit
) {
    val colors = LocalSnowColors.current
    Surface(
        modifier = Modifier
            .clip(RoundedCornerShape(9999.dp))
            .border(1.dp, if (selected) colors.accentCyan else colors.borderSubtle, RoundedCornerShape(9999.dp))
            .clickable(onClick = onClick),
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
private fun PeerHostModeCard(
    peerHostState: PeerHostState,
    onToggle: (Boolean) -> Unit,
    onShowQr: () -> Unit = {}
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
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Box(
                        modifier = Modifier
                            .size(38.dp)
                            .clip(CircleShape)
                            .background(colors.accentEmerald.copy(alpha = 0.15f)),
                        contentAlignment = Alignment.Center
                    ) {
                        Icon(
                            imageVector = Icons.Default.PhoneAndroid,
                            contentDescription = null,
                            tint = colors.accentEmerald,
                            modifier = Modifier.size(20.dp)
                        )
                    }
                    Spacer(modifier = Modifier.width(12.dp))
                    Column {
                        Text(
                            text = "Phone Host Server",
                            style = SnowTypography.titleSmall,
                            color = colors.textPrimary
                        )
                        Text(
                            text = if (peerHostState.isActive) "Host ready • ${peerHostState.peerCount} linked" else "Accepts direct peer links",
                            style = SnowTypography.bodySmall,
                            color = colors.textSecondary
                        )
                    }
                }

                Switch(
                    checked = peerHostState.isActive,
                    onCheckedChange = onToggle,
                    colors = SwitchDefaults.colors(
                        checkedThumbColor = Color.White,
                        checkedTrackColor = colors.accentEmerald,
                        uncheckedThumbColor = colors.textMuted,
                        uncheckedTrackColor = colors.surfaceElevated
                    ),
                    modifier = Modifier.scale(0.85f)
                )
            }

            if (peerHostState.isActive && !peerHostState.pairingPin.isNullOrBlank()) {
                Spacer(modifier = Modifier.height(12.dp))
                Divider(color = colors.borderSubtle)
                Spacer(modifier = Modifier.height(10.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = "PAIRING PIN: ${peerHostState.pairingPin}",
                        style = SnowTypography.monospaceSmall.copy(fontWeight = FontWeight.Bold),
                        color = colors.accentCyan
                    )
                    SnowTonalButton(
                        text = "Show QR",
                        icon = Icons.Default.QrCode,
                        onClick = onShowQr
                    )
                }
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

@Composable
private fun CrossNetworkSharingCard(
    grants: List<Map<String, Any?>>,
    onGenerateCode: () -> Unit,
    onJoinCode: () -> Unit,
    onRevokeGrant: (String) -> Unit,
    onKillSwitch: () -> Unit = {}
) {
    val colors = LocalSnowColors.current

    SnowCard(
        modifier = Modifier.fillMaxWidth(),
        cornerRadius = 20.dp
    ) {
        Column {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                SnowGradientButton(
                    text = "Share Code",
                    icon = Icons.Default.Share,
                    onClick = onGenerateCode,
                    modifier = Modifier.weight(1f)
                )
                SnowTonalButton(
                    text = "Join Session",
                    icon = Icons.Default.Add,
                    onClick = onJoinCode,
                    modifier = Modifier.weight(1f)
                )
            }

            Spacer(modifier = Modifier.height(10.dp))

            SnowOutlinedButton(
                text = "Emergency Kill Switch",
                icon = Icons.Default.Security,
                onClick = onKillSwitch,
                modifier = Modifier.fillMaxWidth()
            )

            if (grants.isNotEmpty()) {
                Spacer(modifier = Modifier.height(16.dp))
                Divider(color = colors.borderSubtle)
                Spacer(modifier = Modifier.height(10.dp))
                Text(
                    text = "ACTIVE SESSIONS (${grants.size})",
                    style = SnowTypography.labelSmall.copy(letterSpacing = 1.sp),
                    color = colors.textMuted
                )
                Spacer(modifier = Modifier.height(8.dp))
                grants.forEach { grant ->
                    val grantId = grant["grant_id"]?.toString() ?: ""
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(vertical = 4.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = "Grant: ${grantId.take(12)}...",
                            style = SnowTypography.monospaceSmall,
                            color = colors.textPrimary
                        )
                        SnowOutlinedButton(
                            text = "Revoke",
                            onClick = { onRevokeGrant(grantId) }
                        )
                    }
                }
            }
        }
    }
}
