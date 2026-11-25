package org.snow.ui.shell

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
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
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Computer
import androidx.compose.material.icons.filled.PhoneAndroid
import androidx.compose.material3.Divider
import androidx.compose.material3.Icon
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import org.snow.ui.PhoneTelemetry
import org.snow.ui.SavedDevice
import org.snow.ui.components.SnowBadgeType
import org.snow.ui.components.SnowSectionHeader
import org.snow.ui.components.SnowStatusBadge
import org.snow.ui.components.SnowTonalButton
import org.snow.ui.theme.LocalSnowColors
import org.snow.ui.theme.SnowTypography
import java.util.Locale

/**
 * Floating Network & Device Selector Island modal matching snow_network_device_selector_island.
 */
@Composable
fun SnowDeviceSelectorIsland(
    visible: Boolean,
    onDismiss: () -> Unit,
    localDeviceName: String,
    localSnowId: String,
    peerHostActive: Boolean,
    pairedDevices: List<SavedDevice>,
    activeDeviceHost: String,
    onSelectDevice: (SavedDevice) -> Unit,
    onJoinAnotherNetwork: () -> Unit,
    federationGrants: List<Map<String, Any?>> = emptyList(),
    onFederationGrantClick: () -> Unit = {},
    localPhoneTelemetry: PhoneTelemetry = PhoneTelemetry.UNAVAILABLE
) {
    if (!visible) return

    val colors = LocalSnowColors.current

    Dialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(usePlatformDefaultWidth = false)
    ) {
        Box(
            modifier = Modifier
                .fillMaxSize()
                .background(Color.Black.copy(alpha = 0.55f))
                .clickable(
                    interactionSource = remember { MutableInteractionSource() },
                    indication = null,
                    onClick = onDismiss
                ),
            contentAlignment = Alignment.TopCenter
        ) {
            Surface(
                modifier = Modifier
                    .padding(top = 72.dp, start = 16.dp, end = 16.dp)
                    .fillMaxWidth()
                    .shadow(16.dp, RoundedCornerShape(26.dp))
                    .clip(RoundedCornerShape(26.dp))
                    .border(1.dp, colors.border, RoundedCornerShape(26.dp))
                    .clickable(
                        interactionSource = remember { MutableInteractionSource() },
                        indication = null,
                        onClick = {} // Consume click
                    ),
                color = if (colors.isDark) Color(0xFF191B1F) else Color.White
            ) {
                Column(
                    modifier = Modifier.padding(20.dp)
                ) {
                    // Header
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = "NETWORK & DEVICES",
                            style = SnowTypography.labelSmall.copy(letterSpacing = 1.sp),
                            color = colors.textMuted
                        )
                        Text(
                            text = "Close",
                            style = SnowTypography.labelMedium,
                            color = colors.accentCyan,
                            modifier = Modifier
                                .clip(RoundedCornerShape(6.dp))
                                .clickable(onClick = onDismiss)
                                .padding(4.dp)
                        )
                    }

                    Spacer(modifier = Modifier.height(16.dp))

                    // Local Phone Node
                    Surface(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clip(RoundedCornerShape(16.dp))
                            .border(1.dp, colors.borderSubtle, RoundedCornerShape(16.dp)),
                        color = colors.surfaceElevated
                    ) {
                        Row(
                            modifier = Modifier.padding(14.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Box(
                                modifier = Modifier
                                    .size(38.dp)
                                    .clip(CircleShape)
                                    .background(colors.accentBlue.copy(alpha = 0.15f)),
                                contentAlignment = Alignment.Center
                            ) {
                                Icon(
                                    imageVector = Icons.Default.PhoneAndroid,
                                    contentDescription = null,
                                    tint = colors.accentBlue,
                                    modifier = Modifier.size(20.dp)
                                )
                            }
                            Spacer(modifier = Modifier.width(12.dp))
                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    text = localDeviceName.ifBlank { "This Phone" },
                                    style = SnowTypography.titleSmall,
                                    color = colors.textPrimary,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis
                                )
                                Spacer(modifier = Modifier.height(2.dp))
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    Text(
                                        text = "Local Node",
                                        style = SnowTypography.bodySmall,
                                        color = colors.textSecondary
                                    )
                                    val compactSnowId = if (localSnowId.isNotBlank()) {
                                        if (localSnowId.startsWith("SNW-") && localSnowId.length >= 8) localSnowId.substring(0, 8) else localSnowId.take(8)
                                    } else ""
                                    if (compactSnowId.isNotBlank()) {
                                        Spacer(modifier = Modifier.width(6.dp))
                                        Surface(
                                            shape = RoundedCornerShape(4.dp),
                                            color = colors.accentCyan.copy(alpha = 0.15f)
                                        ) {
                                            Text(
                                                text = compactSnowId,
                                                style = SnowTypography.monospaceSmall.copy(fontSize = 10.sp, fontWeight = androidx.compose.ui.text.font.FontWeight.Bold),
                                                color = colors.accentCyan,
                                                modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                                            )
                                        }
                                    }
                                }
                                if (localPhoneTelemetry.isAvailable) {
                                    Spacer(modifier = Modifier.height(4.dp))
                                    val metrics = buildList {
                                        val ch = if (localPhoneTelemetry.isCharging) " ⚡" else ""
                                        add("${localPhoneTelemetry.batteryPercent}%$ch")
                                        localPhoneTelemetry.temperatureCelsius?.let {
                                            add(String.format(Locale.US, "%.1f°C", it))
                                        }
                                        val rTot = localPhoneTelemetry.ramTotalBytes
                                        val rAvail = localPhoneTelemetry.ramAvailableBytes
                                        if (rTot != null && rTot > 0 && rAvail != null) {
                                            val ramPct = (((rTot - rAvail) * 100) / rTot).toInt()
                                            add("RAM $ramPct%")
                                        }
                                        val sAvail = localPhoneTelemetry.storageAvailableBytes
                                        if (sAvail != null && sAvail > 0) {
                                            val freeGb = sAvail.toDouble() / (1024.0 * 1024.0 * 1024.0)
                                            add(String.format(Locale.US, "%.1f GB free", freeGb))
                                        }
                                    }
                                    Text(
                                        text = metrics.joinToString(" • "),
                                        style = SnowTypography.labelSmall.copy(fontSize = 11.sp),
                                        color = colors.textMuted,
                                        maxLines = 1,
                                        overflow = TextOverflow.Ellipsis
                                    )
                                }
                            }
                            if (peerHostActive) {
                                SnowStatusBadge(text = "Host On", type = SnowBadgeType.CONNECTED)
                            }
                        }
                    }

                    Spacer(modifier = Modifier.height(16.dp))

                    // MY NETWORK Section
                    SnowSectionHeader(title = "Linked Devices (${pairedDevices.size})")

                    if (pairedDevices.isEmpty()) {
                        Text(
                            text = "No linked devices found. Tap + Connect to pair.",
                            style = SnowTypography.bodySmall,
                            color = colors.textSecondary,
                            modifier = Modifier.padding(vertical = 12.dp)
                        )
                    } else {
                        Column(
                            verticalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            pairedDevices.forEach { dev ->
                                val isActive = dev.host == activeDeviceHost || (activeDeviceHost == "127.0.0.1" && dev.host == "127.0.0.1")
                                val isPhone = dev.isPhone
                                val transportLabel = when {
                                    isPhone -> "Direct Peer"
                                    dev.host == "127.0.0.1" || dev.host == "localhost" -> "USB"
                                    dev.host.contains("relay") || dev.host.contains("tunnel") || dev.connectionMode == "remote_only" -> "Remote"
                                    else -> "Wi-Fi"
                                }

                                Surface(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .clip(RoundedCornerShape(14.dp))
                                        .border(
                                            1.dp,
                                            if (isActive) colors.accentBlue else colors.borderSubtle,
                                            RoundedCornerShape(14.dp)
                                        )
                                        .clickable {
                                            onSelectDevice(dev)
                                            onDismiss()
                                        },
                                    color = if (isActive) colors.surfaceElevated else colors.surface
                                ) {
                                    Row(
                                        modifier = Modifier.padding(12.dp),
                                        verticalAlignment = Alignment.CenterVertically
                                    ) {
                                        Icon(
                                            imageVector = if (isPhone) Icons.Default.PhoneAndroid else Icons.Default.Computer,
                                            contentDescription = null,
                                            tint = if (isActive) colors.accentBlue else colors.textSecondary,
                                            modifier = Modifier.size(22.dp)
                                        )
                                        Spacer(modifier = Modifier.width(12.dp))
                                        Column(modifier = Modifier.weight(1f)) {
                                            Text(
                                                text = dev.deviceName.ifBlank { dev.host },
                                                style = SnowTypography.bodyMedium.copy(fontWeight = androidx.compose.ui.text.font.FontWeight.SemiBold),
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
                                        if (isActive) {
                                            Box(
                                                modifier = Modifier
                                                    .size(22.dp)
                                                    .clip(CircleShape)
                                                    .background(colors.accentEmerald),
                                                contentAlignment = Alignment.Center
                                            ) {
                                                Icon(
                                                    imageVector = Icons.Default.Check,
                                                    contentDescription = "Active",
                                                    tint = Color.White,
                                                    modifier = Modifier.size(14.dp)
                                                )
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    Spacer(modifier = Modifier.height(16.dp))
                    Divider(color = colors.borderSubtle)
                    Spacer(modifier = Modifier.height(12.dp))

                    // OTHER NETWORKS Section
                    SnowSectionHeader(title = "OTHER NETWORKS")

                    val activeFedGrants = federationGrants.filter {
                        (it["status"]?.toString() ?: "ACTIVE").equals("ACTIVE", ignoreCase = true)
                    }
                    if (activeFedGrants.isEmpty()) {
                        Text(
                            text = "No remote federated networks connected.",
                            style = SnowTypography.bodySmall,
                            color = colors.textSecondary,
                            modifier = Modifier.padding(bottom = 10.dp)
                        )
                    } else {
                        Column(
                            verticalArrangement = Arrangement.spacedBy(8.dp),
                            modifier = Modifier.padding(bottom = 10.dp)
                        ) {
                            activeFedGrants.forEach { grant ->
                                val peerLabel = (grant["network_name"] as? String)
                                    ?: (grant["peer_node_name"] as? String)
                                    ?: (grant["peer_node_id"] as? String)
                                    ?: (grant["grant_id"] as? String)?.take(12)
                                    ?: "Federated Peer"
                                val direction = grant["direction"]?.toString() ?: "INBOUND"
                                val capsList = grant["allowed_capabilities"] as? List<*>
                                val capsSummary = if (!capsList.isNullOrEmpty()) {
                                    capsList.take(2).joinToString(", ")
                                } else {
                                    "Scoped Access"
                                }
                                Surface(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .clip(RoundedCornerShape(14.dp))
                                        .border(1.dp, colors.borderSubtle, RoundedCornerShape(14.dp))
                                        .clickable {
                                            onFederationGrantClick()
                                            onDismiss()
                                        },
                                    color = colors.surface
                                ) {
                                    Row(
                                        modifier = Modifier.padding(12.dp),
                                        verticalAlignment = Alignment.CenterVertically
                                    ) {
                                        Column(modifier = Modifier.weight(1f)) {
                                            Text(
                                                text = peerLabel,
                                                style = SnowTypography.bodyMedium.copy(fontWeight = androidx.compose.ui.text.font.FontWeight.SemiBold),
                                                color = colors.textPrimary
                                            )
                                            Text(
                                                text = "$direction • $capsSummary",
                                                style = SnowTypography.bodySmall,
                                                color = colors.textSecondary
                                            )
                                        }
                                        SnowStatusBadge(text = "Federated", type = SnowBadgeType.CONNECTED)
                                    }
                                }
                            }
                        }
                    }

                    SnowTonalButton(
                        text = "Join Another Network",
                        icon = Icons.Default.Add,
                        onClick = {
                            onJoinAnotherNetwork()
                            onDismiss()
                        },
                        modifier = Modifier.fillMaxWidth()
                    )
                }
            }
        }
    }
}
