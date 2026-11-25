package org.snow.ui.shell

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
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
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.History
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material3.Divider
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import org.snow.ui.PendingApprovalItem
import org.snow.ui.UiLogEntry
import org.snow.ui.components.SnowBadgeType
import org.snow.ui.components.SnowCard
import org.snow.ui.components.SnowEmptyState
import org.snow.ui.components.SnowSectionHeader
import org.snow.ui.components.SnowStatusBadge
import org.snow.ui.theme.LocalSnowColors
import org.snow.ui.theme.SnowTypography

/**
 * Modal bottom sheet presenting real pending capability approvals & real-time activity stream.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SnowApprovalsSheet(
    visible: Boolean,
    onDismiss: () -> Unit,
    pendingApprovals: List<PendingApprovalItem>,
    logs: List<UiLogEntry>,
    onResolveApproval: (requestId: String, decision: String) -> Unit,
    initialTab: Int = 0
) {
    if (!visible) return

    val colors = LocalSnowColors.current
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    var selectedTab by remember(visible, initialTab) { mutableStateOf(initialTab) } // 0: Approvals, 1: Activity

    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = sheetState,
        shape = RoundedCornerShape(topStart = 28.dp, topEnd = 28.dp),
        containerColor = if (colors.isDark) Color(0xFF161616) else Color.White,
        tonalElevation = 8.dp
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .fillMaxHeight(0.85f)
                .padding(horizontal = 20.dp)
        ) {
            // Header & Drag Handle Area
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(bottom = 16.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        imageVector = Icons.Default.Shield,
                        contentDescription = null,
                        tint = colors.accentCyan,
                        modifier = Modifier.size(24.dp)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = "Approvals & Activity",
                        style = SnowTypography.titleLarge,
                        color = colors.textPrimary
                    )
                }

                Text(
                    text = "Done",
                    style = SnowTypography.labelMedium,
                    color = colors.accentCyan,
                    modifier = Modifier
                        .clip(RoundedCornerShape(6.dp))
                        .clickable(onClick = onDismiss)
                        .padding(6.dp)
                )
            }

            // Tab Switcher
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(9999.dp))
                    .background(colors.surfaceElevated)
                    .padding(4.dp)
            ) {
                Box(
                    modifier = Modifier
                        .weight(1f)
                        .clip(RoundedCornerShape(9999.dp))
                        .background(if (selectedTab == 0) (if (colors.isDark) Color(0xFF2A2A2A) else Color.White) else Color.Transparent)
                        .clickable { selectedTab = 0 }
                        .padding(vertical = 8.dp),
                    contentAlignment = Alignment.Center
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(
                            text = "Pending Approvals",
                            style = SnowTypography.labelMedium,
                            color = if (selectedTab == 0) colors.textPrimary else colors.textMuted
                        )
                        if (pendingApprovals.isNotEmpty()) {
                            Spacer(modifier = Modifier.width(6.dp))
                            Box(
                                modifier = Modifier
                                    .clip(CircleShape)
                                    .background(colors.accentCyan)
                                    .padding(horizontal = 6.dp, vertical = 2.dp)
                            ) {
                                Text(
                                    text = pendingApprovals.size.toString(),
                                    style = SnowTypography.labelSmall.copy(fontSize = 10.sp, color = Color.Black)
                                )
                            }
                        }
                    }
                }

                Box(
                    modifier = Modifier
                        .weight(1f)
                        .clip(RoundedCornerShape(9999.dp))
                        .background(if (selectedTab == 1) (if (colors.isDark) Color(0xFF2A2A2A) else Color.White) else Color.Transparent)
                        .clickable { selectedTab = 1 }
                        .padding(vertical = 8.dp),
                    contentAlignment = Alignment.Center
                ) {
                    Text(
                        text = "Live Activity (${logs.size})",
                        style = SnowTypography.labelMedium,
                        color = if (selectedTab == 1) colors.textPrimary else colors.textMuted
                    )
                }
            }

            Spacer(modifier = Modifier.height(16.dp))

            // Tab Content
            if (selectedTab == 0) {
                if (pendingApprovals.isEmpty()) {
                    SnowEmptyState(
                        title = "No Pending Approvals",
                        description = "All incoming capability executions and agent operations are currently authorized or idle.",
                        icon = Icons.Default.Security
                    )
                } else {
                    LazyColumn(
                        verticalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        items(pendingApprovals, key = { it.requestId }) { item ->
                            SnowApprovalCard(
                                item = item,
                                onApprove = { onResolveApproval(item.requestId, "APPROVE") },
                                onDeny = { onResolveApproval(item.requestId, "DENY") }
                            )
                        }
                    }
                }
            } else {
                if (logs.isEmpty()) {
                    SnowEmptyState(
                        title = "No Activity Logs",
                        description = "Operational telemetry and audit events will appear here in real time.",
                        icon = Icons.Default.History
                    )
                } else {
                    LazyColumn(
                        verticalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        items(logs.reversed()) { log ->
                            SnowLogCard(log = log)
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun SnowApprovalCard(
    item: PendingApprovalItem,
    onApprove: () -> Unit,
    onDeny: () -> Unit
) {
    val colors = LocalSnowColors.current

    SnowCard(
        modifier = Modifier.fillMaxWidth(),
        cornerRadius = 16.dp
    ) {
        Column {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = item.action.uppercase(),
                    style = SnowTypography.labelSmall.copy(fontWeight = FontWeight.Bold, letterSpacing = 1.sp),
                    color = colors.accentCyan
                )
                val badgeType = when (item.riskLevel.uppercase()) {
                    "HIGH", "CRITICAL" -> SnowBadgeType.ERROR
                    "MEDIUM" -> SnowBadgeType.PROCESSING
                    else -> SnowBadgeType.STANDBY
                }
                SnowStatusBadge(text = "${item.riskLevel.uppercase()} RISK", type = badgeType)
            }

            Spacer(modifier = Modifier.height(8.dp))

            Text(
                text = item.reason.ifBlank { "Operation requested by autonomous agent or peer." },
                style = SnowTypography.bodyMedium,
                color = colors.textPrimary
            )

            Spacer(modifier = Modifier.height(6.dp))

            Text(
                text = "Target: ${item.targetDevice.ifBlank { "Local Device" }} • Principal: ${item.principal}",
                style = SnowTypography.bodySmall,
                color = colors.textSecondary
            )

            if (item.timeRemainingSeconds > 0) {
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = "Expires in ${item.timeRemainingSeconds.toInt()}s",
                    style = SnowTypography.labelSmall,
                    color = colors.textMuted
                )
            }

            Spacer(modifier = Modifier.height(14.dp))
            Divider(color = colors.borderSubtle)
            Spacer(modifier = Modifier.height(12.dp))

            // Action Buttons
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.End
            ) {
                // Deny Button
                Surface(
                    modifier = Modifier
                        .clip(RoundedCornerShape(9999.dp))
                        .border(1.dp, Color(0xFFEF4444).copy(alpha = 0.4f), RoundedCornerShape(9999.dp))
                        .clickable(onClick = onDeny),
                    shape = RoundedCornerShape(9999.dp),
                    color = Color(0xFFEF4444).copy(alpha = 0.1f)
                ) {
                    Row(
                        modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(
                            imageVector = Icons.Default.Close,
                            contentDescription = "Deny",
                            tint = Color(0xFFEF4444),
                            modifier = Modifier.size(16.dp)
                        )
                        Spacer(modifier = Modifier.width(6.dp))
                        Text(
                            text = "Deny",
                            style = SnowTypography.labelMedium,
                            color = Color(0xFFEF4444)
                        )
                    }
                }

                Spacer(modifier = Modifier.width(12.dp))

                // Approve Button
                Surface(
                    modifier = Modifier
                        .clip(RoundedCornerShape(9999.dp))
                        .clickable(onClick = onApprove),
                    shape = RoundedCornerShape(9999.dp),
                    color = colors.accentEmerald
                ) {
                    Row(
                        modifier = Modifier.padding(horizontal = 18.dp, vertical = 8.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(
                            imageVector = Icons.Default.Check,
                            contentDescription = "Approve",
                            tint = Color.White,
                            modifier = Modifier.size(16.dp)
                        )
                        Spacer(modifier = Modifier.width(6.dp))
                        Text(
                            text = "Approve",
                            style = SnowTypography.labelMedium,
                            color = Color.White
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun SnowLogCard(log: UiLogEntry) {
    val colors = LocalSnowColors.current

    Surface(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(12.dp))
            .border(1.dp, colors.borderSubtle, RoundedCornerShape(12.dp)),
        color = colors.surfaceElevated
    ) {
        Column(modifier = Modifier.padding(10.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = "[${log.tag}]",
                    style = SnowTypography.monospaceSmall.copy(fontWeight = FontWeight.Bold),
                    color = colors.accentCyan
                )
                Text(
                    text = log.timestamp,
                    style = SnowTypography.bodySmall,
                    color = colors.textMuted
                )
            }
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                text = log.message,
                style = SnowTypography.bodySmall,
                color = colors.textPrimary
            )
        }
    }
}
