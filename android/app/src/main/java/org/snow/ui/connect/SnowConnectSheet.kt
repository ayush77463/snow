package org.snow.ui.connect

import android.graphics.Bitmap
import androidx.compose.foundation.Image
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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.ExpandLess
import androidx.compose.material.icons.filled.ExpandMore
import androidx.compose.material.icons.filled.QrCode
import androidx.compose.material.icons.filled.QrCodeScanner
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Divider
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.google.zxing.BarcodeFormat
import com.google.zxing.qrcode.QRCodeWriter
import org.snow.network.PeerHostState
import org.snow.ui.components.SnowCard
import org.snow.ui.components.SnowGradientButton
import org.snow.ui.components.SnowSectionHeader
import org.snow.ui.components.SnowTonalButton
import org.snow.ui.theme.LocalSnowColors
import org.snow.ui.theme.SnowTypography

/**
 * Connect Device Bottom Sheet providing QR scan, direct input, and live peer-host pairing QR.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SnowConnectSheet(
    visible: Boolean,
    onDismiss: () -> Unit,
    onScanQr: () -> Unit,
    onConnectInput: (String) -> Unit,
    mySnowId: String,
    myDeviceId: String,
    isConnecting: Boolean = false,
    errorMessage: String? = null,
    peerHostState: PeerHostState = PeerHostState(),
    pairingQrJson: String? = null,
    pairingQrError: String? = null,
    isPreparingPairingQr: Boolean = false,
    onPreparePairingQr: () -> Unit = {},
    onRegeneratePairingPin: () -> Unit = {}
) {
    if (!visible) return

    val colors = LocalSnowColors.current
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    var inputQuery by remember { mutableStateOf("") }
    var showMyQr by remember { mutableStateOf(false) }
    val clipboardManager = LocalClipboardManager.current
    var copiedFeedback by remember { mutableStateOf(false) }

    LaunchedEffect(showMyQr) {
        if (showMyQr) {
            onPreparePairingQr()
        }
    }

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
                .verticalScroll(rememberScrollState())
        ) {
            // Header
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(bottom = 16.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = "Connect Device",
                    style = SnowTypography.titleLarge,
                    color = colors.textPrimary
                )
                Text(
                    text = "Close",
                    style = SnowTypography.labelMedium,
                    color = colors.accentCyan,
                    modifier = Modifier
                        .clip(RoundedCornerShape(6.dp))
                        .clickable(onClick = onDismiss)
                        .padding(6.dp)
                )
            }

            // Action 1: Scan QR Code (Primary Hero)
            SnowGradientButton(
                text = "Scan QR Code",
                icon = Icons.Default.QrCodeScanner,
                onClick = {
                    onScanQr()
                    onDismiss()
                },
                modifier = Modifier.fillMaxWidth()
            )

            Spacer(modifier = Modifier.height(16.dp))

            // Action 2: Direct or Code Link (Collapsible Manual IP / Address)
            var showManualInput by remember { mutableStateOf(false) }

            SnowCard(
                modifier = Modifier.fillMaxWidth(),
                cornerRadius = 18.dp
            ) {
                Column {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable { showManualInput = !showManualInput },
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = "SNOW ID or Network Code",
                            style = SnowTypography.titleSmall,
                            color = colors.textPrimary
                        )
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Text(
                                text = if (showManualInput) "Hide" else "Enter",
                                style = SnowTypography.labelSmall.copy(fontWeight = FontWeight.SemiBold),
                                color = colors.accentCyan
                            )
                            Spacer(modifier = Modifier.width(4.dp))
                            Icon(
                                imageVector = if (showManualInput) Icons.Default.ExpandLess else Icons.Default.ExpandMore,
                                contentDescription = null,
                                tint = colors.accentCyan,
                                modifier = Modifier.size(18.dp)
                            )
                        }
                    }

                    if (showManualInput) {
                        Spacer(modifier = Modifier.height(8.dp))
                        Text(
                            text = "Enter a SNOW ID (SNW-...) or 9-digit network invite code.",
                            style = SnowTypography.bodySmall,
                            color = colors.textSecondary
                        )
                        Spacer(modifier = Modifier.height(12.dp))

                        OutlinedTextField(
                            value = inputQuery,
                            onValueChange = { inputQuery = it },
                            modifier = Modifier.fillMaxWidth(),
                            placeholder = {
                                Text(
                                    text = "SNW-XXXX-XXXX or 123-456-789",
                                    style = SnowTypography.bodyMedium,
                                    color = colors.textMuted
                                )
                            },
                            colors = OutlinedTextFieldDefaults.colors(
                                focusedBorderColor = colors.accentBlue,
                                unfocusedBorderColor = colors.border,
                                focusedTextColor = colors.textPrimary,
                                unfocusedTextColor = colors.textPrimary,
                                cursorColor = colors.accentCyan
                            ),
                            singleLine = true,
                            shape = RoundedCornerShape(12.dp)
                        )

                        if (!errorMessage.isNullOrBlank()) {
                            Spacer(modifier = Modifier.height(8.dp))
                            Text(
                                text = errorMessage,
                                style = SnowTypography.bodySmall,
                                color = Color(0xFFEF4444)
                            )
                        }

                        Spacer(modifier = Modifier.height(14.dp))

                        SnowTonalButton(
                            text = if (isConnecting) "Connecting..." else "Connect",
                            onClick = {
                                if (inputQuery.isNotBlank()) {
                                    onConnectInput(inputQuery.trim())
                                }
                            },
                            enabled = inputQuery.isNotBlank() && !isConnecting,
                            modifier = Modifier.fillMaxWidth()
                        )
                    }
                }
            }

            Spacer(modifier = Modifier.height(16.dp))

            // Action 3 & 4: My Identity and QR
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
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = "MY SNOW ID",
                                style = SnowTypography.labelSmall.copy(letterSpacing = 1.sp),
                                color = colors.textMuted
                            )
                            Spacer(modifier = Modifier.height(4.dp))
                            Text(
                                text = mySnowId.ifBlank { myDeviceId },
                                style = SnowTypography.monospaceSmall.copy(fontWeight = FontWeight.Bold),
                                color = colors.textPrimary
                            )
                        }

                        SnowTonalButton(
                            text = if (copiedFeedback) "Copied!" else "Copy",
                            icon = Icons.Default.ContentCopy,
                            onClick = {
                                clipboardManager.setText(AnnotatedString(mySnowId.ifBlank { myDeviceId }))
                                copiedFeedback = true
                            }
                        )
                    }

                    Spacer(modifier = Modifier.height(14.dp))
                    Divider(color = colors.borderSubtle)
                    Spacer(modifier = Modifier.height(12.dp))

                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable { showMyQr = !showMyQr },
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(
                                imageVector = Icons.Default.QrCode,
                                contentDescription = null,
                                tint = colors.accentCyan,
                                modifier = Modifier.size(20.dp)
                            )
                            Spacer(modifier = Modifier.width(8.dp))
                            Text(
                                text = if (showMyQr) "Hide Pairing QR" else "Show My Pairing QR",
                                style = SnowTypography.labelMedium,
                                color = colors.textPrimary
                            )
                        }
                        Icon(
                            imageVector = if (showMyQr) Icons.Default.ExpandLess else Icons.Default.ExpandMore,
                            contentDescription = null,
                            tint = colors.textMuted,
                            modifier = Modifier.size(18.dp)
                        )
                    }

                    if (showMyQr) {
                        Spacer(modifier = Modifier.height(14.dp))
                        if (isPreparingPairingQr) {
                            Box(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(vertical = 24.dp),
                                contentAlignment = Alignment.Center
                            ) {
                                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                                    CircularProgressIndicator(
                                        modifier = Modifier.size(26.dp),
                                        color = colors.accentCyan,
                                        strokeWidth = 2.5.dp
                                    )
                                    Spacer(modifier = Modifier.height(8.dp))
                                    Text(
                                        text = "Starting direct pairing host...",
                                        style = SnowTypography.bodySmall,
                                        color = colors.textSecondary
                                    )
                                }
                            }
                        } else if (!pairingQrJson.isNullOrBlank()) {
                            Box(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .clip(RoundedCornerShape(12.dp))
                                    .background(Color.White)
                                    .padding(16.dp),
                                contentAlignment = Alignment.Center
                            ) {
                                val qrBitmap = remember(pairingQrJson) {
                                    generateQrCode(pairingQrJson)
                                }
                                if (qrBitmap != null) {
                                    Image(
                                        bitmap = qrBitmap.asImageBitmap(),
                                        contentDescription = "SNOW Protocol Pairing QR Code",
                                        modifier = Modifier.size(200.dp)
                                    )
                                } else {
                                    Text(
                                        text = "Unable to encode pairing QR",
                                        style = SnowTypography.bodySmall,
                                        color = Color.Black
                                    )
                                }
                            }

                            Spacer(modifier = Modifier.height(10.dp))

                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                val pinRaw = peerHostState.pairingPin ?: ""
                                val formattedPin = if (pinRaw.length == 6) "${pinRaw.take(3)} ${pinRaw.drop(3)}" else pinRaw.ifBlank { "--- ---" }
                                Column(modifier = Modifier.weight(1f)) {
                                    Text(
                                        text = "PAIRING PIN: $formattedPin",
                                        style = SnowTypography.monospaceSmall.copy(fontWeight = FontWeight.Bold),
                                        color = colors.accentCyan
                                    )
                                    val ttlText = if (peerHostState.pinExpiresInSeconds > 0L) {
                                        "Expires in ${peerHostState.pinExpiresInSeconds}s • ${peerHostState.ipAddress}"
                                    } else {
                                        "Host ${peerHostState.ipAddress}"
                                    }
                                    Text(
                                        text = ttlText,
                                        style = SnowTypography.labelSmall,
                                        color = colors.textMuted
                                    )
                                }
                                SnowTonalButton(
                                    text = "New PIN",
                                    icon = Icons.Default.Refresh,
                                    onClick = onRegeneratePairingPin
                                )
                            }
                        } else {
                            Column(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(vertical = 12.dp),
                                horizontalAlignment = Alignment.CenterHorizontally
                            ) {
                                Text(
                                    text = pairingQrError ?: "Unable to generate pairing QR.",
                                    style = SnowTypography.bodySmall,
                                    color = colors.textSecondary
                                )
                                Spacer(modifier = Modifier.height(10.dp))
                                SnowTonalButton(
                                    text = "Retry QR",
                                    icon = Icons.Default.Refresh,
                                    onClick = onPreparePairingQr
                                )
                            }
                        }
                    }
                }
            }

            Spacer(modifier = Modifier.height(24.dp))
        }
    }
}

private fun generateQrCode(text: String): Bitmap? {
    if (text.isBlank()) return null
    return try {
        val writer = QRCodeWriter()
        val bitMatrix = writer.encode(text, BarcodeFormat.QR_CODE, 512, 512)
        val width = bitMatrix.width
        val height = bitMatrix.height
        val bmp = Bitmap.createBitmap(width, height, Bitmap.Config.RGB_565)
        for (x in 0 until width) {
            for (y in 0 until height) {
                bmp.setPixel(x, y, if (bitMatrix.get(x, y)) android.graphics.Color.BLACK else android.graphics.Color.WHITE)
            }
        }
        bmp
    } catch (_: Exception) {
        null
    }
}
