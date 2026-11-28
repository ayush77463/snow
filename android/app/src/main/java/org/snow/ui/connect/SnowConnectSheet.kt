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
import androidx.compose.foundation.text.KeyboardOptions
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
import androidx.compose.material3.LinearProgressIndicator
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
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import org.snow.ui.SnowIdStep1Result
import org.snow.ui.components.SnowOutlinedButton
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
    onRegeneratePairingPin: () -> Unit = {},
    onCancelPairingPin: () -> Unit = {},
    myNetworkId: String? = null,
    onConnectSnowIdStep1: ((String, (SnowIdStep1Result) -> Unit) -> Unit)? = null,
    onConnectSnowIdStep2: ((snowId: String, pin: String, onResult: (Boolean, String?, Int?) -> Unit) -> Unit)? = null
) {
    if (!visible) return

    val colors = LocalSnowColors.current
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    var inputQuery by remember { mutableStateOf("") }
    var pendingStep2SnowId by remember { mutableStateOf<String?>(null) }
    var pendingStep2DisplayName by remember { mutableStateOf<String?>(null) }
    var step2Pin by remember { mutableStateOf("") }
    var stepBusy by remember { mutableStateOf(false) }
    var localStepError by remember { mutableStateOf<String?>(null) }
    val clipboardManager = LocalClipboardManager.current
    var copiedFeedback by remember { mutableStateOf(false) }

    val resetStepFlow = {
        pendingStep2SnowId = null
        pendingStep2DisplayName = null
        step2Pin = ""
        stepBusy = false
        localStepError = null
    }
    val dismissSheet = {
        resetStepFlow()
        onDismiss()
    }

    LaunchedEffect(visible) {
        if (visible) {
            resetStepFlow()
            onPreparePairingQr()
        }
    }

    ModalBottomSheet(
        onDismissRequest = dismissSheet,
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
                        .clickable(onClick = dismissSheet)
                        .padding(6.dp)
                )
            }

            // Action 1: Scan QR Code (Primary Hero)
            SnowGradientButton(
                text = "Scan QR Code",
                icon = Icons.Default.QrCodeScanner,
                onClick = {
                    onScanQr()
                    dismissSheet()
                },
                modifier = Modifier.fillMaxWidth()
            )

            Spacer(modifier = Modifier.height(16.dp))

            // Action 2: 2-Step SNOW ID -> PIN Connection Card
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
                        val effectiveBusy = isConnecting || stepBusy
                        val effectiveError = localStepError ?: errorMessage
                        val step2SnowId = pendingStep2SnowId

                        Spacer(modifier = Modifier.height(8.dp))

                        if (step2SnowId == null) {
                            // Step 1: Enter Peer SNOW ID -> Connect
                            Text(
                                text = "Enter a peer SNOW ID (SNW-...) to pair or reconnect.",
                                style = SnowTypography.bodySmall,
                                color = colors.textSecondary
                            )
                            Spacer(modifier = Modifier.height(12.dp))

                            OutlinedTextField(
                                value = inputQuery,
                                onValueChange = {
                                    inputQuery = it
                                    localStepError = null
                                },
                                modifier = Modifier.fillMaxWidth(),
                                label = { Text("Enter Peer SNOW ID") },
                                placeholder = {
                                    Text(
                                        text = "SNW-XXXX-XXXX or SNW-NET-XXXXXXXX",
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

                            if (!effectiveError.isNullOrBlank()) {
                                Spacer(modifier = Modifier.height(8.dp))
                                Surface(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .border(1.dp, Color(0xFFEF4444).copy(alpha = 0.45f), RoundedCornerShape(10.dp)),
                                    shape = RoundedCornerShape(10.dp),
                                    color = Color(0xFFEF4444).copy(alpha = 0.12f)
                                ) {
                                    Text(
                                        text = effectiveError,
                                        style = SnowTypography.bodySmall,
                                        color = Color(0xFFEF4444),
                                        modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp)
                                    )
                                }
                            }

                            Spacer(modifier = Modifier.height(14.dp))

                            SnowTonalButton(
                                text = if (effectiveBusy) "Connecting..." else "Connect",
                                onClick = {
                                    val target = inputQuery.trim()
                                    if (target.isNotEmpty()) {
                                        val step1Handler = onConnectSnowIdStep1
                                        if (step1Handler != null) {
                                            stepBusy = true
                                            localStepError = null
                                            step1Handler(target) { result ->
                                                stepBusy = false
                                                when (result) {
                                                    is SnowIdStep1Result.AlreadyConnected -> {
                                                        dismissSheet()
                                                    }
                                                    is SnowIdStep1Result.NeedsPin -> {
                                                        pendingStep2SnowId = result.snowId
                                                        pendingStep2DisplayName = result.displayName
                                                        step2Pin = ""
                                                        localStepError = null
                                                    }
                                                    is SnowIdStep1Result.Error -> {
                                                        localStepError = result.message
                                                    }
                                                }
                                            }
                                        } else {
                                            onConnectInput(target)
                                        }
                                    }
                                },
                                enabled = inputQuery.isNotBlank() && !effectiveBusy,
                                isLoading = effectiveBusy,
                                modifier = Modifier.fillMaxWidth()
                            )
                        } else {
                            // Step 2: Enter the 6-digit PIN shown on peer -> Verify & Pair / Change ID
                            Text(
                                text = "Enter the 6-digit PIN shown on $step2SnowId",
                                style = SnowTypography.bodySmall.copy(fontWeight = FontWeight.SemiBold),
                                color = colors.textPrimary
                            )
                            val peerDisplay = pendingStep2DisplayName
                            if (!peerDisplay.isNullOrBlank()) {
                                Spacer(modifier = Modifier.height(2.dp))
                                Text(
                                    text = peerDisplay,
                                    style = SnowTypography.labelSmall,
                                    color = colors.textSecondary
                                )
                            }
                            Spacer(modifier = Modifier.height(12.dp))

                            OutlinedTextField(
                                value = step2Pin,
                                onValueChange = { raw ->
                                    step2Pin = raw.filter { it.isDigit() }.take(6)
                                    localStepError = null
                                },
                                modifier = Modifier.fillMaxWidth(),
                                label = { Text("6-Digit PIN") },
                                placeholder = {
                                    Text(
                                        text = "123456",
                                        style = SnowTypography.monospaceSmall,
                                        color = colors.textMuted
                                    )
                                },
                                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
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

                            if (!effectiveError.isNullOrBlank()) {
                                Spacer(modifier = Modifier.height(8.dp))
                                Surface(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .border(1.dp, Color(0xFFEF4444).copy(alpha = 0.45f), RoundedCornerShape(10.dp)),
                                    shape = RoundedCornerShape(10.dp),
                                    color = Color(0xFFEF4444).copy(alpha = 0.12f)
                                ) {
                                    Text(
                                        text = effectiveError,
                                        style = SnowTypography.bodySmall,
                                        color = Color(0xFFEF4444),
                                        modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp)
                                    )
                                }
                            }

                            Spacer(modifier = Modifier.height(14.dp))

                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.spacedBy(10.dp)
                            ) {
                                SnowOutlinedButton(
                                    text = "Change ID",
                                    onClick = { resetStepFlow() },
                                    enabled = !effectiveBusy,
                                    modifier = Modifier.weight(1f)
                                )
                                SnowGradientButton(
                                    text = if (effectiveBusy) "Verifying..." else "Verify & Pair",
                                    onClick = {
                                        val step2Handler = onConnectSnowIdStep2
                                        if (step2Handler != null) {
                                            stepBusy = true
                                            localStepError = null
                                            step2Handler(step2SnowId, step2Pin) { success, msg, remainingAttempts ->
                                                stepBusy = false
                                                if (success) {
                                                    dismissSheet()
                                                } else {
                                                    // Stay on Step 2, keep snowId intact, clear invalid PIN for re-entry
                                                    step2Pin = ""
                                                    localStepError = if (remainingAttempts != null && remainingAttempts > 0) {
                                                        "Incorrect PIN — $remainingAttempts attempts remaining. Please re-enter."
                                                    } else {
                                                        msg?.takeIf { it.isNotBlank() }
                                                            ?: "Incorrect PIN. Please re-enter."
                                                    }
                                                }
                                            }
                                        } else {
                                            onConnectInput("$step2SnowId $step2Pin")
                                        }
                                    },
                                    enabled = step2Pin.length == 6 && !effectiveBusy,
                                    isLoading = effectiveBusy,
                                    modifier = Modifier.weight(1.4f)
                                )
                            }
                        }
                    }
                }
            }

            Spacer(modifier = Modifier.height(16.dp))

            // Action 3 & 4: Canonical Identity + Always-Visible Live Zero-PIN Pairing QR
            val canonicalId = mySnowId.trim().uppercase()
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
                                text = canonicalId.ifBlank { "Generating..." },
                                style = SnowTypography.monospaceSmall.copy(fontWeight = FontWeight.Bold),
                                color = colors.textPrimary
                            )
                        }

                        SnowTonalButton(
                            text = if (copiedFeedback) "Copied!" else "Copy",
                            icon = Icons.Default.ContentCopy,
                            enabled = canonicalId.isNotBlank(),
                            onClick = {
                                if (canonicalId.isNotBlank()) {
                                    clipboardManager.setText(AnnotatedString(canonicalId))
                                    copiedFeedback = true
                                }
                            }
                        )
                    }

                    Spacer(modifier = Modifier.height(10.dp))

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = "MY NETWORK ID",
                                style = SnowTypography.labelSmall.copy(letterSpacing = 1.sp),
                                color = colors.textMuted
                            )
                            Spacer(modifier = Modifier.height(2.dp))
                            Text(
                                text = myNetworkId?.takeIf { it.isNotBlank() } ?: "Standalone",
                                style = SnowTypography.monospaceSmall.copy(fontWeight = FontWeight.SemiBold),
                                color = if (!myNetworkId.isNullOrBlank()) colors.accentCyan else colors.textSecondary
                            )
                        }
                    }

                    Spacer(modifier = Modifier.height(14.dp))
                    Divider(color = colors.borderSubtle)
                    Spacer(modifier = Modifier.height(12.dp))

                    Row(
                        modifier = Modifier.fillMaxWidth(),
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
                                text = "Live Zero-PIN Pairing QR",
                                style = SnowTypography.labelMedium,
                                color = colors.textPrimary
                            )
                        }
                        SnowOutlinedButton(
                            text = "Refresh QR",
                            onClick = onPreparePairingQr
                        )
                    }

                    Spacer(modifier = Modifier.height(12.dp))

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
                                    text = "Preparing live QR v2...",
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

                        Spacer(modifier = Modifier.height(12.dp))

                        val activePin = peerHostState.pairingPin?.takeIf {
                            it.isNotBlank() && peerHostState.pinExpiresInSeconds > 0L
                        }
                        if (activePin != null) {
                            val formattedPin = if (activePin.length == 6) {
                                "${activePin.take(3)} ${activePin.drop(3)}"
                            } else {
                                activePin
                            }
                            Column(modifier = Modifier.fillMaxWidth()) {
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Column(modifier = Modifier.weight(1f)) {
                                        Text(
                                            text = "PIN: $formattedPin",
                                            style = SnowTypography.monospaceSmall.copy(fontWeight = FontWeight.Bold),
                                            color = colors.accentCyan
                                        )
                                        Text(
                                            text = "Expires in ${peerHostState.pinExpiresInSeconds}s • ${peerHostState.ipAddress}",
                                            style = SnowTypography.labelSmall,
                                            color = colors.textMuted
                                        )
                                    }
                                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                        SnowTonalButton(
                                            text = "New PIN",
                                            icon = Icons.Default.Refresh,
                                            onClick = onRegeneratePairingPin
                                        )
                                        SnowOutlinedButton(
                                            text = "Cancel",
                                            onClick = onCancelPairingPin
                                        )
                                    }
                                }
                                Spacer(modifier = Modifier.height(6.dp))
                                LinearProgressIndicator(
                                    progress = (peerHostState.pinExpiresInSeconds.coerceIn(0L, 60L) / 60f),
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .height(4.dp)
                                        .clip(RoundedCornerShape(9999.dp)),
                                    color = colors.accentCyan,
                                    trackColor = colors.surfaceElevated
                                )
                            }
                        } else {
                            SnowTonalButton(
                                text = "Generate 6-Digit PIN",
                                icon = Icons.Default.Refresh,
                                onClick = onRegeneratePairingPin,
                                modifier = Modifier.fillMaxWidth()
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
                                text = pairingQrError ?: "Connect to Wi-Fi or hotspot to share live QR.",
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
