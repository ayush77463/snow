package org.snow.capabilities

import android.content.Context
import android.graphics.Bitmap
import android.graphics.PixelFormat
import android.hardware.display.DisplayManager
import android.hardware.display.VirtualDisplay
import android.media.ImageReader
import android.media.projection.MediaProjection
import android.os.Handler
import android.os.Looper
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import org.snow.security.SafeLog
import org.snow.transfer.FileTransferClient
import java.io.ByteArrayOutputStream
import java.util.UUID

data class ScreenTargetEndpoint(
    val deviceId: String,
    val host: String,
    val transferPort: Int,
    val useRelay: Boolean = false
)

/**
 * Continuous live screen streaming capability using Android MediaProjection.
 *
 * Captures screen frames, scales them to bounded dimensions (max long edge 720px),
 * compresses them to JPEG (quality 70), and POSTs them over authenticated HTTPS (port 8766)
 * at a bounded rate (default 2 FPS, configurable 1-5 FPS).
 *
 * Strict separation: The WSS control plane (port 8765) carries only session metadata
 * and never raw or Base64 image payloads.
 */
class LiveScreenStreamHandler(
    private val context: Context,
    private val transferClientProvider: () -> FileTransferClient?
) {
    companion object {
        private const val TAG = "LiveScreenStreamHandler"
        const val MAX_LONG_EDGE = 720
        const val MAX_FRAME_BYTES = 524288L // 512 KiB
        const val DEFAULT_FPS = 2.0f
        const val MIN_FPS = 1.0f
        const val MAX_FPS = 5.0f
        const val JPEG_QUALITY = 70

        /**
         * Test hooks for deterministic automated JVM unit testing.
         */
        @Volatile
        var mockFrameProvider: (() -> ByteArray?)? = null

        @Volatile
        var mockFramePoster: ((ByteArray, String, Int, Int, Float) -> Boolean)? = null

        @Volatile
        var mockTargetFramePoster: ((ScreenTargetEndpoint, ByteArray, String, Int, Int, Float) -> Boolean)? = null
    }

    enum class StreamState {
        IDLE,
        STARTING,
        STREAMING,
        STOPPING,
        STOPPED,
        ERROR,
        REVOKED
    }

    data class StreamStats(
        val fps: Float = 0f,
        val frameCount: Long = 0L,
        val totalBytes: Long = 0L,
        val lastFrameTimestamp: Long = 0L,
        val frameWidth: Int = 0,
        val frameHeight: Int = 0,
        val deduplicatedSkips: Long = 0L,
        val zeroViewerPauses: Long = 0L
    )

    private val _streamState = MutableStateFlow(StreamState.IDLE)
    val streamState: StateFlow<StreamState> = _streamState.asStateFlow()

    private val _stats = MutableStateFlow(StreamStats())
    val stats: StateFlow<StreamStats> = _stats.asStateFlow()

    @Volatile
    private var activeMediaProjection: MediaProjection? = null
    private var virtualDisplay: VirtualDisplay? = null
    private var imageReader: ImageReader? = null
    private var projectionCallback: MediaProjection.Callback? = null
    private var frameLoopJob: Job? = null
    private val handlerScope = CoroutineScope(Dispatchers.IO)
    private val reusableBaos = ByteArrayOutputStream(64 * 1024)

    @Volatile
    private var currentSessionId: String? = null
    @Volatile
    var targetDeviceIds: List<String> = emptyList()
        private set
    @Volatile
    var activeTargets: List<ScreenTargetEndpoint> = emptyList()
        private set
    @Volatile
    var relayMediaSenderForTarget: ((ScreenTargetEndpoint, Map<String, Any?>, ByteArray) -> Boolean)? = null
    @Volatile
    private var legacyFallbackRelayEnabled: Boolean = false
    @Volatile
    var activeViewerCount: Int = 1
        private set
    @Volatile
    private var lastFrameSha256: String? = null
    @Volatile
    private var lastDims: Pair<Int, Int>? = null
    @Volatile
    private var wasPausedZeroViewers: Boolean = false
    @Volatile
    private var frameSeqCounter: Long = 0L

    var relayMediaSender: ((meta: Map<String, Any?>, jpegBytes: ByteArray) -> Boolean)? = null

    fun setViewerCount(count: Int) {
        val prev = activeViewerCount
        activeViewerCount = count.coerceAtLeast(0)
        if (activeViewerCount == 0 || (prev == 0 && activeViewerCount > 0)) {
            lastFrameSha256 = null
        }
    }

    /**
     * Optional callback invoked when MediaProjection is revoked by OS,
     * allowing the service to demote its foreground notification state.
     */
    var onRevoked: (() -> Unit)? = null

    /**
     * Start continuous live screen streaming to a single legacy target endpoint.
     */
    fun startStreaming(
        projection: MediaProjection,
        serverHost: String,
        transferPort: Int = 8766,
        targetFps: Float = DEFAULT_FPS,
        targetIds: List<String> = emptyList(),
        senderDeviceId: String = "",
        senderName: String = "Android Phone",
        initialViewerCount: Int = 1
    ) {
        val cleanIds = targetIds.filter { it.isNotBlank() }.distinct()
        val endpoint = ScreenTargetEndpoint(
            deviceId = cleanIds.firstOrNull().orEmpty(),
            host = serverHost.trim(),
            transferPort = transferPort,
            useRelay = relayMediaSender != null && serverHost.isBlank()
        )
        startStreamingInternal(
            projection = projection,
            targets = if (serverHost.isNotBlank() || endpoint.useRelay) listOf(endpoint) else emptyList(),
            explicitTargetIds = cleanIds,
            legacyFallbackRelay = true,
            targetFps = targetFps,
            senderDeviceId = senderDeviceId,
            senderName = senderName,
            initialViewerCount = initialViewerCount
        )
    }

    /**
     * Start continuous live screen streaming with concurrent fan-out across multiple endpoints
     * (e.g. PC port 8766, Android peer media port 8769, and/or E2E remote relay).
     */
    fun startStreamingTargets(
        projection: MediaProjection,
        targets: List<ScreenTargetEndpoint>,
        targetFps: Float = DEFAULT_FPS,
        senderDeviceId: String = "",
        senderName: String = "Android Phone",
        initialViewerCount: Int = 1
    ) {
        val deduped = targets
            .filter { it.useRelay || it.host.isNotBlank() }
            .distinctBy { "${it.deviceId.lowercase()}|${it.host}|${it.transferPort}|${it.useRelay}" }
        startStreamingInternal(
            projection = projection,
            targets = deduped,
            explicitTargetIds = deduped.map { it.deviceId }.filter { it.isNotBlank() }.distinct(),
            legacyFallbackRelay = false,
            targetFps = targetFps,
            senderDeviceId = senderDeviceId,
            senderName = senderName,
            initialViewerCount = initialViewerCount
        )
    }

    private fun startStreamingInternal(
        projection: MediaProjection,
        targets: List<ScreenTargetEndpoint>,
        explicitTargetIds: List<String>,
        legacyFallbackRelay: Boolean,
        targetFps: Float,
        senderDeviceId: String,
        senderName: String,
        initialViewerCount: Int
    ) {
        synchronized(this) {
            if (_streamState.value == StreamState.STREAMING || _streamState.value == StreamState.STARTING) {
                SafeLog.w(TAG, "Screen streaming already active or starting; ignoring duplicate start.")
                return
            }
            _streamState.value = StreamState.STARTING
            activeMediaProjection = projection
        }

        val clampedFps = targetFps.coerceIn(MIN_FPS, MAX_FPS)
        val sessionId = UUID.randomUUID().toString().take(8)
        currentSessionId = sessionId
        activeTargets = targets
        targetDeviceIds = explicitTargetIds.ifEmpty {
            targets.map { it.deviceId }.filter { it.isNotBlank() }.distinct()
        }
        legacyFallbackRelayEnabled = legacyFallbackRelay
        activeViewerCount = initialViewerCount.coerceAtLeast(0)
        lastFrameSha256 = null
        lastDims = null
        wasPausedZeroViewers = false
        frameSeqCounter = 0L

        val metrics = context.resources.displayMetrics
        val rawWidth = metrics.widthPixels
        val rawHeight = metrics.heightPixels
        val densityDpi = metrics.densityDpi

        // Scale to bounded dimensions (max long edge 720, preserving aspect ratio)
        val (targetWidth, targetHeight) = computeScaledDimensions(rawWidth, rawHeight, MAX_LONG_EDGE)

        SafeLog.i(
            TAG,
            "Initializing screen stream: ${targetWidth}x${targetHeight} @ ${clampedFps} FPS (session=$sessionId, targets=${targets.size})"
        )

        try {
            // Android 14+ requirement: register callback before creating VirtualDisplay
            val callback = object : MediaProjection.Callback() {
                override fun onStop() {
                    SafeLog.i(TAG, "MediaProjection revoked or stopped by OS.")
                    _streamState.value = StreamState.REVOKED
                    val stopTargets = activeTargets
                    if (stopTargets.isNotEmpty()) {
                        handlerScope.launch {
                            sendStopSignalsToTargets(stopTargets)
                        }
                    }
                    cleanup(isExplicitStop = false)
                    onRevoked?.invoke()
                }
            }
            projectionCallback = callback
            try {
                projection.registerCallback(callback, Handler(Looper.getMainLooper()))
            } catch (e: Exception) {
                SafeLog.w(TAG, "Failed registering projection callback: ${e.message}")
            }

            // ImageReader for bounded frames
            val reader = ImageReader.newInstance(
                targetWidth, targetHeight, PixelFormat.RGBA_8888, 2
            )
            imageReader = reader

            virtualDisplay = projection.createVirtualDisplay(
                "SnowLiveScreenStream",
                targetWidth,
                targetHeight,
                densityDpi,
                DisplayManager.VIRTUAL_DISPLAY_FLAG_AUTO_MIRROR,
                reader.surface,
                null,
                null
            )

            _streamState.value = StreamState.STREAMING
            _stats.value = StreamStats(
                fps = clampedFps,
                frameWidth = targetWidth,
                frameHeight = targetHeight,
                lastFrameTimestamp = System.currentTimeMillis()
            )

            // Start frame acquisition & concurrent multi-target transmission loop
            startFrameLoop(
                reader = reader,
                width = targetWidth,
                height = targetHeight,
                fps = clampedFps,
                targets = targets,
                sessionId = sessionId,
                senderDeviceId = senderDeviceId,
                senderName = senderName
            )

        } catch (e: Exception) {
            SafeLog.e(TAG, "Failed starting screen stream: ${e.message}", e)
            _streamState.value = StreamState.ERROR
            cleanup()
        }
    }

    private fun sha256Hex(bytes: ByteArray): String {
        val digest = java.security.MessageDigest.getInstance("SHA-256").digest(bytes)
        val sb = StringBuilder(digest.size * 2)
        for (b in digest) {
            sb.append(String.format("%02x", b))
        }
        return sb.toString()
    }

    /**
     * Fan out a captured JPEG frame concurrently across all configured targets (PC 8766, Android peer 8769, Relay).
     */
    internal suspend fun transmitFrameToTargets(
        targets: List<ScreenTargetEndpoint>,
        frameBytes: ByteArray,
        sessionId: String,
        width: Int,
        height: Int,
        fps: Float,
        senderDeviceId: String,
        senderName: String,
        frameSeq: Long
    ): Boolean {
        val targetHook = mockTargetFramePoster
        val legacyHook = mockFramePoster
        val effectiveTargets = targets.ifEmpty {
            listOf(ScreenTargetEndpoint(deviceId = "", host = "", transferPort = 8766, useRelay = relayMediaSender != null))
        }

        if (targetHook != null || legacyHook != null) {
            return coroutineScope {
                effectiveTargets.map { endpoint ->
                    async(Dispatchers.IO) {
                        try {
                            targetHook?.invoke(endpoint, frameBytes, sessionId, width, height, fps)
                                ?: legacyHook?.invoke(frameBytes, sessionId, width, height, fps)
                                ?: false
                        } catch (_: Exception) {
                            false
                        }
                    }
                }.awaitAll().any { it }
            }
        }

        val transferClient = transferClientProvider()
        return coroutineScope {
            targets.map { endpoint ->
                async(Dispatchers.IO) {
                    try {
                        val targetMeta = mapOf(
                            "sender_device_id" to senderDeviceId,
                            "sender_name" to senderName,
                            "sender_platform" to "android",
                            "session_id" to sessionId,
                            "frame_seq" to frameSeq,
                            "frame_width" to width,
                            "frame_height" to height,
                            "fps" to fps,
                            "target_device_id" to endpoint.deviceId,
                            "target_device_ids" to listOf(endpoint.deviceId).filter { it.isNotBlank() }.ifEmpty { targetDeviceIds }
                        )
                        var ok = false
                        if (endpoint.useRelay || (legacyFallbackRelayEnabled && relayMediaSender != null)) {
                            ok = relayMediaSenderForTarget?.invoke(endpoint, targetMeta, frameBytes)
                                ?: relayMediaSender?.invoke(targetMeta, frameBytes)
                                ?: false
                        }
                        if (!ok && !endpoint.useRelay &&
                            endpoint.host.isNotBlank() &&
                            !endpoint.host.startsWith("ws://", ignoreCase = true) &&
                            !endpoint.host.startsWith("wss://", ignoreCase = true)
                        ) {
                            ok = transferClient?.postScreenFrame(
                                serverHost = endpoint.host,
                                transferPort = endpoint.transferPort,
                                frameBytes = frameBytes,
                                sessionId = sessionId,
                                width = width,
                                height = height,
                                fps = fps,
                                senderId = senderDeviceId.ifBlank { null },
                                senderName = senderName,
                                senderPlatform = "android",
                                frameSeq = frameSeq,
                                targetDeviceIds = listOf(endpoint.deviceId).filter { it.isNotBlank() }.ifEmpty { targetDeviceIds }
                            ) ?: false
                        }
                        ok
                    } catch (e: Exception) {
                        SafeLog.w(TAG, "Frame push to ${endpoint.deviceId}/${endpoint.host}:${endpoint.transferPort} failed: ${e.message}")
                        false
                    }
                }
            }.awaitAll().any { it }
        }
    }

    private suspend fun sendStopSignalsToTargets(targets: List<ScreenTargetEndpoint>) {
        val transferClient = transferClientProvider() ?: return
        coroutineScope {
            targets.filter {
                !it.useRelay &&
                    it.host.isNotBlank() &&
                    !it.host.startsWith("ws://", ignoreCase = true) &&
                    !it.host.startsWith("wss://", ignoreCase = true)
            }.distinctBy { "${it.host}:${it.transferPort}" }.map { endpoint ->
                async(Dispatchers.IO) {
                    try {
                        transferClient.postScreenStreamStop(endpoint.host, endpoint.transferPort)
                    } catch (e: Exception) {
                        SafeLog.w(TAG, "Could not send stop frame signal to ${endpoint.host}:${endpoint.transferPort}: ${e.message}")
                    }
                }
            }.awaitAll()
        }
    }

    /**
     * Continuous frame loop running on Dispatchers.IO.
     */
    private fun startFrameLoop(
        reader: ImageReader,
        width: Int,
        height: Int,
        fps: Float,
        targets: List<ScreenTargetEndpoint>,
        sessionId: String,
        senderDeviceId: String = "",
        senderName: String = "Android Phone"
    ) {
        frameLoopJob?.cancel()
        val intervalMs = (1000f / fps).toLong().coerceAtLeast(200L)

        frameLoopJob = handlerScope.launch {
            var frameCount = 0L
            var totalBytesSent = 0L
            var dedupSkips = 0L
            var zeroPauses = 0L

            while (isActive && _streamState.value == StreamState.STREAMING) {
                val loopStartTime = System.currentTimeMillis()

                try {
                    if (activeViewerCount <= 0) {
                        zeroPauses++
                        wasPausedZeroViewers = true
                        lastFrameSha256 = null
                        _stats.value = _stats.value.copy(zeroViewerPauses = zeroPauses)
                        delay(intervalMs)
                        continue
                    }

                    // 1. Acquire frame bytes (either from test hook or live ImageReader)
                    val frameBytes: ByteArray? = if (mockFrameProvider != null) {
                        val mockRaw = mockFrameProvider!!.invoke()
                        if (mockRaw != null) {
                            val mockHash = sha256Hex(mockRaw)
                            if (!wasPausedZeroViewers && lastDims == Pair(width, height) && mockHash == lastFrameSha256) {
                                dedupSkips++
                                _stats.value = _stats.value.copy(deduplicatedSkips = dedupSkips)
                                null
                            } else {
                                lastDims = Pair(width, height)
                                wasPausedZeroViewers = false
                                lastFrameSha256 = mockHash
                                mockRaw
                            }
                        } else null
                    } else {
                        val res = acquireLatestFrameJpegWithDedup(reader, width, height)
                        if (res == null && _stats.value.deduplicatedSkips != dedupSkips) {
                            dedupSkips = _stats.value.deduplicatedSkips
                        }
                        res
                    }

                    if (frameBytes != null && frameBytes.isNotEmpty()) {
                        if (frameBytes.size.toLong() <= MAX_FRAME_BYTES) {
                            frameSeqCounter++
                            val seq = frameSeqCounter
                            // 2. Transmit frame concurrently across all selected targets
                            val sent = transmitFrameToTargets(
                                targets = targets,
                                frameBytes = frameBytes,
                                sessionId = sessionId,
                                width = width,
                                height = height,
                                fps = fps,
                                senderDeviceId = senderDeviceId,
                                senderName = senderName,
                                frameSeq = seq
                            )

                            if (sent) {
                                frameCount++
                                totalBytesSent += frameBytes.size
                                _stats.value = StreamStats(
                                    fps = fps,
                                    frameCount = frameCount,
                                    totalBytes = totalBytesSent,
                                    lastFrameTimestamp = System.currentTimeMillis(),
                                    frameWidth = width,
                                    frameHeight = height,
                                    deduplicatedSkips = dedupSkips,
                                    zeroViewerPauses = zeroPauses
                                )
                            }
                        } else {
                            SafeLog.w(TAG, "Skipping frame: size ${frameBytes.size} exceeds $MAX_FRAME_BYTES limit.")
                        }
                    }

                } catch (e: Exception) {
                    SafeLog.w(TAG, "Frame capture error: ${e.message}")
                }

                // Maintain target FPS pace
                val elapsed = System.currentTimeMillis() - loopStartTime
                val delayTime = (intervalMs - elapsed).coerceAtLeast(50L)
                delay(delayTime)
            }
        }
    }

    private fun acquireLatestFrameJpegWithDedup(reader: ImageReader, width: Int, height: Int): ByteArray? {
        val image = try {
            reader.acquireLatestImage() ?: return null
        } catch (_: Exception) {
            return null
        }

        var rawBitmap: Bitmap? = null
        var cleanBitmap: Bitmap? = null
        try {
            val planes = image.planes
            if (planes.isEmpty()) return null
            val buffer = planes[0].buffer
            val pixelStride = planes[0].pixelStride
            val rowStride = planes[0].rowStride
            val rowPadding = rowStride - pixelStride * width

            val dup = buffer.duplicate()
            val rawBytes = ByteArray(dup.remaining())
            dup.get(rawBytes)
            val dims = Pair(width, height)
            val hash = sha256Hex(rawBytes)
            if (!wasPausedZeroViewers && lastDims == dims && hash == lastFrameSha256) {
                val skips = _stats.value.deduplicatedSkips + 1L
                _stats.value = _stats.value.copy(deduplicatedSkips = skips)
                return null
            }

            rawBitmap = Bitmap.createBitmap(
                width + rowPadding / pixelStride,
                height,
                Bitmap.Config.ARGB_8888
            )
            buffer.rewind()
            rawBitmap.copyPixelsFromBuffer(buffer)

            cleanBitmap = if (rowPadding != 0) {
                Bitmap.createBitmap(rawBitmap, 0, 0, width, height)
            } else {
                rawBitmap
            }

            synchronized(reusableBaos) {
                reusableBaos.reset()
                cleanBitmap.compress(Bitmap.CompressFormat.JPEG, JPEG_QUALITY, reusableBaos)
                lastDims = dims
                wasPausedZeroViewers = false
                lastFrameSha256 = hash
                return reusableBaos.toByteArray()
            }
        } catch (e: Exception) {
            SafeLog.w(TAG, "Bitmap processing error: ${e.message}")
            return null
        } finally {
            try {
                if (cleanBitmap != null && cleanBitmap !== rawBitmap && !cleanBitmap.isRecycled) {
                    cleanBitmap.recycle()
                }
            } catch (_: Exception) {}
            try {
                if (rawBitmap != null && !rawBitmap.isRecycled) {
                    rawBitmap.recycle()
                }
            } catch (_: Exception) {}
            try {
                image.close()
            } catch (_: Exception) {}
        }
    }

    /**
     * Stop streaming and release all underlying system resources cleanly.
     * Idempotent: safe to invoke repeatedly.
     */
    fun stopStreaming(serverHost: String? = null, transferPort: Int = 8766) {
        synchronized(this) {
            if (_streamState.value == StreamState.STOPPED || _streamState.value == StreamState.IDLE) {
                return
            }
            _streamState.value = StreamState.STOPPING
        }

        val stopTargets = buildList {
            addAll(activeTargets)
            if (!serverHost.isNullOrBlank()) {
                add(ScreenTargetEndpoint(deviceId = "", host = serverHost.trim(), transferPort = transferPort, useRelay = false))
            }
        }

        cleanup(isExplicitStop = true)
        lastFrameSha256 = null
        lastDims = null
        wasPausedZeroViewers = false
        frameSeqCounter = 0L
        targetDeviceIds = emptyList()
        activeTargets = emptyList()
        legacyFallbackRelayEnabled = false

        // Inform all streaming target servers of stream termination
        if (stopTargets.isNotEmpty()) {
            handlerScope.launch {
                sendStopSignalsToTargets(stopTargets)
            }
        }

        _streamState.value = StreamState.STOPPED
        SafeLog.i(TAG, "Screen streaming stopped cleanly.")
    }

    private fun cleanup(isExplicitStop: Boolean = false) {
        try {
            frameLoopJob?.cancel()
            frameLoopJob = null

            virtualDisplay?.release()
            virtualDisplay = null

            imageReader?.close()
            imageReader = null

            val callback = projectionCallback
            val proj = activeMediaProjection
            if (callback != null && proj != null) {
                try {
                    proj.unregisterCallback(callback)
                } catch (_: Exception) {}
            }
            projectionCallback = null

            if (isExplicitStop && proj != null) {
                try {
                    proj.stop()
                } catch (_: Exception) {}
            }
            activeMediaProjection = null
        } catch (e: Exception) {
            SafeLog.w(TAG, "Cleanup exception: ${e.message}")
        }
    }

    /**
     * Scale dimensions so that the longer edge is <= maxLongEdge while preserving aspect ratio.
     * Dimensions are aligned to multiples of 2.
     */
    private fun computeScaledDimensions(rawWidth: Int, rawHeight: Int, maxLongEdge: Int): Pair<Int, Int> {
        val w = if (rawWidth <= 0) 720 else rawWidth
        val h = if (rawHeight <= 0) 1280 else rawHeight

        val longEdge = maxOf(w, h)
        if (longEdge <= maxLongEdge) {
            return Pair(w / 2 * 2, h / 2 * 2)
        }

        val scale = maxLongEdge.toFloat() / longEdge.toFloat()
        val scaledWidth = (w * scale).toInt() / 2 * 2
        val scaledHeight = (h * scale).toInt() / 2 * 2
        return Pair(maxOf(scaledWidth, 160), maxOf(scaledHeight, 160))
    }
}
