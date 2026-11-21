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
        val frameHeight: Int = 0
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

    @Volatile
    private var currentSessionId: String? = null

    /**
     * Optional callback invoked when MediaProjection is revoked by OS,
     * allowing the service to demote its foreground notification state.
     */
    var onRevoked: (() -> Unit)? = null

    /**
     * Start continuous live screen streaming.
     */
    fun startStreaming(
        projection: MediaProjection,
        serverHost: String,
        transferPort: Int = 8766,
        targetFps: Float = DEFAULT_FPS
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

        val metrics = context.resources.displayMetrics
        val rawWidth = metrics.widthPixels
        val rawHeight = metrics.heightPixels
        val densityDpi = metrics.densityDpi

        // Scale to bounded dimensions (max long edge 720, preserving aspect ratio)
        val (targetWidth, targetHeight) = computeScaledDimensions(rawWidth, rawHeight, MAX_LONG_EDGE)

        SafeLog.i(TAG, "Initializing screen stream: ${targetWidth}x${targetHeight} @ ${clampedFps} FPS (session=$sessionId)")

        try {
            // Android 14+ requirement: register callback before creating VirtualDisplay
            val callback = object : MediaProjection.Callback() {
                override fun onStop() {
                    SafeLog.i(TAG, "MediaProjection revoked or stopped by OS.")
                    _streamState.value = StreamState.REVOKED
                    // Send desktop a metadata-only stop/status event with state="REVOKED"
                    if (serverHost.isNotBlank()) {
                        handlerScope.launch {
                            try {
                                val client = transferClientProvider()
                                client?.postScreenStreamStop(serverHost, transferPort)
                            } catch (e: Exception) {
                                SafeLog.w(TAG, "Could not send revoked signal: ${e.message}")
                            }
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

            // Start frame acquisition & transmission loop
            startFrameLoop(reader, targetWidth, targetHeight, clampedFps, serverHost, transferPort, sessionId)

        } catch (e: Exception) {
            SafeLog.e(TAG, "Failed starting screen stream: ${e.message}", e)
            _streamState.value = StreamState.ERROR
            cleanup()
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
        serverHost: String,
        transferPort: Int,
        sessionId: String
    ) {
        frameLoopJob?.cancel()
        val intervalMs = (1000f / fps).toLong().coerceAtLeast(200L)

        frameLoopJob = handlerScope.launch {
            var frameCount = 0L
            var totalBytesSent = 0L

            while (isActive && _streamState.value == StreamState.STREAMING) {
                val loopStartTime = System.currentTimeMillis()

                try {
                    // 1. Acquire frame bytes (either from test hook or live ImageReader)
                    val frameBytes: ByteArray? = if (mockFrameProvider != null) {
                        mockFrameProvider!!.invoke()
                    } else {
                        acquireLatestFrameJpeg(reader, width, height)
                    }

                    if (frameBytes != null && frameBytes.isNotEmpty()) {
                        if (frameBytes.size.toLong() <= MAX_FRAME_BYTES) {
                            // 2. Transmit frame over authenticated HTTPS (port 8766)
                            val sent = if (mockFramePoster != null) {
                                mockFramePoster!!.invoke(frameBytes, sessionId, width, height, fps)
                            } else {
                                val transferClient = transferClientProvider()
                                transferClient?.postScreenFrame(
                                    serverHost = serverHost,
                                    transferPort = transferPort,
                                    frameBytes = frameBytes,
                                    sessionId = sessionId,
                                    width = width,
                                    height = height,
                                    fps = fps
                                ) ?: false
                            }

                            if (sent) {
                                frameCount++
                                totalBytesSent += frameBytes.size
                                _stats.value = StreamStats(
                                    fps = fps,
                                    frameCount = frameCount,
                                    totalBytes = totalBytesSent,
                                    lastFrameTimestamp = System.currentTimeMillis(),
                                    frameWidth = width,
                                    frameHeight = height
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

    /**
     * Acquire the latest frame from the ImageReader and encode to bounded JPEG.
     */
    private fun acquireLatestFrameJpeg(reader: ImageReader, width: Int, height: Int): ByteArray? {
        val image = try {
            reader.acquireLatestImage() ?: return null
        } catch (e: Exception) {
            return null
        }

        try {
            val planes = image.planes
            if (planes.isEmpty()) return null
            val buffer = planes[0].buffer
            val pixelStride = planes[0].pixelStride
            val rowStride = planes[0].rowStride
            val rowPadding = rowStride - pixelStride * width

            val bitmap = Bitmap.createBitmap(
                width + rowPadding / pixelStride,
                height,
                Bitmap.Config.ARGB_8888
            )
            bitmap.copyPixelsFromBuffer(buffer)

            val cleanBitmap = if (rowPadding != 0) {
                val cropped = Bitmap.createBitmap(bitmap, 0, 0, width, height)
                bitmap.recycle()
                cropped
            } else {
                bitmap
            }

            val baos = ByteArrayOutputStream()
            cleanBitmap.compress(Bitmap.CompressFormat.JPEG, JPEG_QUALITY, baos)
            cleanBitmap.recycle()
            return baos.toByteArray()
        } catch (e: Exception) {
            SafeLog.w(TAG, "Bitmap processing error: ${e.message}")
            return null
        } finally {
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

        cleanup(isExplicitStop = true)

        // Inform desktop server of stream termination
        if (!serverHost.isNullOrBlank()) {
            handlerScope.launch {
                try {
                    val client = transferClientProvider()
                    client?.postScreenStreamStop(serverHost, transferPort)
                } catch (e: Exception) {
                    SafeLog.w(TAG, "Could not send stop frame signal: ${e.message}")
                }
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
