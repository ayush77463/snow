package org.snow.capabilities

import android.graphics.Bitmap
import android.graphics.BitmapFactory
import org.snow.security.SafeLog
import java.io.File
import java.security.MessageDigest

/**
 * Deterministic canonical image digest matching Python's `compute_canonical_image_digest`:
 *
 * `SHA-256("${width}x${height}:" + unpremultiplied RGBA pixel bytes)`
 *
 * Rejects invalid dimensions (> 8192) or aggregate pixel counts (> 33,554,432) cleanly
 * and streams rows into SHA-256 to avoid duplicating full RGBA buffers on mobile.
 */
object CanonicalImageDigest {
    private const val TAG = "CanonicalImageDigest"
    const val MAX_DIMENSION = 8192
    const val MAX_PIXEL_COUNT = 33_554_432L

    data class DecodedRgbaImage(
        val width: Int,
        val height: Int,
        val rgbaBytes: ByteArray
    )

    fun interface ImagePixelDecoder {
        fun decode(file: File): DecodedRgbaImage?
    }

    @Volatile
    var fileDecoderOverrideForTest: ImagePixelDecoder? = null

    fun isValidDimensions(width: Int, height: Int): Boolean {
        if (width <= 0 || height <= 0) return false
        if (width > MAX_DIMENSION || height > MAX_DIMENSION) return false
        return width.toLong() * height.toLong() <= MAX_PIXEL_COUNT
    }

    @JvmStatic
    fun computeFromRgbaPixels(width: Int, height: Int, rgbaBytes: ByteArray): String? {
        if (!isValidDimensions(width, height)) return null
        val expectedBytes = width.toLong() * height.toLong() * 4L
        if (expectedBytes > Int.MAX_VALUE.toLong() || rgbaBytes.size.toLong() != expectedBytes) {
            return null
        }
        return try {
            val md = MessageDigest.getInstance("SHA-256")
            md.update("${width}x${height}:".toByteArray(Charsets.US_ASCII))
            md.update(rgbaBytes)
            md.digest().joinToString("") { "%02x".format(it) }
        } catch (_: Throwable) {
            null
        }
    }

    @JvmStatic
    fun computeFromArgbInts(width: Int, height: Int, argbPixels: IntArray): String? {
        if (!isValidDimensions(width, height)) return null
        val totalPixels = width.toLong() * height.toLong()
        if (totalPixels > Int.MAX_VALUE.toLong() || argbPixels.size.toLong() != totalPixels) {
            return null
        }
        return try {
            val md = MessageDigest.getInstance("SHA-256")
            md.update("${width}x${height}:".toByteArray(Charsets.US_ASCII))
            val rowRgba = ByteArray(width * 4)
            for (y in 0 until height) {
                val rowStart = y * width
                for (x in 0 until width) {
                    val argb = argbPixels[rowStart + x]
                    val outIdx = x * 4
                    rowRgba[outIdx] = ((argb ushr 16) and 0xFF).toByte()
                    rowRgba[outIdx + 1] = ((argb ushr 8) and 0xFF).toByte()
                    rowRgba[outIdx + 2] = (argb and 0xFF).toByte()
                    rowRgba[outIdx + 3] = ((argb ushr 24) and 0xFF).toByte()
                }
                md.update(rowRgba)
            }
            md.digest().joinToString("") { "%02x".format(it) }
        } catch (_: Throwable) {
            null
        }
    }

    @JvmStatic
    fun computeFromBitmap(bitmap: Bitmap?): String? {
        if (bitmap == null || bitmap.isRecycled) return null
        val width = try { bitmap.width } catch (_: Throwable) { 0 }
        val height = try { bitmap.height } catch (_: Throwable) { 0 }
        if (!isValidDimensions(width, height)) return null

        return try {
            val md = MessageDigest.getInstance("SHA-256")
            md.update("${width}x${height}:".toByteArray(Charsets.US_ASCII))
            val rowPixels = IntArray(width)
            val rowRgba = ByteArray(width * 4)
            for (y in 0 until height) {
                bitmap.getPixels(rowPixels, 0, width, 0, y, width, 1)
                for (x in 0 until width) {
                    val argb = rowPixels[x]
                    val outIdx = x * 4
                    rowRgba[outIdx] = ((argb ushr 16) and 0xFF).toByte()
                    rowRgba[outIdx + 1] = ((argb ushr 8) and 0xFF).toByte()
                    rowRgba[outIdx + 2] = (argb and 0xFF).toByte()
                    rowRgba[outIdx + 3] = ((argb ushr 24) and 0xFF).toByte()
                }
                md.update(rowRgba)
            }
            md.digest().joinToString("") { "%02x".format(it) }
        } catch (t: Throwable) {
            SafeLog.w(TAG, "Failed hashing bitmap pixels: ${t.message}")
            null
        }
    }

    @JvmStatic
    fun computeFromFile(file: File?, decoderOverride: ImagePixelDecoder? = null): String? {
        if (file == null || !file.isFile || file.length() <= 0L) return null
        val effectiveDecoder = decoderOverride ?: fileDecoderOverrideForTest
        if (effectiveDecoder != null) {
            val decoded = try {
                effectiveDecoder.decode(file)
            } catch (_: Throwable) {
                null
            } ?: return null
            return computeFromRgbaPixels(decoded.width, decoded.height, decoded.rgbaBytes)
        }

        var decodedBitmap: Bitmap? = null
        return try {
            val boundsOpts = BitmapFactory.Options().apply {
                inJustDecodeBounds = true
            }
            BitmapFactory.decodeFile(file.absolutePath, boundsOpts)
            val w = boundsOpts.outWidth
            val h = boundsOpts.outHeight
            if (!isValidDimensions(w, h)) return null

            val decodeOpts = BitmapFactory.Options().apply {
                inJustDecodeBounds = false
                inPreferredConfig = Bitmap.Config.ARGB_8888
                inScaled = false
                inPremultiplied = false
            }
            decodedBitmap = BitmapFactory.decodeFile(file.absolutePath, decodeOpts)
            if (decodedBitmap == null) return null
            computeFromBitmap(decodedBitmap)
        } catch (oom: OutOfMemoryError) {
            SafeLog.w(TAG, "OOM computing canonical digest for ${file.name}: ${oom.message}")
            null
        } catch (t: Throwable) {
            SafeLog.w(TAG, "Failed computing canonical digest for ${file.name}: ${t.message}")
            null
        } finally {
            try {
                decodedBitmap?.recycle()
            } catch (_: Throwable) {
            }
        }
    }

    @JvmStatic
    fun computeFromBytes(bytes: ByteArray?): String? {
        if (bytes == null || bytes.isEmpty()) return null
        var decodedBitmap: Bitmap? = null
        return try {
            val boundsOpts = BitmapFactory.Options().apply {
                inJustDecodeBounds = true
            }
            BitmapFactory.decodeByteArray(bytes, 0, bytes.size, boundsOpts)
            val w = boundsOpts.outWidth
            val h = boundsOpts.outHeight
            if (!isValidDimensions(w, h)) return null

            val decodeOpts = BitmapFactory.Options().apply {
                inJustDecodeBounds = false
                inPreferredConfig = Bitmap.Config.ARGB_8888
                inScaled = false
                inPremultiplied = false
            }
            decodedBitmap = BitmapFactory.decodeByteArray(bytes, 0, bytes.size, decodeOpts)
            if (decodedBitmap == null) return null
            computeFromBitmap(decodedBitmap)
        } catch (oom: OutOfMemoryError) {
            SafeLog.w(TAG, "OOM computing canonical digest from byte array: ${oom.message}")
            null
        } catch (t: Throwable) {
            SafeLog.w(TAG, "Failed computing canonical digest from byte array: ${t.message}")
            null
        } finally {
            try {
                decodedBitmap?.recycle()
            } catch (_: Throwable) {
            }
        }
    }
}
