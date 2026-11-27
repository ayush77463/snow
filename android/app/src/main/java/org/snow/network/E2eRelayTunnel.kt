package org.snow.network

import org.snow.security.SafeLog
import org.snow.security.TlsConfig
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.security.cert.X509Certificate
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLEngine
import javax.net.ssl.SSLEngineResult
import javax.net.ssl.SSLEngineResult.HandshakeStatus

/**
 * End-to-End Encrypted TLS 1.3 Tunnel for Android Peer over Untrusted SNOW Relays.
 *
 * Drives an in-memory SSLEngine with ByteBuffers to mutually authenticate and
 * encrypt application data without trusting the intermediate relay host.
 */
class E2eRelayTunnel(
    sslContext: SSLContext,
    val isServer: Boolean = false,
    val expectedPeerFingerprint: String? = null
) {
    companion object {
        private const val TAG = "E2eRelayTunnel"
        const val MAX_FRAME_SIZE = 25 * 1024 * 1024 // 25 MiB
        private const val INITIAL_BUFFER_CAPACITY = 32 * 1024
    }

    val engine: SSLEngine = sslContext.createSSLEngine().apply {
        useClientMode = !isServer
        if (isServer && expectedPeerFingerprint != null) {
            needClientAuth = true
        }
        // Support TLS 1.3 with TLS 1.2 compatibility
        val supported = supportedProtocols.toSet()
        val requested = listOf("TLSv1.3", "TLSv1.2").filter { supported.contains(it) }
        if (requested.isNotEmpty()) {
            enabledProtocols = requested.toTypedArray()
        }
    }

    @Volatile
    var handshakeDone: Boolean = false
        private set

    var peerFingerprint: String? = null
        private set

    private var inNetBuffer: ByteBuffer = ByteBuffer.allocate(INITIAL_BUFFER_CAPACITY)

    init {
        // Begin handshake for both client and server roles
        engine.beginHandshake()
    }

    /**
     * Feed incoming raw network ciphertext bytes received from the relay.
     */
    @Synchronized
    fun feedNetworkData(bytes: ByteArray) {
        if (bytes.isEmpty()) return
        if (bytes.size > MAX_FRAME_SIZE) {
            throw IllegalArgumentException("Incoming frame exceeds 25 MiB maximum limit: ${bytes.size} bytes")
        }

        val required = inNetBuffer.position() + bytes.size
        if (required > inNetBuffer.capacity()) {
            val newCapacity = minOf(MAX_FRAME_SIZE, maxOf(inNetBuffer.capacity() * 2, required))
            val expanded = ByteBuffer.allocate(newCapacity)
            inNetBuffer.flip()
            expanded.put(inNetBuffer)
            inNetBuffer = expanded
        }
        inNetBuffer.put(bytes)
    }

    /**
     * Drive the TLS handshake forward.
     * Returns Pair(isHandshakeDone, outgoingBytesToSendToRelay).
     */
    @Synchronized
    fun driveHandshake(): Pair<Boolean, ByteArray> {
        val outStream = ByteArrayOutputStream()
        val emptyApp = ByteBuffer.allocate(0)
        val packetSize = maxOf(engine.session.packetBufferSize, 16384)
        val netOut = ByteBuffer.allocate(packetSize * 2)
        val appOut = ByteBuffer.allocate(maxOf(engine.session.applicationBufferSize, 16384) * 2)

        var loop = true
        while (loop && !handshakeDone) {
            val status = engine.handshakeStatus
            if (status == HandshakeStatus.FINISHED) {
                verifyPeerCertificate()
                handshakeDone = true
                break
            } else if (status == HandshakeStatus.NOT_HANDSHAKING) {
                // In SSLEngine, NOT_HANDSHAKING can occur after completion or before initial data.
                // Complete ONLY if session negotiated a valid cipher suite!
                val cipher = engine.session.cipherSuite
                if (cipher != null && cipher != "SSL_NULL_WITH_NULL_NULL") {
                    verifyPeerCertificate()
                    handshakeDone = true
                }
                break
            }

            when (status) {
                HandshakeStatus.NEED_TASK -> {
                    while (true) {
                        val task = engine.delegatedTask ?: break
                        task.run()
                    }
                }
                HandshakeStatus.NEED_WRAP -> {
                    netOut.clear()
                    val res = engine.wrap(emptyApp, netOut)
                    netOut.flip()
                    if (netOut.hasRemaining()) {
                        val chunk = ByteArray(netOut.remaining())
                        netOut.get(chunk)
                        outStream.write(chunk)
                    }
                    if (res.status == SSLEngineResult.Status.CLOSED && !handshakeDone) {
                        throw SecurityException("E2E TLS handshake closed before completion.")
                    }
                    if (res.handshakeStatus == HandshakeStatus.FINISHED) {
                        verifyPeerCertificate()
                        handshakeDone = true
                        break
                    }
                }
                HandshakeStatus.NEED_UNWRAP -> {
                    inNetBuffer.flip()
                    if (!inNetBuffer.hasRemaining()) {
                        inNetBuffer.compact()
                        loop = false
                        break
                    }
                    appOut.clear()
                    val res = engine.unwrap(inNetBuffer, appOut)
                    inNetBuffer.compact()

                    if (res.status == SSLEngineResult.Status.CLOSED && !handshakeDone) {
                        throw SecurityException("E2E TLS handshake rejected or closed before completion.")
                    }
                    if (res.status == SSLEngineResult.Status.BUFFER_UNDERFLOW) {
                        loop = false
                        break
                    }
                    if (res.handshakeStatus == HandshakeStatus.FINISHED) {
                        verifyPeerCertificate()
                        handshakeDone = true
                        break
                    }
                }
                else -> {
                    loop = false
                    break
                }
            }
        }

        return Pair(handshakeDone, outStream.toByteArray())
    }

    /**
     * Encrypt plaintext application data into TLS record bytes for transmission.
     */
    @Synchronized
    fun encryptApplicationData(plaintext: ByteArray): ByteArray {
        if (!handshakeDone) {
            throw IllegalStateException("Cannot encrypt application data: TLS handshake not completed.")
        }
        if (plaintext.size > MAX_FRAME_SIZE) {
            throw IllegalArgumentException("Plaintext exceeds 25 MiB maximum: ${plaintext.size} bytes")
        }

        val appIn = ByteBuffer.wrap(plaintext)
        val packetSize = maxOf(engine.session.packetBufferSize, 16384)
        val netOut = ByteBuffer.allocate(packetSize * 2)
        val outStream = ByteArrayOutputStream()

        while (appIn.hasRemaining()) {
            netOut.clear()
            val res = engine.wrap(appIn, netOut)
            netOut.flip()
            if (netOut.hasRemaining()) {
                val chunk = ByteArray(netOut.remaining())
                netOut.get(chunk)
                outStream.write(chunk)
            }
            if (res.status != SSLEngineResult.Status.OK) {
                break
            }
        }
        return outStream.toByteArray()
    }

    /**
     * Decrypt any available TLS ciphertext from inNetBuffer into plaintext bytes.
     */
    @Synchronized
    fun decryptApplicationData(): ByteArray {
        if (!handshakeDone) return ByteArray(0)

        val outStream = ByteArrayOutputStream()
        val appSize = maxOf(engine.session.applicationBufferSize, 16384)
        val appOut = ByteBuffer.allocate(appSize * 2)

        inNetBuffer.flip()
        while (inNetBuffer.hasRemaining()) {
            appOut.clear()
            val res = engine.unwrap(inNetBuffer, appOut)
            appOut.flip()
            if (appOut.hasRemaining()) {
                val chunk = ByteArray(appOut.remaining())
                appOut.get(chunk)
                outStream.write(chunk)
            }
            if (res.status == SSLEngineResult.Status.BUFFER_UNDERFLOW) {
                break
            }
            if (res.bytesProduced() == 0 && res.bytesConsumed() == 0) {
                break
            }
        }
        inNetBuffer.compact()
        return outStream.toByteArray()
    }

    /**
     * Initiate clean TLS shutdown and return closure alert bytes.
     */
    @Synchronized
    fun closeOutbound(): ByteArray {
        engine.closeOutbound()
        val emptyApp = ByteBuffer.allocate(0)
        val packetSize = maxOf(engine.session.packetBufferSize, 16384)
        val netOut = ByteBuffer.allocate(packetSize * 2)
        val outStream = ByteArrayOutputStream()
        while (!engine.isOutboundDone) {
            netOut.clear()
            val res = engine.wrap(emptyApp, netOut)
            netOut.flip()
            if (netOut.hasRemaining()) {
                val chunk = ByteArray(netOut.remaining())
                netOut.get(chunk)
                outStream.write(chunk)
            }
            if (res.status == SSLEngineResult.Status.CLOSED) {
                break
            }
        }
        return outStream.toByteArray()
    }

    private fun verifyPeerCertificate() {
        val certs = try {
            engine.session.peerCertificates
        } catch (e: Exception) {
            if (expectedPeerFingerprint != null) {
                SafeLog.e(TAG, "Peer certificate required for mutual authentication, but none presented: ${e.message}")
                throw SecurityException("Peer certificate required for mutual authentication, but none presented: ${e.message}")
            }
            null
        }

        if (certs != null && certs.isNotEmpty() && certs[0] is X509Certificate) {
            val presented = TlsConfig.computeSha256Fingerprint(certs[0] as X509Certificate)
            peerFingerprint = presented
            if (expectedPeerFingerprint != null) {
                if (!TlsConfig.fingerprintsMatch(expectedPeerFingerprint, presented)) {
                    SafeLog.e(TAG, "Relay peer fingerprint mismatch! Expected: $expectedPeerFingerprint, Got: $presented")
                    throw SecurityException("Certificate fingerprint mismatch! Expected: $expectedPeerFingerprint, Presented: $presented")
                }
            }
        } else if (expectedPeerFingerprint != null) {
            throw SecurityException("Peer certificate missing during mutual authentication!")
        }
    }
}
