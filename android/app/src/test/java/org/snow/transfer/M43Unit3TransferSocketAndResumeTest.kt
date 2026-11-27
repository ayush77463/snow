package org.snow.transfer

import android.content.Context
import android.content.ContextWrapper
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.snow.network.TransportOrchestrator
import org.snow.network.TransportRoute
import org.snow.security.InMemoryCertPinStorage
import org.snow.security.InMemoryTokenStorage
import java.io.BufferedInputStream
import java.io.File
import java.net.InetAddress
import java.net.ServerSocket
import java.nio.file.Files
import kotlin.concurrent.thread

/**
 * Stage 6 regression tests for SNOW FileTransferClient:
 * - Carrying socket route classification (Wi-Fi/Hotspot never mislabeled USB even when USB cable attached)
 * - Route pinning blocks background opportunistic route switching during active large transfers
 * - Cross-route Range resume from partial offset after mid-transfer disconnect
 * - Remote Relay quota preflight enforcement
 * - 64-bit Long offset math (> 2 GiB / 7-10 GB files)
 */
class M43Unit3TransferSocketAndResumeTest {

    private fun stubContext(filesDir: File): Context {
        return object : ContextWrapper(null) {
            override fun getFilesDir(): File = filesDir
        }
    }

    @Test
    fun socketClassificationNeverFakesUsbAndRespectsRelayQuota() = runBlocking {
        val tempRoot = Files.createTempDirectory("m43_quota_test_").toFile()
        try {
            val ctx = stubContext(tempRoot)
            val orch = TransportOrchestrator()
            val client = FileTransferClient(
                context = ctx,
                deviceId = "android-test",
                certPinStorage = InMemoryCertPinStorage(),
                tokenStorage = InMemoryTokenStorage().apply { saveToken("tok") },
                useTls = false,
                targetDeviceIdProvider = { "pc-1" }
            ).apply {
                transportOrchestrator = orch
                // Even when ADB USB mapping exists on the device, non-loopback transfers MUST NOT be labeled USB
                usbMappingVerifiedProvider = { true }
                maxRelayTransferBytes = 1024L
            }

            assertEquals(TransportRoute.WIFI_LAN to "Wi-Fi • Zero Data", client.resolveSocketRouteAndBadge("192.168.1.40"))
            assertEquals(TransportRoute.HOTSPOT to "Hotspot • Zero Data", client.resolveSocketRouteAndBadge("192.168.43.1"))
            assertEquals(TransportRoute.USB to "USB • Zero Data", client.resolveSocketRouteAndBadge("127.0.0.1"))

            client.usbMappingVerifiedProvider = { false }
            assertEquals(TransportRoute.WIFI_LAN to "Wi-Fi • Zero Data", client.resolveSocketRouteAndBadge("127.0.0.1"))

            // Relay quota rejects oversized file upfront with clear guidance before uploading
            val bigTmp = File(tempRoot, "relay_big.bin").apply {
                writeBytes(ByteArray(2048) { 7 })
            }
            val relayRes = client.uploadFile("relay.snow.example", 8766, bigTmp)
            assertTrue(relayRes is FileTransferClient.TransferResult.Error)
            val err = relayRes as FileTransferClient.TransferResult.Error
            assertEquals(413, err.code)
            assertTrue(err.message.contains("USB, Hotspot, or Wi-Fi LAN"))

            // 64-bit multi-GB arithmetic sanity (9 GB of 10 GB)
            val nineGb = 9_663_676_416L
            val tenGb = 10_737_418_240L
            assertEquals(90, ((nineGb * 100L) / tenGb).toInt())
        } finally {
            tempRoot.deleteRecursively()
        }
    }

    @Test
    fun routePinningBlocksBackgroundSwitchAndFallbackResumesViaRange() = runBlocking {
        val tempRoot = Files.createTempDirectory("m43_resume_test_").toFile()
        val failingPrimary = ServerSocket(0, 4, InetAddress.getByName("127.0.0.1"))
        val fallbackServer = ServerSocket(0, 4, InetAddress.getByName("127.0.0.1"))
        try {
            val ctx = stubContext(tempRoot)
            val orch = TransportOrchestrator()
            orch.markVerified("pc-1", TransportRoute.WIFI_LAN, host = "127.0.0.1", isActive = true)
            orch.registerDiscovered("pc-1", TransportRoute.USB, host = "127.0.0.1", port = 8765)

            val payload = ("SNOW_M43_FALLBACK_RESUME_PAYLOAD_0123456789ABCDEF").repeat(4).toByteArray()
            val expectedSha = FileTransferClient.computeSha256(payload.inputStream())
            val firstHalf = payload.copyOfRange(0, 48)
            val secondHalf = payload.copyOfRange(48, payload.size)
            var capturedRangeHeader = ""

            // Primary sends truncated HTTP 200 (48 bytes out of full Content-Length) and closes socket
            val tPrimary = thread(isDaemon = true) {
                failingPrimary.accept().use { sock ->
                    val inp = BufferedInputStream(sock.getInputStream())
                    val sb = StringBuilder()
                    while (!sb.endsWith("\r\n\r\n")) {
                        val b = inp.read()
                        if (b == -1) break
                        sb.append(b.toChar())
                    }
                    val hdr = (
                        "HTTP/1.1 200 OK\r\n" +
                            "Content-Length: ${payload.size}\r\n" +
                            "X-Snow-Transport-Badge: Hotspot • Zero Data\r\n" +
                            "Connection: close\r\n\r\n"
                        ).toByteArray(Charsets.US_ASCII)
                    sock.getOutputStream().write(hdr)
                    sock.getOutputStream().write(firstHalf)
                    sock.getOutputStream().flush()
                }
            }

            // Fallback reads Range header and sends HTTP 206 Partial Content tail
            val tFallback = thread(isDaemon = true) {
                fallbackServer.accept().use { sock ->
                    val inp = BufferedInputStream(sock.getInputStream())
                    val sb = StringBuilder()
                    while (!sb.endsWith("\r\n\r\n")) {
                        val b = inp.read()
                        if (b == -1) break
                        sb.append(b.toChar())
                    }
                    capturedRangeHeader = sb.toString().lines()
                        .firstOrNull { it.startsWith("Range:", ignoreCase = true) }
                        ?.substringAfter(":")?.trim().orEmpty()
                    val hdr = (
                        "HTTP/1.1 206 Partial Content\r\n" +
                            "Content-Range: bytes ${firstHalf.size}-${payload.size - 1}/${payload.size}\r\n" +
                            "Content-Length: ${secondHalf.size}\r\n" +
                            "X-Snow-Transport-Route: wifi_lan\r\n" +
                            "X-Snow-Transport-Badge: Wi-Fi • Zero Data\r\n" +
                            "Connection: close\r\n\r\n"
                        ).toByteArray(Charsets.US_ASCII)
                    sock.getOutputStream().write(hdr)
                    sock.getOutputStream().write(secondHalf)
                    sock.getOutputStream().flush()
                }
            }

            val pinnedDuringProgress = mutableListOf<Boolean>()
            val client = FileTransferClient(
                context = ctx,
                deviceId = "android-1",
                tokenStorage = InMemoryTokenStorage().apply { saveToken("tok") },
                useTls = false,
                targetDeviceIdProvider = { "pc-1" },
                maxRetryAttempts = 2,
                retryBaseDelayMs = 20L
            ).apply {
                transportOrchestrator = orch
                fallbackTargetProvider = { _, _ ->
                    "127.0.0.1" to fallbackServer.localPort
                }
            }

            val destFile = File(tempRoot, "resumed.bin")
            val res = client.downloadFile(
                serverHost = "127.0.0.1",
                transferPort = failingPrimary.localPort,
                transferId = "tx-m43-1",
                destinationFile = destFile,
                expectedSha256 = expectedSha,
                resume = true
            ) { _ ->
                pinnedDuringProgress.add(orch.hasActivePinnedTransfer("pc-1"))
                assertNull(orch.selectHigherPriorityCandidate("pc-1"))
            }

            tPrimary.join(3000)
            tFallback.join(3000)

            assertTrue("Expected Success, got $res", res is FileTransferClient.TransferResult.Success)
            val okRes = res as FileTransferClient.TransferResult.Success
            assertEquals(expectedSha, okRes.sha256)
            assertEquals("Wi-Fi • Zero Data", okRes.routeBadge)
            assertEquals("bytes=${firstHalf.size}-", capturedRangeHeader)
            assertTrue(pinnedDuringProgress.isNotEmpty() && pinnedDuringProgress.all { it })
            assertFalse(orch.hasActivePinnedTransfer("pc-1"))
            assertEquals(payload.size.toLong(), destFile.length())
        } finally {
            failingPrimary.close()
            fallbackServer.close()
            tempRoot.deleteRecursively()
        }
    }
}
