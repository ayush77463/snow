package org.snow.transfer

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.File
import java.nio.charset.StandardCharsets
import java.security.MessageDigest

class FileTransferClientTest {

    @Test
    fun testComputeSha256FromInputStreamMatchesKnownVector() {
        val testData = "SNOW Phase 3 reliable file transfer".toByteArray(StandardCharsets.UTF_8)
        val expectedDigest = MessageDigest.getInstance("SHA-256")
            .digest(testData)
            .joinToString("") { "%02x".format(it) }

        val inputStream = ByteArrayInputStream(testData)
        val actualDigest = FileTransferClient.computeSha256(inputStream)

        assertEquals(64, actualDigest.length)
        assertEquals(expectedDigest, actualDigest)
    }

    @Test
    fun testComputeSha256FromFileMatchesKnownVector() {
        val testData = "Testing 64 KiB bounded chunk computation".toByteArray(StandardCharsets.UTF_8)
        val expectedDigest = MessageDigest.getInstance("SHA-256")
            .digest(testData)
            .joinToString("") { "%02x".format(it) }

        val tempFile = File.createTempFile("snow_test_", ".bin")
        try {
            tempFile.writeBytes(testData)
            val actualDigest = FileTransferClient.computeSha256(tempFile)
            assertEquals(expectedDigest, actualDigest)
        } finally {
            tempFile.delete()
        }
    }

    @Test
    fun testTransferProgressPercentCalculation() {
        val progress50 = FileTransferClient.TransferProgress(
            transferId = "tid-1",
            bytesTransferred = 500,
            totalBytes = 1000,
            percent = 50
        )
        assertEquals(50, progress50.percent)
        assertEquals(500, progress50.bytesTransferred)
        assertEquals(1000, progress50.totalBytes)

        val progress100 = FileTransferClient.TransferProgress(
            transferId = "tid-2",
            bytesTransferred = 65536,
            totalBytes = 65536,
            percent = 100
        )
        assertEquals(100, progress100.percent)
    }

    @Test
    fun testDuplicateCheckResultParsing() {
        val matchResult = FileTransferClient.DuplicateCheckResult(
            alreadyExists = true,
            isConflict = false,
            existingSha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
        assertTrue(matchResult.alreadyExists)
        assertFalse(matchResult.isConflict)
        assertEquals("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", matchResult.existingSha256)

        val conflictResult = FileTransferClient.DuplicateCheckResult(
            alreadyExists = false,
            isConflict = true,
            existingSha256 = "1111111111111111111111111111111111111111111111111111111111111111"
        )
        assertFalse(conflictResult.alreadyExists)
        assertTrue(conflictResult.isConflict)
    }
}
