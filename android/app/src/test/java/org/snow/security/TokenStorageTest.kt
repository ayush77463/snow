package org.snow.security

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class TokenStorageTest {

    @Test
    fun testInMemoryTokenStorageLifecycle() {
        val storage = InMemoryTokenStorage()

        assertFalse("Initially should have no token", storage.hasToken())
        assertNull("getToken should return null initially", storage.getToken())

        val testToken = "test-token-abcdef1234567890"
        storage.saveToken(testToken)

        assertTrue("Should have token after save", storage.hasToken())
        assertEquals(testToken, storage.getToken())

        storage.clearToken()

        assertFalse("Should not have token after clear", storage.hasToken())
        assertNull("getToken should return null after clear", storage.getToken())
    }

    @Test
    fun testBlankTokenTreatedAsEmpty() {
        val storage = InMemoryTokenStorage()
        storage.saveToken("   ")
        assertFalse("Blank token should not be considered valid", storage.hasToken())
    }
}
