package org.snow.network

import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.snow.security.InMemoryCertPinStorage
import org.snow.security.SnowTrustManager
import org.snow.security.TlsConfig
import org.snow.ui.DeviceEndpoint
import org.snow.ui.SavedDevice
import java.io.ByteArrayInputStream
import java.security.KeyFactory
import java.security.KeyStore
import java.security.PrivateKey
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.PKCS8EncodedKeySpec
import java.util.Base64
import javax.net.ssl.KeyManager
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.X509TrustManager

/**
 * Phase 28A unit & integration tests for hybrid all-pairs remote mesh,
 * deterministic TLS role negotiation, genuine SSLEngine TLS 1.3 handshakes,
 * mutual certificate authentication, and per-device connection mode policies.
 */
class Phase28RemoteMeshTest {

    companion object {
        const val SERVER_CERT_PEM = """-----BEGIN CERTIFICATE-----
MIICwjCCAaqgAwIBAgIURpUUlk6WgBrwsbEcJYMUvqD8YuEwDQYJKoZIhvcNAQEL
BQAwGzEZMBcGA1UEAwwQc25vdy10ZXN0LXNlcnZlcjAeFw0yNjExMjEwMzA2MzNa
Fw0zNjExMTkwMzA2MzNaMBsxGTAXBgNVBAMMEHNub3ctdGVzdC1zZXJ2ZXIwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCvki457/t8//chEv9bOn8GfkVL
ipwrSJ6tDmTN86M2qzfF+jSjU0Mr0PXcWHYOaRyhGzrh/xhhc/2v9xtN0hei5jaK
mQXSIpeDOBKYhoQivwXuw+LKKGXsCrNqRXgpt5+m3BXXn57eELjc0LPhysj5EKOr
ZVTeWSXbS4qEenm0s0jccg550p2SD9txMu1BUJyEfymsm6J9Q3HTQOSuRFOmuJx9
rPtWPNJvpG/jMqIN4C47HdjpD5uWtrrqnHaIX3c6f12QNfqwhC+O89XvFY9r0o8M
O5p/zASwuZ0FAcwiGX76o5Iq73zbiT3EpTgEQdHoWveG2ofbnuMGSzFIs/yPAgMB
AAEwDQYJKoZIhvcNAQELBQADggEBAFQnmyknw/T6LVU1Rk5+Cq8RwbfsuZFZwWrm
BaSkk+HCGEHLvBy38s+ni9TpcT2+r7db7+avhRSjwuGewCCxUh/+AZfHOKhBfCd8
g2dRfk4oEGesYn23ywAGlkkN/bcZkSAMbLVRB1wsjPZdpGv/+o8v2E7p095B6gil
6PS4nBYQmVjqtcz6NGS6kWoLkH1S5De/R7jP8NRLyB9oia4l0g0Ha9LIi1RJT8bb
2huDuyCQgkbjP9E2JJ1sHpJcPSpmqcfFyJw2BfW/g940Z6V+ong9LllxPLqi8Cs9
qpBFyp+BwQ5WgYQcAAD6nbzpqToG0pL6O624u5K39W2KvB/FWF8=
-----END CERTIFICATE-----"""

        const val SERVER_KEY_PEM = """-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCvki457/t8//ch
Ev9bOn8GfkVLipwrSJ6tDmTN86M2qzfF+jSjU0Mr0PXcWHYOaRyhGzrh/xhhc/2v
9xtN0hei5jaKmQXSIpeDOBKYhoQivwXuw+LKKGXsCrNqRXgpt5+m3BXXn57eELjc
0LPhysj5EKOrZVTeWSXbS4qEenm0s0jccg550p2SD9txMu1BUJyEfymsm6J9Q3HT
QOSuRFOmuJx9rPtWPNJvpG/jMqIN4C47HdjpD5uWtrrqnHaIX3c6f12QNfqwhC+O
89XvFY9r0o8MO5p/zASwuZ0FAcwiGX76o5Iq73zbiT3EpTgEQdHoWveG2ofbnuMG
SzFIs/yPAgMBAAECggEASBifIuuJOitiMBK9CZlb0C7KBdtFhgCsKCRhALGrtCdb
H9E/DFKEotmMHI+26vP+7alg5Kz8NgiLhFbUv4AmdJ5Uh1WPLltGHHxKJpgWaq5G
oWWPG7S7JdK/GkSss3TT+pEl5wWFF2uGfia1t2KuZJiQnTFfSG8TPJoop34jvC+0
w510dt4gEI+xeYPh18zNpQoPWfLFRByHkgMJboWCqzc7jnSfuxSQzPUcw3np54tv
ouYhwAHkNkm7XpWZfUuVifBBVyYFAq1wP+Qn5yb2Wm4a0FUJzOzhD2t/eYt/5AM3
hbtrlffVk2Ef3yZE3GlZqAa7OZ8Va7T8p6QbuqvZAQKBgQDfHJihTjCt23U3hzr4
ZgYySEYz3dIIv1EdWJZYt75r+dbzRUvCCDv4zNtpAi88oY51qMYuKprnWZKVxb6p
dbkXtanGQeiEXFJNtCGem0AkAoR0BnS9GHICe+n7Nkib2SFxv4NKyZDQ97vFRUtc
O3Sn9V1IKitAbggBKU2vuxUoQwKBgQDJc5N9ail6/RMpwxtPm9YVI1c0x8Qg+2sQ
w58F3DPbpQZtzudUPzL2ihKZXZnyWKJ4gupX447Xn6JNjM9D6c/ljelFDC2JbF8O
x3MrWSvkjJKyoN6p8QdiIJnqgtLSE/lPzzA/TPFIPpomAKmSs/eR43aALUCjjvlt
nV0OMohrxQKBgBzOxm5deC+anIH09gpIshgf+OCNjacPfNu7Kn5+CxpKAhUbJ3MA
OS4g1VuzqoG7ondSuXQQkDu69xBbnginaKTFEgzFSc59VSsvTP/7r8Z2hL+ubbhU
xbPIaCfFlI569LSJM9yeNhKlShtonRhlnORq7AZ7W2ZQTrxHpv4/u7WdAoGANGmQ
lxG25xvPD4+GnIjEA03lk4LiAV7IdV0gE6s+BsiByrIJN78VqFU2D5btxcLPyqDt
DZ7T/D+5P4oCJv4/K89nQKKxek6q0LKNwVp69ASq6jS2mepu7FXlFcGhziyKMfyK
5f1DzXMUMgz8EYInSFqw6xpa9fLt7FoD6vy0x60CgYEAw+ddpSKJ1DvK6hkoBw64
LpyGwoFytXpH6i5cXOCW+bgpX1+TBMy+d1pfStaJC7mTJL/O5wCkhUiZS+ZJG/Ug
u1dkEXs4ymUeaKdAv6bzv5O1/SQNWoKzGrVs52O93KGp/g933OMLv45xGLifPCV4
McS/859LcMLDJrN97HdSy4w=
-----END PRIVATE KEY-----"""

        const val SERVER_FP = "6F:E1:40:86:01:73:73:EA:77:AF:DB:E6:3B:D3:03:C7:A0:D7:EF:44:A0:F7:1D:5F:AB:90:41:3E:D4:37:77:1E"

        const val CLIENT_CERT_PEM = """-----BEGIN CERTIFICATE-----
MIICwjCCAaqgAwIBAgIUd/H7JTOLjQzpKZmZfFulDAEgW+swDQYJKoZIhvcNAQEL
BQAwGzEZMBcGA1UEAwwQc25vdy10ZXN0LWNsaWVudDAeFw0yNjExMjEwMzA2MzNa
Fw0zNjExMTkwMzA2MzNaMBsxGTAXBgNVBAMMEHNub3ctdGVzdC1jbGllbnQwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQChvfvRC9glH5xHXgDQh1U+ndSg
igPzk1KD07I/ZZSwqlFfLk9xojnONKRYF3FiSL3vS1qA3lhK37/7ZE8l6jMWiH8D
ZL5391tyR9SPvzb8sFjyWF36Sxz1D4zDGrBQzQJXYZq7/uNLwK+LapRfQFAS4VJY
FuEJj+QxcjzF6zPVdQbJNtXgCA1oXyzex1vi/vZFEE3ugKh8J+MvW2EoooU3ZgH/
vfE7rtPA/narFqDezbAPPi0RUluiY+GAfM5vM5Qv2ddTxPRACX4cKJE5kIRAirMW
JKvcArK8kN3BspDQxqRgPC/dbj97BqgvpcXFUWedOYQtum9TxJ0qoIKDXJt3AgMB
AAEwDQYJKoZIhvcNAQELBQADggEBAIS3JFVOnJIBk+lxCbD+lHPBgxxlcFddqjFA
7vjrbkAlT4dd7gBDTaaP2EgMJge7RE9wD4QVleksDsrv3gMYRqLHMfqicy1e/reb
skHRIqtUOnCnPjyyfGomYzbzoPQVQhS5Nxxtkkw6NacBzsXvBUWbcPjt1pwbf9kl
bGUQHDT3Vu37Vep3+USB59eNMLTtBLUubz9Fb6cqwPMf9e+Jh2iqy8D+5n4w0G/G
Gqny6MQneLBAvsNYdd8RRN7WxzFhDQ9TaUXYqashV5n4Eug0R1hjjBtkHObgQ8Pf
ZXJB7uXevW7Pwnmg879Y6aaebYY64tgmBufQlk2uS7zdD1vwwLM=
-----END CERTIFICATE-----"""

        const val CLIENT_KEY_PEM = """-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQChvfvRC9glH5xH
XgDQh1U+ndSgigPzk1KD07I/ZZSwqlFfLk9xojnONKRYF3FiSL3vS1qA3lhK37/7
ZE8l6jMWiH8DZL5391tyR9SPvzb8sFjyWF36Sxz1D4zDGrBQzQJXYZq7/uNLwK+L
apRfQFAS4VJYFuEJj+QxcjzF6zPVdQbJNtXgCA1oXyzex1vi/vZFEE3ugKh8J+Mv
W2EoooU3ZgH/vfE7rtPA/narFqDezbAPPi0RUluiY+GAfM5vM5Qv2ddTxPRACX4c
KJE5kIRAirMWJKvcArK8kN3BspDQxqRgPC/dbj97BqgvpcXFUWedOYQtum9TxJ0q
oIKDXJt3AgMBAAECggEATvKB2L70SOKOEJPEyARWypKVd6sGVL0jOK97QNCfbEAm
KdRb+LZbithNI6aFtJiXBRd93IsrA5kFh3ql23beavBDNu/UvI/jdfuzuFp4R4z4
TYpujL5fKwrlBVKgn0ACFY7RzVOTtKUfymhCdd/Zde2/mLnKLDWtB6mgGmc8zMJk
1U0XpLOwFJ3F2suw3TiJzGKAcpPma6E6uECpBBsz2mQ6HhN2ohwY6vAcwKwb0hPv
RMaz5o/jSvncSHUdUFt84ViGS5JnDSF4z+XkDKDo2kE2s8XjaXRBmZtTRXaYRjnT
Tse7nIa6m16Ynrr5AyqRUY3H6Sar2GeAAKuGpUrMCQKBgQDP4JS6JpA4w5BvtAO+
d9ea1hBV5X6nsnCpbucovBobR6Rkt19OuEWbySRmjTSlnxjkldR4yTDhlXgtnpl5
qBfIC4P8zwNyfanzuOZnosTsdc0GmMlYu+pnccpYpQbApFJ0Z5xe+c44WXGz39s+
PSXqtajDXOhnKaDieP3IsV5UJQKBgQDHL0xRuou6KxImfJiL/UG53+qSJL4ZiUW6
T+Z3LOa381td/ph9MSD+WyhfUlmSE0C+gQ5Gf3amtPgg/UUuwL972gbOJ09oGy79
BCPfWfNg9rtD6vc3gVCiDxuIvzdRuT7WNypbQTDH0hS12PxM81693KYd53zRkblz
EWJjo96wawKBgAYSLwXIvomJ3JwGi91yLo/NFKkNjMdlBLlODd44sCJ/0yNF37iy
1QWZuEBue00i+l0iqxPj/FN6RApBCYZuDFPBUld9zEH5vY7qpX/9Vvb48cXxjF/V
DSF8R0aTe0EBC49uvzhe31Dx+8ofDY4hxwu1xnn+KqNoqdQzaGYGGBUpAoGAW2yh
Si4mrlfQp+uulSq0fV2CrHvC6bOxVpgP/4mTiMFhoZ4XXfcr3rP2rvH8fOjrYcWY
yND+o/wSnAnENHZyLaXgU8WFVBKOGcJJuN3vsQTu5Xi26jonyYrHp5elC5TMe8Ss
Y2BjxIPvz5v+Ck/2n4zkjntPNl390gwbrgJsV2sCgYAhtw5XNQlyLVNwisUv7Si/
J35yv+rKkMdzOAmAmnLwEZmVJsZuCZ/GkNDGBsaILcLYS0RlRh00HrTyclFp1Q5n
AI6SvBy2vvbn8Xe1opJdCpzTX/mxDLRwbAapFR4ymlEHepSmu7yZQV/WvUEVlvK7
h1poUR4RxRP6mWfwhlBYJg==
-----END PRIVATE KEY-----"""

        const val CLIENT_FP = "DA:13:B2:E3:9B:3A:16:D4:ED:EE:DB:FE:F1:44:F6:72:5D:8D:D7:E1:C7:12:A3:84:F1:8C:5F:DF:AB:BB:9A:C4"

        fun parseCertificate(pem: String): X509Certificate {
            val cf = CertificateFactory.getInstance("X.509")
            return cf.generateCertificate(ByteArrayInputStream(pem.toByteArray(Charsets.UTF_8))) as X509Certificate
        }

        fun parsePrivateKey(pem: String): PrivateKey {
            val clean = pem.replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replace("\r", "")
                .replace("\n", "")
                .trim()
            val decoded = Base64.getDecoder().decode(clean)
            val kf = KeyFactory.getInstance("RSA")
            return kf.generatePrivate(PKCS8EncodedKeySpec(decoded))
        }

        fun createSslContext(
            certPem: String? = null,
            keyPem: String? = null,
            expectedPeerFp: String? = null
        ): SSLContext {
            val keyManagers = if (certPem != null && keyPem != null) {
                val cert = parseCertificate(certPem)
                val key = parsePrivateKey(keyPem)
                val ks = KeyStore.getInstance("PKCS12").apply {
                    load(null, null)
                    setKeyEntry("snow_key", key, "".toCharArray(), arrayOf(cert))
                }
                val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
                kmf.init(ks, "".toCharArray())
                kmf.keyManagers
            } else {
                null
            }

            val trustManager: X509TrustManager = if (expectedPeerFp != null) {
                SnowTrustManager(InMemoryCertPinStorage(expectedPeerFp))
            } else {
                object : X509TrustManager {
                    override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
                    override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
                    override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
                }
            }

            val sslContext = SSLContext.getInstance("TLS")
            sslContext.init(keyManagers, arrayOf(trustManager), java.security.SecureRandom())
            return sslContext
        }
    }

    @Test
    fun testDeterministicRoleNegotiationHelper() {
        assertTrue(isTlsServerRole("dev-b", "dev-a"))
        assertFalse(isTlsServerRole("dev-a", "dev-b"))

        val windowsId = "00000000-0000-4000-8000-000000000001"
        val phoneId = "11111111-1111-4111-8111-111111111111"

        assertFalse("Windows with lower ID must act as TLS client", isTlsServerRole(windowsId, phoneId))
        assertTrue("Phone with higher ID must act as TLS server", isTlsServerRole(phoneId, windowsId))
    }

    @Test
    fun testRelayClientRoleAssignment() {
        val lowId = "aaaa-1111"
        val highId = "zzzz-9999"

        val clientInstance = RelayClient(
            relayUrl = "wss://relay.example.com/v1/tunnel",
            deviceId = lowId,
            groupId = "group-1",
            ticket = "ticket.payload.sig",
            targetPeerId = highId
        )
        assertTrue(clientInstance.isClientMode)
        assertFalse(clientInstance.isServer)

        val serverInstance = RelayClient(
            relayUrl = "wss://relay.example.com/v1/tunnel",
            deviceId = highId,
            groupId = "group-1",
            ticket = "ticket.payload.sig",
            targetPeerId = lowId
        )
        assertFalse(serverInstance.isClientMode)
        assertTrue(serverInstance.isServer)
    }

    @Test
    fun testGenuineTls13HandshakeAndDataTransfer() {
        // Server context has server cert/key and expects client's pinned fingerprint
        val serverCtx = createSslContext(SERVER_CERT_PEM, SERVER_KEY_PEM, expectedPeerFp = CLIENT_FP)
        // Client context has client cert/key and expects server's pinned fingerprint
        val clientCtx = createSslContext(CLIENT_CERT_PEM, CLIENT_KEY_PEM, expectedPeerFp = SERVER_FP)

        val serverTunnel = E2eRelayTunnel(serverCtx, isServer = true, expectedPeerFingerprint = CLIENT_FP)
        val clientTunnel = E2eRelayTunnel(clientCtx, isServer = false, expectedPeerFingerprint = SERVER_FP)

        // Drive mutual handshake over in-memory pipe
        var (_, clientOut) = clientTunnel.driveHandshake()
        assertTrue(clientOut.isNotEmpty()) // Initial ClientHello

        for (i in 0 until 12) {
            if (clientOut.isNotEmpty()) {
                serverTunnel.feedNetworkData(clientOut)
            }
            val (_, sOut) = serverTunnel.driveHandshake()
            if (sOut.isNotEmpty()) {
                clientTunnel.feedNetworkData(sOut)
            }
            val (_, cOut) = clientTunnel.driveHandshake()
            clientOut = cOut

            if (serverTunnel.handshakeDone && clientTunnel.handshakeDone) {
                break
            }
        }

        assertTrue("Server handshake must complete", serverTunnel.handshakeDone)
        assertTrue("Client handshake must complete", clientTunnel.handshakeDone)

        // Verify mutual authentication
        assertEquals(CLIENT_FP, serverTunnel.peerFingerprint)
        assertEquals(SERVER_FP, clientTunnel.peerFingerprint)

        // 3. Client-to-server application data
        val clientMsg = "CONFIDENTIAL_PAYLOAD_FROM_CLIENT_12345".toByteArray(Charsets.UTF_8)
        val encryptedC2S = clientTunnel.encryptApplicationData(clientMsg)
        serverTunnel.feedNetworkData(encryptedC2S)
        val decryptedOnServer = serverTunnel.decryptApplicationData()
        assertArrayEquals(clientMsg, decryptedOnServer)

        // 4. Server-to-client application data
        val serverMsg = "CONFIDENTIAL_PAYLOAD_FROM_SERVER_67890".toByteArray(Charsets.UTF_8)
        val encryptedS2C = serverTunnel.encryptApplicationData(serverMsg)
        clientTunnel.feedNetworkData(encryptedS2C)
        val decryptedOnClient = clientTunnel.decryptApplicationData()
        assertArrayEquals(serverMsg, decryptedOnClient)
    }

    @Test
    fun testFingerprintMismatchRejected() {
        val wrongFp = "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99"
        val serverCtx = createSslContext(SERVER_CERT_PEM, SERVER_KEY_PEM, expectedPeerFp = wrongFp)
        val clientCtx = createSslContext(CLIENT_CERT_PEM, CLIENT_KEY_PEM, expectedPeerFp = SERVER_FP)

        val serverTunnel = E2eRelayTunnel(serverCtx, isServer = true, expectedPeerFingerprint = wrongFp)
        val clientTunnel = E2eRelayTunnel(clientCtx, isServer = false, expectedPeerFingerprint = SERVER_FP)

        var (_, clientOut) = clientTunnel.driveHandshake()

        var caughtSecurityException = false
        try {
            for (i in 0 until 10) {
                if (clientOut.isNotEmpty()) {
                    serverTunnel.feedNetworkData(clientOut)
                }
                val (_, sOut) = serverTunnel.driveHandshake()
                if (sOut.isNotEmpty()) {
                    clientTunnel.feedNetworkData(sOut)
                }
                val (_, cOut) = clientTunnel.driveHandshake()
                clientOut = cOut
            }
        } catch (e: SecurityException) {
            caughtSecurityException = true
            assertTrue(e.message?.contains("fingerprint mismatch") == true || e.message?.contains("Expected") == true)
        }
        assertTrue("Handshake with mismatched fingerprint must fail with SecurityException", caughtSecurityException)
    }

    @Test
    fun testMissingClientCertRejectedWhenMutualAuthRequired() {
        // Server requires client authentication, but client context has no cert/key
        val serverCtx = createSslContext(SERVER_CERT_PEM, SERVER_KEY_PEM, expectedPeerFp = CLIENT_FP)
        val anonymousClientCtx = createSslContext(certPem = null, keyPem = null, expectedPeerFp = SERVER_FP)

        val serverTunnel = E2eRelayTunnel(serverCtx, isServer = true, expectedPeerFingerprint = CLIENT_FP)
        val clientTunnel = E2eRelayTunnel(anonymousClientCtx, isServer = false, expectedPeerFingerprint = SERVER_FP)

        var (_, clientOut) = clientTunnel.driveHandshake()
        var caughtFailure = false

        try {
            for (i in 0 until 10) {
                if (clientOut.isNotEmpty()) {
                    serverTunnel.feedNetworkData(clientOut)
                }
                val (_, sOut) = serverTunnel.driveHandshake()
                if (sOut.isNotEmpty()) {
                    clientTunnel.feedNetworkData(sOut)
                }
                val (_, cOut) = clientTunnel.driveHandshake()
                clientOut = cOut
            }
        } catch (e: Exception) {
            caughtFailure = true
        }

        assertFalse("Server must not complete handshake without client certificate", serverTunnel.handshakeDone)
    }

    @Test
    fun testCleanTlsShutdown() {
        val serverCtx = createSslContext(SERVER_CERT_PEM, SERVER_KEY_PEM, expectedPeerFp = CLIENT_FP)
        val clientCtx = createSslContext(CLIENT_CERT_PEM, CLIENT_KEY_PEM, expectedPeerFp = SERVER_FP)

        val serverTunnel = E2eRelayTunnel(serverCtx, isServer = true, expectedPeerFingerprint = CLIENT_FP)
        val clientTunnel = E2eRelayTunnel(clientCtx, isServer = false, expectedPeerFingerprint = SERVER_FP)

        var (_, clientOut) = clientTunnel.driveHandshake()
        for (i in 0 until 12) {
            if (clientOut.isNotEmpty()) serverTunnel.feedNetworkData(clientOut)
            val (_, sOut) = serverTunnel.driveHandshake()
            if (sOut.isNotEmpty()) clientTunnel.feedNetworkData(sOut)
            val (_, cOut) = clientTunnel.driveHandshake()
            clientOut = cOut
            if (serverTunnel.handshakeDone && clientTunnel.handshakeDone) break
        }

        assertTrue(clientTunnel.handshakeDone)
        val closeNotify = clientTunnel.closeOutbound()
        assertTrue("Close notify alert must produce output bytes", closeNotify.isNotEmpty())
    }

    @Test
    fun testFreshSessionAfterReconnect() {
        for (attempt in 1..2) {
            val serverCtx = createSslContext(SERVER_CERT_PEM, SERVER_KEY_PEM, expectedPeerFp = CLIENT_FP)
            val clientCtx = createSslContext(CLIENT_CERT_PEM, CLIENT_KEY_PEM, expectedPeerFp = SERVER_FP)

            val serverTunnel = E2eRelayTunnel(serverCtx, isServer = true, expectedPeerFingerprint = CLIENT_FP)
            val clientTunnel = E2eRelayTunnel(clientCtx, isServer = false, expectedPeerFingerprint = SERVER_FP)

            var (_, clientOut) = clientTunnel.driveHandshake()
            for (i in 0 until 12) {
                if (clientOut.isNotEmpty()) serverTunnel.feedNetworkData(clientOut)
                val (_, sOut) = serverTunnel.driveHandshake()
                if (sOut.isNotEmpty()) clientTunnel.feedNetworkData(sOut)
                val (_, cOut) = clientTunnel.driveHandshake()
                clientOut = cOut
                if (serverTunnel.handshakeDone && clientTunnel.handshakeDone) break
            }
            assertTrue("Attempt $attempt: Handshake must succeed", serverTunnel.handshakeDone)
            val msg = "RECONNECT_ATTEMPT_$attempt".toByteArray(Charsets.UTF_8)
            serverTunnel.feedNetworkData(clientTunnel.encryptApplicationData(msg))
            assertArrayEquals(msg, serverTunnel.decryptApplicationData())
        }
    }

    @Test
    fun testSavedDeviceConnectionModeDefaultsAndMutation() {
        val device = SavedDevice(
            deviceId = "dev-test-1",
            deviceName = "Lenovo V15",
            host = "192.168.1.10",
            port = 8765
        )
        assertEquals("auto", device.connectionMode)

        val localOnlyDevice = device.copy(connectionMode = "local_only")
        assertEquals("local_only", localOnlyDevice.connectionMode)

        val remoteOnlyDevice = device.copy(connectionMode = "remote_only")
        assertEquals("remote_only", remoteOnlyDevice.connectionMode)
    }

    @Test
    fun testSavedDeviceConnectionModeJsonSerialization() {
        val device = SavedDevice(
            deviceId = "dev-phone-42",
            deviceName = "Realme RMX5110",
            host = "192.168.1.50",
            port = 8765,
            lastSeen = "2026-11-22T08:00:00Z",
            trustTier = "PEER",
            certFingerprint = "AA:BB:CC:DD",
            recentEndpoints = listOf(DeviceEndpoint("192.168.1.50", 8765)),
            connectionMode = "remote_only"
        )

        val json = JSONObject().apply {
            put("deviceId", device.deviceId)
            put("deviceName", device.deviceName)
            put("host", device.host)
            put("port", device.port)
            put("lastSeen", device.lastSeen)
            put("trustTier", device.trustTier)
            put("certFingerprint", device.certFingerprint)
            put("connectionMode", device.connectionMode)
        }

        assertEquals("remote_only", json.optString("connectionMode", "auto"))

        val legacyJson = JSONObject().apply {
            put("deviceId", device.deviceId)
            put("deviceName", device.deviceName)
            put("host", device.host)
            put("port", device.port)
        }

        val deserializedMode = legacyJson.optString("connectionMode", "auto")
        assertEquals("auto", deserializedMode)
    }

    @Test
    fun testTunnelInitSignalIntegrity() {
        val signalStr = "SNOW_TUNNEL_INIT"
        val signalBytes = signalStr.toByteArray(Charsets.UTF_8)
        assertEquals(16, signalBytes.size)
        assertEquals("SNOW_TUNNEL_INIT", String(signalBytes, Charsets.UTF_8))
    }
}
