package com.dcodelabs.logi.sdk.internal

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonObjectBuilder
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.junit.Assert.assertEquals
import org.junit.Assert.fail
import org.junit.Test
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.PKCS8EncodedKeySpec
import java.util.Base64

/**
 * P2 hardening unit tests (plain JVM — no Robolectric/network):
 *  - A1: JWKS `kty`/`use`/`alg` filter must pick the RSA signing key even when a
 *        same-kid EC key precedes it, and reject when no RSA key matches.
 *  - A2: `at_hash` (OIDC §3.1.3.6) binding — accept when it matches the
 *        access_token, reject AT_HASH_MISMATCH when it doesn't, skip when the
 *        access_token is absent.
 *
 * Tokens are signed inline with the shared test key (a copy of
 * test-vectors/test-signing-key.pem) so no golden fixture / generate.mjs edit is
 * needed. The public JWK snapshot is loaded from the golden vectors resource.
 */
class IdTokenHardeningTest {

    @Serializable
    private data class Vectors(
        val now: Long,
        val expected: Expected,
        val jwks: Jwks,
        val cases: List<Case>,
    )

    @Serializable
    private data class Expected(val issuer: String, val clientId: String, val nonce: String? = null)

    @Serializable
    private data class Case(val name: String, val token: String)

    private companion object {
        val json = Json { ignoreUnknownKeys = true }
        const val KID = "logi-test-2026"
    }

    private fun vectors(): Vectors {
        val stream = javaClass.classLoader?.getResourceAsStream("id-token-vectors.json")
            ?: error("golden vectors fixture missing from test resources")
        return json.decodeFromString(stream.bufferedReader().use { it.readText() })
    }

    // Independent base64url-nopad encoder (test-side oracle for at_hash + JWS).
    private fun b64url(bytes: ByteArray): String =
        Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)

    private fun atHashOf(accessToken: String): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(accessToken.toByteArray(Charsets.UTF_8))
        return b64url(digest.copyOfRange(0, 16))
    }

    /** Build + RS256-sign an id_token from a payload, kid = golden test kid. */
    private fun signToken(payload: JsonObject): String {
        val header = buildJsonObject {
            put("alg", "RS256"); put("kid", KID); put("typ", "JWT")
        }
        val headerB64 = b64url(header.toString().toByteArray(Charsets.UTF_8))
        val payloadB64 = b64url(payload.toString().toByteArray(Charsets.UTF_8))
        val signingInput = "$headerB64.$payloadB64"
        val sig = Signature.getInstance("SHA256withRSA").run {
            initSign(privateKey())
            update(signingInput.toByteArray(Charsets.UTF_8))
            sign()
        }
        return "$signingInput.${b64url(sig)}"
    }

    private fun privateKey(): java.security.PrivateKey {
        val pem = javaClass.classLoader?.getResourceAsStream("test-signing-key.pem")
            ?.bufferedReader()?.use { it.readText() }
            ?: error("test-signing-key.pem missing from test resources")
        val body = pem
            .replace("-----BEGIN PRIVATE KEY-----", "")
            .replace("-----END PRIVATE KEY-----", "")
            .replace(Regex("\\s"), "")
        val der = Base64.getDecoder().decode(body)
        return KeyFactory.getInstance("RSA").generatePrivate(PKCS8EncodedKeySpec(der))
    }

    private fun basePayload(v: Vectors, extra: JsonObjectBuilder.() -> Unit): JsonObject =
        buildJsonObject {
            put("iss", v.expected.issuer)
            put("aud", v.expected.clientId)
            put("sub", "pairwise-sub-0001")
            put("exp", v.now + 3600)
            put("iat", v.now - 30)
            v.expected.nonce?.let { put("nonce", it) }
            extra()
        }

    // ── A2: at_hash ──────────────────────────────────────────────────────────

    @Test
    fun atHashMatchesAccessToken() {
        val v = vectors()
        val accessToken = "test-access-token-value-123"
        val token = signToken(basePayload(v) { put("at_hash", atHashOf(accessToken)) })
        val expected = VerifyExpected(v.expected.issuer, v.expected.clientId, v.expected.nonce)

        val verified = verifyIdToken(token, v.jwks, expected, now = v.now, accessToken = accessToken)
        assertEquals("pairwise-sub-0001", verified.sub)
    }

    @Test
    fun atHashMismatchRejected() {
        val v = vectors()
        val token = signToken(basePayload(v) { put("at_hash", atHashOf("the-real-access-token")) })
        val expected = VerifyExpected(v.expected.issuer, v.expected.clientId, v.expected.nonce)

        try {
            verifyIdToken(token, v.jwks, expected, now = v.now, accessToken = "a-different-access-token")
            fail("expected AT_HASH_MISMATCH")
        } catch (e: IdTokenVerificationException) {
            assertEquals(IdTokenVerifyError.AT_HASH_MISMATCH, e.error)
        }
    }

    @Test
    fun atHashSkippedWhenAccessTokenAbsent() {
        val v = vectors()
        val token = signToken(basePayload(v) { put("at_hash", atHashOf("some-access-token")) })
        val expected = VerifyExpected(v.expected.issuer, v.expected.clientId, v.expected.nonce)

        // No access_token supplied → at_hash check skipped (backward compatible).
        val verified = verifyIdToken(token, v.jwks, expected, now = v.now)
        assertEquals("pairwise-sub-0001", verified.sub)
    }

    // ── A1: JWKS kty/use/alg filter ─────────────────────────────────────────

    @Test
    fun ktyFilterSelectsRsaWhenEcSharesKid() {
        val v = vectors()
        val rsa = v.jwks.keys.single()
        // An EC key that (wrongly) shares the RSA key's kid must be skipped, not
        // picked for RS256 signature verification. dummy n/e are never read.
        val ec = Jwk(kty = "EC", n = "AQAB", e = "AQAB", kid = KID, alg = null, use = null)
        val jwks = Jwks(keys = listOf(ec, rsa))

        val token = signToken(basePayload(v) {})
        val expected = VerifyExpected(v.expected.issuer, v.expected.clientId, v.expected.nonce)
        val verified = verifyIdToken(token, jwks, expected, now = v.now)
        assertEquals("pairwise-sub-0001", verified.sub)
    }

    @Test
    fun realMixedJwksJsonDecodesAndVerifies() {
        // Regression for the codex BLOCK: a real EC JWK has crv/x/y and NO n/e.
        // The JWKS must still deserialize (n/e nullable) so JwksClient.fetch()
        // doesn't throw before the kty filter can skip the EC key.
        val v = vectors()
        val rsa = v.jwks.keys.single()
        val jwksJson = """
            {"keys":[
              {"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0","kid":"$KID","use":"sig","alg":"ES256"},
              {"kty":"RSA","n":"${rsa.n}","e":"${rsa.e}","kid":"$KID","alg":"RS256","use":"sig"}
            ]}
        """.trimIndent()
        val jwks = json.decodeFromString<Jwks>(jwksJson)

        val token = signToken(basePayload(v) {})
        val expected = VerifyExpected(v.expected.issuer, v.expected.clientId, v.expected.nonce)
        assertEquals("pairwise-sub-0001", verifyIdToken(token, jwks, expected, now = v.now).sub)
    }

    @Test
    fun ktyFilterRejectsWhenOnlyNonRsaKeyMatchesKid() {
        val v = vectors()
        val ecOnly = Jwks(keys = listOf(Jwk(kty = "EC", n = "AQAB", e = "AQAB", kid = KID)))

        val token = signToken(basePayload(v) {})
        val expected = VerifyExpected(v.expected.issuer, v.expected.clientId, v.expected.nonce)
        try {
            verifyIdToken(token, ecOnly, expected, now = v.now)
            fail("expected UNKNOWN_KID (no RS256 RSA key)")
        } catch (e: IdTokenVerificationException) {
            assertEquals(IdTokenVerifyError.UNKNOWN_KID, e.error)
        }
    }

    @Test
    fun ktyFilterRejectsEncUseKey() {
        val v = vectors()
        val rsa = v.jwks.keys.single()
        // Same RSA material but marked use=enc — must not be used to verify sigs.
        val encKey = rsa.copy(use = "enc")
        val jwks = Jwks(keys = listOf(encKey))

        val token = signToken(basePayload(v) {})
        val expected = VerifyExpected(v.expected.issuer, v.expected.clientId, v.expected.nonce)
        try {
            verifyIdToken(token, jwks, expected, now = v.now)
            fail("expected UNKNOWN_KID (use=enc filtered out)")
        } catch (e: IdTokenVerificationException) {
            assertEquals(IdTokenVerifyError.UNKNOWN_KID, e.error)
        }
    }

    // Guard: ensure the golden happy-path token also carries the expected sub so
    // the inline-signing path stays consistent with the fixture.
    @Test
    fun goldenValidTokenStillVerifies() {
        val v = vectors()
        val validToken = v.cases.first { it.name == "valid" }.token
        val expected = VerifyExpected(v.expected.issuer, v.expected.clientId, v.expected.nonce)
        val verified = verifyIdToken(validToken, v.jwks, expected, now = v.now)
        assertEquals("pairwise-sub-0001", verified.sub)
    }
}
