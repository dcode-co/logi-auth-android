package com.dcodelabs.logi.sdk.internal

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * Golden-vector parity test. `resources/id-token-vectors.json` is a copy of the
 * 4-SDK shared set (`test-vectors/id-token-vectors.json`, SoT = generate.mjs).
 * Android MUST produce identical verify/reject results to Web/iOS/Flutter.
 * JWKS is a fixed snapshot so this runs as a plain JVM unit test — no network,
 * no Robolectric.
 */
class IdTokenVerifierTest {

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
    private data class Case(
        val name: String,
        val token: String,
        // Present-only at_hash binding: threaded into verifyIdToken when set
        // (cases without it skip at_hash, staying backward compatible).
        val accessToken: String? = null,
        val expect: Expect,
    )

    @Serializable
    private data class Expect(val valid: Boolean, val sub: String? = null, val error: String? = null)

    private fun loadVectors(): Vectors {
        val stream = javaClass.classLoader?.getResourceAsStream("id-token-vectors.json")
            ?: error("golden vectors fixture missing from test resources")
        val text = stream.bufferedReader().use { it.readText() }
        return json.decodeFromString(text)
    }

    private companion object {
        val json = Json { ignoreUnknownKeys = true }
    }

    @Test
    fun goldenVectors() {
        val v = loadVectors()
        val expected = VerifyExpected(v.expected.issuer, v.expected.clientId, v.expected.nonce)

        for (c in v.cases) {
            try {
                val result = verifyIdToken(c.token, v.jwks, expected, now = v.now, accessToken = c.accessToken)
                assertTrue("case '${c.name}' expected to be invalid but verified", c.expect.valid)
                c.expect.sub?.let { assertEquals("case '${c.name}' sub mismatch", it, result.sub) }
            } catch (e: IdTokenVerificationException) {
                assertTrue("case '${c.name}' expected valid but threw ${e.error.code}", !c.expect.valid)
                c.expect.error?.let { assertEquals("case '${c.name}' error code mismatch", it, e.error.code) }
            }
        }
    }

    @Test
    fun goldenVectorCoverage() {
        val v = loadVectors()
        assertTrue("expected the full golden-vector set", v.cases.size >= 9)
        assertTrue(v.cases.any { it.name == "valid" })
        if (v.cases.none { it.name == "valid" }) fail("missing the happy-path vector")
    }
}
