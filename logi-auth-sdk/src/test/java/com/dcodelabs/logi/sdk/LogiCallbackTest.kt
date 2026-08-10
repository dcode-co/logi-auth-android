package com.dcodelabs.logi.sdk

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Contract tests for the backend-led (BFF) surface — [LogiCallback] and the
 * error it can fail with.
 *
 * Scope note: [LogiAuth.authorize] itself is not exercised here. It touches
 * `android.net.Uri`, and this module deliberately runs plain JVM unit tests
 * with no Robolectric (see the comment on `testImplementation` in
 * build.gradle.kts) — the same reason `signIn` and
 * `handleAuthorizationCallback` have no unit tests either. What IS covered
 * below is the part that carries the security contract: the shape of the value
 * handed to the RP app.
 */
class LogiCallbackTest {

    @Test
    fun `carries the code and state it was built with`() {
        val cb = LogiCallback(code = "the-code", state = "the-state")
        assertEquals("the-code", cb.code)
        assertEquals("the-state", cb.state)
    }

    /**
     * The whole point of the BFF split is that the app never holds a token or
     * the PKCE verifier — those stay on the RP backend. If either ever shows up
     * as a field here, the app is holding a secret it must not have.
     */
    @Test
    fun `carries nothing except code and state`() {
        val fields = LogiCallback::class.java.declaredFields
            .filterNot { it.isSynthetic }
            .map { it.name }
            .sorted()
        assertEquals(
            "LogiCallback must not grow token or verifier fields — they belong to the backend",
            listOf("code", "state"),
            fields,
        )
    }

    /** Value semantics — RPs compare and log these. */
    @Test
    fun `is a value type`() {
        assertEquals(LogiCallback("c", "s"), LogiCallback("c", "s"))
        assertTrue(LogiCallback("c", "s") != LogiCallback("c", "other"))
    }

    /**
     * A start Uri with no state is refused with a dedicated error rather than a
     * generic one, so an RP can tell "my backend built a bad Uri" apart from
     * "the user cancelled".
     */
    @Test
    fun `missing state error is distinct and explains itself`() {
        val error = LogiAuthError.MissingStateInStartUri
        assertNotNull(error.message)
        assertTrue(
            "the message should point at the backend, which owns state in this flow",
            error.message!!.contains("state"),
        )
        val neighbours: List<LogiAuthError> =
            listOf(LogiAuthError.InvalidAuthorizeUrl, LogiAuthError.StateMismatch)
        assertTrue(
            "it must not collapse into the generic authorize-URL or state errors",
            neighbours.none { it === error || it.message == error.message },
        )
    }
}
