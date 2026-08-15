package com.dcodelabs.logi.sdk

import com.dcodelabs.logi.sdk.internal.StartUriPairVerdict
import com.dcodelabs.logi.sdk.internal.StartUriState
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Pins the launch-time input validation of `authorize(startUri, nativeStartUri)`.
 *
 * The verdicts drive which error the caller gets **before anything is
 * launched**: no usable `state` → `MissingStateInStartUri`; a duplicated
 * `state`, or a pair that differs beyond the host → `StartUriPairMismatch`.
 * `authorize()` itself needs an Activity and `android.net.Uri`, so what JVM
 * tests can pin are these decision functions — the wiring (validate before the
 * single-flight claim, launch only after both pass) is asserted by the call
 * order in `authorize()`.
 */
class StartUriStateTest {

    private val base = "https://api.1pass.dev/oauth/authorize"

    @Test
    fun `single state is read back`() {
        assertEquals(StartUriState.One("abc-123"), StartUriState.read("$base?client_id=x&state=abc-123&scope=openid"))
    }

    @Test
    fun `missing state is Missing`() {
        assertEquals(StartUriState.Missing, StartUriState.read("$base?client_id=x&scope=openid"))
    }

    @Test
    fun `empty state is Missing`() {
        assertEquals(StartUriState.Missing, StartUriState.read("$base?state=&client_id=x"))
        assertEquals(StartUriState.Missing, StartUriState.read("$base?state&client_id=x"))
    }

    /**
     * Two `state` keys are ambiguity, not "first wins" — which one the server
     * echoes back is server-dependent, and guessing wrong fails the callback
     * match after the user has already authenticated.
     */
    @Test
    fun `duplicated state is Duplicated`() {
        assertEquals(StartUriState.Duplicated, StartUriState.read("$base?state=a&state=a"))
        assertEquals(StartUriState.Duplicated, StartUriState.read("$base?state=a&client_id=x&state=b"))
    }

    /** `statement=x` must not be mistaken for a `state` key. */
    @Test
    fun `prefix keys do not count`() {
        assertEquals(StartUriState.Missing, StartUriState.read("$base?statement=a&states=b"))
    }

    /** Percent-encoded values compare decoded, like android.net.Uri does. */
    @Test
    fun `state is percent-decoded`() {
        assertEquals(StartUriState.One("a b+c"), StartUriState.read("$base?state=a%20b%2Bc"))
    }

    @Test
    fun `unparseable url is Missing`() {
        assertEquals(StartUriState.Missing, StartUriState.read("not a url"))
        assertEquals(StartUriState.Missing, StartUriState.read("$base"))
    }

    // ---- StartUriPairVerdict ----

    /**
     * The meetnote-shaped pair: the native leg derived from the web leg by a
     * host swap → passes, and the shared state comes back.
     */
    @Test
    fun `host-swapped pair validates`() {
        val web = "$base?state=S1&code_challenge=C&code_challenge_method=S256"
        val native = web.replace("api.1pass.dev", "open.1pass.dev")
        assertEquals(StartUriPairVerdict.Ok("S1"), StartUriPairVerdict.validate(web, native))
    }

    @Test
    fun `null native leg validates as single uri`() {
        assertEquals(
            StartUriPairVerdict.Ok("S1"),
            StartUriPairVerdict.validate("$base?state=S1&code_challenge=C", null),
        )
    }

    @Test
    fun `missing state on web leg is MissingState`() {
        assertEquals(
            StartUriPairVerdict.MissingState,
            StartUriPairVerdict.validate("$base?client_id=x", null),
        )
    }

    /**
     * Duplicated `state` is a pair-contract violation, not a missing state —
     * the caller must learn it built a bad Uri, not that it forgot the state.
     */
    @Test
    fun `duplicated state is PairMismatch`() {
        assertEquals(
            StartUriPairVerdict.PairMismatch,
            StartUriPairVerdict.validate("$base?state=a&state=b", null),
        )
    }

    /**
     * 🔴 Same state is NOT enough. A drifting `redirect_uri` strands the
     * handoff until timeout; drifting PKCE fails the exchange after the user
     * already authenticated. The whole query must be byte-identical.
     */
    @Test
    fun `same state but drifting query is PairMismatch`() {
        val web = "$base?state=S1&redirect_uri=a%3A%2F%2Fcb&code_challenge=C1"
        val drifted = "https://open.1pass.dev/oauth/authorize?state=S1&redirect_uri=b%3A%2F%2Fcb&code_challenge=C1"
        assertEquals(StartUriPairVerdict.PairMismatch, StartUriPairVerdict.validate(web, drifted))
    }

    @Test
    fun `different path is PairMismatch`() {
        assertEquals(
            StartUriPairVerdict.PairMismatch,
            StartUriPairVerdict.validate(
                "$base?state=S1",
                "https://open.1pass.dev/oauth/authorize2?state=S1",
            ),
        )
    }

    /** Only the host may differ — that is the entire point of the pair. */
    @Test
    fun `different port is PairMismatch`() {
        assertEquals(
            StartUriPairVerdict.PairMismatch,
            StartUriPairVerdict.validate(
                "$base?state=S1",
                "https://open.1pass.dev:8443/oauth/authorize?state=S1",
            ),
        )
    }
}
