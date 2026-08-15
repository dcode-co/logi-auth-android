package com.dcodelabs.logi.sdk

import com.dcodelabs.logi.sdk.internal.StartUriState
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Pins the launch-time input validation of `authorize(startUri, nativeStartUri)`.
 *
 * The verdicts drive which error the caller gets **before anything is
 * launched**: `Missing` → `MissingStateInStartUri`, `Duplicated` or a value
 * differing from the web leg → `StartUriStateMismatch`. `authorize()` itself
 * needs an Activity and `android.net.Uri`, so what JVM tests can pin is this
 * decision function — the wiring (validate before the single-flight claim,
 * launch only after both pass) is asserted by the call order in `authorize()`.
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

    /**
     * The meetnote-shaped pair: the native leg derived from the web leg by a
     * host swap keeps the identical state → the pair passes validation.
     */
    @Test
    fun `host-swapped pair carries the same state`() {
        val web = "$base?state=S1&code_challenge=C&code_challenge_method=S256"
        val native = web.replace("api.1pass.dev", "open.1pass.dev")
        val webState = StartUriState.read(web)
        val nativeState = StartUriState.read(native)
        assertEquals(webState, nativeState)
        assertEquals(StartUriState.One("S1"), webState)
    }
}
