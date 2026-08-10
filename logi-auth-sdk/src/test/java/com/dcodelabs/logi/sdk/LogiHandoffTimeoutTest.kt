package com.dcodelabs.logi.sdk

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.currentTime
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The wait deadline: a claimed flow must always end, and must always give the
 * single-flight slot back when it does.
 *
 * Why this matters more than it looks: in split-screen / freeform (multi-resume,
 * API 29+) no RP Activity is stopped or resumed while the logi app sits beside
 * it, so the lifecycle cancel detector never fires. Before the deadline such a
 * flow waited forever, and because the slot is single-flight, *every* later
 * `signIn()` in that process failed with `AlreadyInProgress` — the login button
 * was dead until the process died.
 *
 * Scope note, same as [LogiCallbackTest]: `signIn` / `authorize` themselves need
 * an Activity, `android.net.Uri` and encrypted prefs, and this module runs plain
 * JVM tests with no Robolectric. So these drive [LogiAuth.runPendingFlow] — the
 * one function both entry points delegate their wait and teardown to — with the
 * Android-touching launch and persistence stubbed out. What is NOT covered here
 * is that `signIn` / `authorize` call it; that is held by the code reading as a
 * single `return runPendingFlow(...)` in each.
 *
 * Virtual time throughout: `runTest` advances the clock whenever the test
 * coroutine goes idle, so a five-minute deadline costs no wall-clock time.
 */
@OptIn(ExperimentalCoroutinesApi::class)  // TestScope.currentTime
class LogiHandoffTimeoutTest {

    /**
     * Mirrors the SDK's private `HANDOFF_TIMEOUT_MS`. Deliberately duplicated
     * rather than exposed: the constant is private on both SDKs (iOS
     * `LogiAuth.swift:32`), and a test that reads it back could not notice the
     * value changing. 300s is the contract, so state it.
     */
    private val deadlineMs = 300_000L

    @After
    fun tearDown() {
        // LogiAuth is an object with process-wide state. A failed assertion must
        // not leave a slot claimed, or every later test fails with
        // AlreadyInProgress for the wrong reason.
        LogiAuth.callbackInFlight = false
        LogiAuth.failPendingFlow(LogiAuthError.UserCancelled)
    }

    @Test
    fun `a callback that never arrives fails with HandoffTimeout`() = runTest {
        val flow = CompletableDeferred<Result<LogiSession>>()
        assertTrue(LogiAuth.claimSignIn(flow) {})

        val result = LogiAuth.runPendingFlow(flow, clearPersisted = {}) { null }

        assertTrue(result.isFailure)
        assertSame(LogiAuthError.HandoffTimeout, result.exceptionOrNull())
        assertEquals(
            "the flow must wait the full deadline before giving up",
            deadlineMs,
            currentTime,
        )
    }

    /**
     * The actual regression this change exists to prevent. A timed-out flow that
     * kept the slot would be no better than the hang it replaced.
     */
    @Test
    fun `timing out hands the single-flight slot back`() = runTest {
        val abandoned = CompletableDeferred<Result<LogiSession>>()
        assertTrue(LogiAuth.claimSignIn(abandoned) {})
        LogiAuth.runPendingFlow(abandoned, clearPersisted = {}) { null }

        val retry = CompletableDeferred<Result<LogiSession>>()
        assertTrue(
            "a timed-out flow must not hold the slot — that is the state that killed the login button",
            LogiAuth.claimSignIn(retry) {},
        )
    }

    /**
     * The backend-led (BFF) path shares the deadline and the release. Split
     * across two SDKs' worth of near-identical code this was the easiest thing to
     * get wrong: fix `signIn` only and confidential RPs stay locked.
     */
    @Test
    fun `the backend-led flow times out and releases the same way`() = runTest {
        val abandoned = CompletableDeferred<Result<LogiCallback>>()
        assertTrue(LogiAuth.claimAuthorize(abandoned) {})

        val result = LogiAuth.runPendingFlow(abandoned, clearPersisted = {}) { null }

        assertSame(LogiAuthError.HandoffTimeout, result.exceptionOrNull())
        assertTrue(
            "an abandoned authorize() must not block a later signIn() either",
            LogiAuth.claimSignIn(CompletableDeferred<Result<LogiSession>>()) {},
        )
    }

    /**
     * The deadline must never win over a session the server already issued. The
     * token exchange runs inside the callback handler *before* it completes the
     * deferred, so a slow network can still be exchanging when the clock runs
     * out — `callbackInFlight` buys it the grace window.
     */
    @Test
    fun `a session landing while the exchange is in flight beats the deadline`() = runTest {
        val flow = CompletableDeferred<Result<LogiSession>>()
        assertTrue(LogiAuth.claimSignIn(flow) {})
        LogiAuth.callbackInFlight = true  // the callback handler is mid-exchange

        launch {
            delay(deadlineMs + 1_000)  // lands past the deadline, inside the grace
            flow.complete(Result.success(session()))
        }
        val result = LogiAuth.runPendingFlow(flow, clearPersisted = {}) { null }

        assertTrue(
            "the exchange was in flight at the deadline — failing here would discard a live session",
            result.isSuccess,
        )
        assertEquals("sub-1", result.getOrNull()?.sub)
    }

    /** No exchange in flight ⇒ no grace, and the failure is the deadline's. */
    @Test
    fun `without an exchange in flight the deadline is not extended`() = runTest {
        val flow = CompletableDeferred<Result<LogiSession>>()
        assertTrue(LogiAuth.claimSignIn(flow) {})

        LogiAuth.runPendingFlow(flow, clearPersisted = {}) { null }

        assertEquals(deadlineMs, currentTime)
    }

    /** The deadline costs the happy path nothing. */
    @Test
    fun `a callback that already landed is returned without waiting`() = runTest {
        val landed = CompletableDeferred(Result.success(session()))

        val result = LogiAuth.awaitCallback(landed)

        assertTrue(result.isSuccess)
        assertEquals("the deadline must not delay a callback that is already in hand", 0L, currentTime)
    }

    /**
     * A flow that finished after its slot was handed to a newer one must not tear
     * that newer flow down — the teardown is identity-checked under the same lock
     * the claim takes. Without it the departing flow nulls the new flow's
     * persisted state and its callback dies with StateMismatch.
     */
    @Test
    fun `a departing flow leaves a newer flow's slot and state alone`() = runTest {
        val newer = CompletableDeferred<Result<LogiSession>>()
        assertTrue(LogiAuth.claimSignIn(newer) {})

        var clearedPersistedState = false
        val older = CompletableDeferred<Result<LogiSession>>()  // never owned the slot
        LogiAuth.runPendingFlow(older, clearPersisted = { clearedPersistedState = true }) { null }

        assertFalse(
            "the departing flow wiped the state of the flow that now owns the slot",
            clearedPersistedState,
        )
        assertFalse(
            "the newer flow must still hold the slot",
            LogiAuth.claimSignIn(CompletableDeferred<Result<LogiSession>>()) {},
        )
    }

    /**
     * The same protection on the callback side. A token exchange slower than the
     * deadline plus its grace lands after the caller gave up and the user retried,
     * and the callback handler's teardown must not take the retry down with it:
     * the retry's `state` / `nonce` / verifier are what is in the store now, and
     * its slot is what is claimed now. Before the deadline existed this teardown
     * could be unconditional, because a flow could not end before its callback
     * arrived. (codex review P1, 2026-08-10.)
     *
     * Drives the exact call the callback handler makes — `signIn` /
     * `handleAuthorizationCallback` themselves need Android, per the note above.
     */
    @Test
    fun `a callback landing after its flow timed out leaves the retry alone`() = runTest {
        val abandoned = CompletableDeferred<Result<LogiSession>>()
        assertTrue(LogiAuth.claimSignIn(abandoned) {})
        var ownStateCleared = false
        val timedOut = LogiAuth.runPendingFlow(
            abandoned,
            clearPersisted = { ownStateCleared = true },
        ) { null }
        assertSame(LogiAuthError.HandoffTimeout, timedOut.exceptionOrNull())
        assertTrue("a flow that gives up must clear its own state", ownStateCleared)

        // The user retries. This flow now owns the slot and the persisted state.
        val retry = CompletableDeferred<Result<LogiSession>>()
        assertTrue(LogiAuth.claimSignIn(retry) {})

        // ...and only now does the abandoned flow's exchange come back.
        var lateCallbackClearedStore = false
        LogiAuth.releaseFlowIfOwner(abandoned) { lateCallbackClearedStore = true }
        abandoned.complete(Result.success(session()))

        assertFalse(
            "the late callback wiped the retry's verifier / state / nonce",
            lateCallbackClearedStore,
        )
        assertFalse(
            "the late callback freed the retry's slot",
            LogiAuth.claimSignIn(CompletableDeferred<Result<LogiSession>>()) {},
        )
    }

    /** A launch that fails never waits out the deadline. */
    @Test
    fun `a launch failure fails immediately and releases the slot`() = runTest {
        val flow = CompletableDeferred<Result<LogiSession>>()
        assertTrue(LogiAuth.claimSignIn(flow) {})

        val noBrowser = LogiAuthError.Network(IllegalStateException("no browser"))
        val result = LogiAuth.runPendingFlow(flow, clearPersisted = {}) { noBrowser }

        assertSame(noBrowser, result.exceptionOrNull())
        assertEquals(0L, currentTime)
        assertTrue(LogiAuth.claimSignIn(CompletableDeferred<Result<LogiSession>>()) {})
    }

    private fun session(sub: String = "sub-1") = LogiSession(
        sub = sub,
        email = null,
        idToken = "header.payload.signature",
        accessToken = "at",
        refreshToken = null,
        tokenType = "Bearer",
        scope = null,
        expiresInSec = 3600,
    )
}
