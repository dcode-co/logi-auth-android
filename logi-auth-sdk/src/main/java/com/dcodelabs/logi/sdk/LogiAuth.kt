package com.dcodelabs.logi.sdk

import android.app.Activity
import android.app.Application
import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import androidx.browser.customtabs.CustomTabsClient
import androidx.browser.customtabs.CustomTabsIntent
import com.dcodelabs.logi.sdk.internal.AuthorizeHostSplit
import com.dcodelabs.logi.sdk.internal.IdTokenVerificationException
import com.dcodelabs.logi.sdk.internal.IdTokenVerifyError
import com.dcodelabs.logi.sdk.internal.Jwks
import com.dcodelabs.logi.sdk.internal.JwksClient
import com.dcodelabs.logi.sdk.internal.PendingAuthStore
import com.dcodelabs.logi.sdk.internal.Pkce
import com.dcodelabs.logi.sdk.internal.TokenExchange
import com.dcodelabs.logi.sdk.internal.VerifiedIdToken
import com.dcodelabs.logi.sdk.internal.VerifyExpected
import com.dcodelabs.logi.sdk.internal.verifyIdToken
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.delay
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.serialization.json.JsonPrimitive

/**
 * Public entry point for RP apps integrating logi as their identity
 * provider. Usage:
 *
 * ```kotlin
 * // Application.onCreate
 * LogiAuth.configure(this, LogiAuthConfig(
 *     issuer = "https://api.1pass.dev",
 *     clientId = "logi_xxx",
 *     redirectUri = "myapp://callback",
 * ))
 *
 * // From a button click somewhere in your UI
 * lifecycleScope.launch {
 *     val result = LogiAuth.signIn(activity).getOrElse { error ->
 *         // surface error to user
 *         return@launch
 *     }
 *     // result.accessToken / result.idToken etc.
 * }
 * ```
 *
 * The callback URL must be claimed by [LogiAuthCallbackActivity] (or your
 * own Activity calling [handleAuthorizationCallback]). See README for the
 * AndroidManifest snippet.
 *
 * Public API mirrors the iOS LogiAuth Swift Package so cross-platform teams
 * share a mental model.
 */
object LogiAuth {

    /** Package name of the logi Android app — pinned for app-to-app handoff. */
    private const val LOGI_APP_PACKAGE = "com.dcodelabs.logi"

    /**
     * How long to wait for the app-to-app handoff to take the foreground before
     * concluding the platform swallowed it.
     *
     * Safe to keep short because the signal we wait for is the *starting
     * window*, not a loaded app: Android shows the target's splash surface
     * before its process finishes initializing, which stops our Activity and
     * sets [sawBackgroundSinceLaunch]. Measured at ~80ms for a cold start of
     * the logi app on a mid-range device (START → splash surface), so 2.5s is
     * ~30x headroom and a slow cold start will not be mistaken for an abort.
     */
    private const val HANDOFF_FOREGROUND_TIMEOUT_MS = 2_500L

    /**
     * How long to wait for the authorization callback itself before failing the
     * flow with [LogiAuthError.HandoffTimeout].
     *
     * A different question from [HANDOFF_FOREGROUND_TIMEOUT_MS], which is why
     * both exist: that one asks "did an authorization surface come up at all"
     * (2.5s, measured against the target's starting window), this one asks "did
     * the user come back" (5min, a human-scale budget for a password, an emailed
     * code, or a passkey prompt).
     *
     * 300_000 is not a new number — it is iOS `LogiAuth.swift:32`
     * (`handoffTimeout = .seconds(300)`). The two SDKs must not disagree on how
     * long a login may hang, so raising it later means raising both.
     *
     * Needed because the cancel detector below cannot fire in split-screen or
     * freeform: with multi-resume (API 29+) no RP Activity is stopped or resumed
     * when the logi app opens beside it, so neither the swallowed-launch recovery
     * ([inMultiWindow] gates it) nor the [LogiAuthError.UserCancelled] path runs.
     * Without a deadline that flow waits forever — and because the slot it holds
     * is single-flight ([anyFlowPending]), every later sign-in in the process
     * fails with [LogiAuthError.AlreadyInProgress].
     *
     * Deliberately not configurable, exactly as on iOS. An RP that wants to give
     * up sooner cancels the coroutine, which already works; a knob would invent
     * an asymmetry between the two SDKs that nothing asked for.
     */
    private const val HANDOFF_TIMEOUT_MS = 300_000L

    /**
     * Extra time granted past [HANDOFF_TIMEOUT_MS] while a callback is already
     * being processed ([callbackInFlight]).
     *
     * The token exchange runs inside the callback handler *before* it completes
     * the deferred, so cutting the flow at the deadline while a slow network
     * finishes that exchange would throw away a session the server has already
     * issued. Same race the cancel detector avoids with the same flag.
     */
    private const val EXCHANGE_GRACE_MS = 30_000L

    private var config: LogiAuthConfig? = null
    private var appContext: Context? = null
    // @Volatile like every other cross-thread field here: written from the
    // callback coroutine (Dispatchers.IO) and read by the Activity lifecycle
    // callbacks on the main thread. These two were the only ones missing it.
    @Volatile private var pendingSignIn: CompletableDeferred<Result<LogiSession>>? = null
    private var pendingSignInLaunchedAt: Long = 0L

    /**
     * The [authorize] counterpart to [pendingSignIn]. Only one of the two is
     * ever set: both drive the same launch surface, the same callback Activity,
     * and the same cancel detector, so they must serialize against each other —
     * see [anyFlowPending].
     */
    @Volatile private var pendingAuthorize: CompletableDeferred<Result<LogiCallback>>? = null

    /**
     * True while either flow is awaiting a callback. Every guard and every
     * lifecycle hook must ask this rather than testing one slot: a check that
     * saw only [pendingSignIn] would let an [authorize] run alongside a
     * [signIn], and the second launch would overwrite the first's
     * [pendingAuthorizeUri] and strand it forever.
     */
    private fun anyFlowPending(): Boolean = pendingSignIn != null || pendingAuthorize != null

    /**
     * Claim the single-flight slot for a [signIn], or report that something else
     * holds it. Check-and-set must be atomic: with two entry points, `signIn`
     * and `authorize` starting on different coroutines could both read
     * [anyFlowPending] as false before either assigned its slot, then launch
     * competing flows over one [pendingAuthorizeUri]. The callback prioritizes
     * [pendingAuthorize], so the loser's deferred would never resolve.
     * (codex review P1, 2026-08-10.) Same lock as [claimFallback].
     *
     * `internal` rather than private only so the unit tests can arm a flow: the
     * public entry points need an Activity, `android.net.Uri` and encrypted
     * prefs, none of which exist in a plain JVM test. Not part of the API — Java
     * consumers never see it.
     */
    internal fun claimSignIn(
        deferred: CompletableDeferred<Result<LogiSession>>,
        setUpFlowState: () -> Unit,
    ): Boolean = synchronized(this) {
        if (anyFlowPending()) return@synchronized false
        // Persist the flow's state BEFORE publishing the slot. A callback that
        // observed a claimed slot with no `pendingState` written yet would fail
        // the state check, clear the slot, and make the real callback arrive to
        // nothing. Setup throwing here (encrypted prefs unavailable, say) leaves
        // the slot unclaimed rather than jamming every later flow with
        // AlreadyInProgress. (codex review P2, 2026-08-10.)
        setUpFlowState()
        pendingSignIn = deferred
        true
    }

    /** [claimSignIn] for the backend-led flow. Same visibility reasoning. */
    internal fun claimAuthorize(
        deferred: CompletableDeferred<Result<LogiCallback>>,
        setUpFlowState: () -> Unit,
    ): Boolean = synchronized(this) {
        if (anyFlowPending()) return@synchronized false
        setUpFlowState()
        pendingAuthorize = deferred
        true
    }

    /**
     * The single way a finished flow lets go: give the slot and the shared launch
     * state back **only if [deferred] still owns the slot**, and clear that flow's
     * persisted state ([clearPersisted]) in the same critical section, under the
     * same lock [claimSignIn] / [claimAuthorize] take.
     *
     * Both halves — the lock and the identity check — are load-bearing, and both
     * were learned from bugs:
     *
     * - **The lock.** Done with plain assignments, a concurrent `authorize()`
     *   could claim a new flow and publish its [pendingAuthorizeUri] between two
     *   of them, after which the finishing callback nulled the NEW flow's URI and
     *   the lifecycle fallback had nothing to recover. (codex review P2,
     *   2026-08-10.)
     * - **The identity check.** [signIn] / [authorize] used to tear down in their
     *   own `finally` blocks and the callback handler used to tear down
     *   unconditionally. Both were survivable only while a flow could not end
     *   *before* its callback arrived. [HANDOFF_TIMEOUT_MS] makes exactly that
     *   routine: the caller gives up, the slot is released, the user retries, and
     *   a new flow publishes its own verifier / state / nonce — and then the old
     *   flow's teardown (from its `finally`, or from a token exchange that finally
     *   came back) wipes the retry's state and frees its slot. The retry's
     *   callback then fails with [LogiAuthError.StateMismatch], or hangs to its
     *   own deadline with no fallback left to recover it. (codex review P1,
     *   2026-08-10.)
     *
     * So a release by anyone who no longer owns the slot is a no-op, persisted
     * state included.
     *
     * [clearPersisted] writes encrypted prefs inside the lock. That is cheap
     * (AES over three short strings; `apply()` flushes to disk off-thread) and
     * the only alternative is the race above.
     */
    internal fun releaseFlowIfOwner(
        deferred: CompletableDeferred<*>,
        clearPersisted: () -> Unit,
    ) = synchronized(this) {
        if (pendingSignIn !== deferred && pendingAuthorize !== deferred) return@synchronized
        if (pendingSignIn === deferred) pendingSignIn = null
        if (pendingAuthorize === deferred) pendingAuthorize = null
        pendingAuthorizeUri = null
        clearPersisted()
    }

    /**
     * Complete whichever flow is in flight with [error] and clear both slots.
     * Used by the cancel detector, which has no idea which kind it interrupted.
     */
    internal fun failPendingFlow(error: LogiAuthError) {
        pendingSignIn?.complete(Result.failure(error))
        pendingAuthorize?.complete(Result.failure(error))
        pendingSignIn = null
        pendingAuthorize = null
    }

    /**
     * The whole life of an already-claimed flow: open the authorization surface,
     * wait for the callback under the deadline, and hand the slot back however it
     * ends — callback, deadline, launch failure, or the caller's coroutine being
     * cancelled.
     *
     * One function so [signIn] and [authorize] cannot drift on any of those four
     * exits. They previously repeated the same `try` / `finally` shape, and the
     * split-screen hang this deadline fixes is precisely the kind of bug that
     * drift produces: a deadline added to one path and not the other would leave
     * backend-led (BFF) RPs locked exactly as before.
     *
     * [openSurface] must not be moved out of the `try`. It suspends while waiting
     * for the native handoff, so a caller cancelled in that window never reaches
     * the await, and its slot would stay claimed forever. (codex review P2,
     * 2026-08-10.)
     */
    internal suspend fun <T> runPendingFlow(
        deferred: CompletableDeferred<Result<T>>,
        clearPersisted: () -> Unit,
        openSurface: suspend () -> LogiAuthError?,
    ): Result<T> = try {
        val launchError = openSurface()
        if (launchError != null) Result.failure(launchError) else awaitCallback(deferred)
    } finally {
        releaseFlowIfOwner(deferred, clearPersisted)
    }

    /**
     * Wait for the callback, but not forever — see [HANDOFF_TIMEOUT_MS] for why
     * the lifecycle detector cannot be the only terminator.
     */
    internal suspend fun <T> awaitCallback(
        deferred: CompletableDeferred<Result<T>>,
    ): Result<T> {
        withTimeoutOrNull(HANDOFF_TIMEOUT_MS) { deferred.await() }?.let { return it }
        // The deadline can collide with a landing callback, and the callback must
        // win: the token exchange happens before the deferred is completed, so
        // failing here would discard a session the server already issued. Two
        // ways it collides — the value landed in the same tick the timeout fired
        // (`isCompleted`, in which case this re-await returns immediately), or the
        // exchange is still in flight (`callbackInFlight`) and deserves
        // [EXCHANGE_GRACE_MS] to finish. Cancelling the await never cancels the
        // deferred itself, so nothing is lost by asking again.
        if (deferred.isCompleted || callbackInFlight) {
            withTimeoutOrNull(EXCHANGE_GRACE_MS) { deferred.await() }?.let { return it }
        }
        return Result.failure(LogiAuthError.HandoffTimeout)
    }

    /**
     * Set when our whole app goes to the background after [signIn] launched the
     * authorization surface — i.e. proof that *something* (the logi app or a
     * Custom Tab) actually took the foreground.
     *
     * Needed because `startActivity()` returning normally does NOT mean the
     * target Activity started: when the framework aborts a launch under the
     * background-activity-launch (BAL) rules it reports `START_ABORTED`
     * internally but hands the caller `START_SUCCESS` (AOSP ActivityStarter).
     * Without this flag a silently-aborted handoff is indistinguishable from a
     * successful one, which cost us both the Custom Tabs fallback and an
     * honest error. (2026-07-28, logi focus on MIUI/Android 15: re-using the
     * already-present logi app task was aborted this way and surfaced as
     * "User cancelled the OAuth flow.")
     *
     * Deliberately keyed on the started-Activity count reaching zero rather
     * than on any single Activity pausing: an in-app screen transition pauses
     * one Activity while starting another, and a configuration change tears one
     * down only to rebuild it. Neither means we lost the foreground, and
     * treating them as handoff proof would re-introduce the very bug this
     * guards against. (codex review P2, 2026-07-28.)
     */
    @Volatile private var sawBackgroundSinceLaunch: Boolean = false

    /** Started (visible-lifecycle) Activity count — zero means backgrounded. */
    private var startedActivities: Int = 0

    /**
     * Authorize URL of the in-flight sign-in, kept for the deferred fallback.
     *
     * Typed as [WebLeg], not `Uri`, on purpose: the deferred fallback re-opens
     * this in a Custom Tab, so parking the native leg here would send a browser
     * sign-in to the host that claims `/oauth/authorize*`. That mistake is a
     * plain assignment the compiler would otherwise wave through, and no JVM
     * unit test can reach this code path (it needs `android.net.Uri` and a live
     * Activity lifecycle), so the type is the only guard available.
     */
    @Volatile private var pendingAuthorizeUri: WebLeg? = null

    /** Whether the current sign-in went out via the app-to-app path. */
    @Volatile private var nativeHandoffAttempted: Boolean = false

    /** Guards the deferred Custom Tabs fallback so it fires at most once. */
    @Volatile private var fallbackLaunched: Boolean = false

    /** In-memory JWKS cache (issuer, keys, fetchedAtMillis). Rare rotation, so
     *  a 1h window avoids a round-trip per sign-in; unknown_kid busts it. */
    private var jwksCache: Triple<String, Jwks, Long>? = null
    private const val JWKS_TTL_MS = 3_600_000L

    /**
     * Set when [LogiAuthCallbackActivity] (or any callback handler) starts
     * processing the redirect. The cancel-detector lifecycle callback uses
     * this to avoid racing the in-flight token exchange with a spurious
     * UserCancelled completion.
     */
    @Volatile internal var callbackInFlight: Boolean = false

    /**
     * Call once at Application.onCreate(). Storing the [Context] (as
     * applicationContext) is safe — it never holds an Activity reference.
     *
     * As a side effect we register an Application-level lifecycle callback
     * so that if the user dismisses the Custom Tab without completing OAuth
     * (back button / swipe close), we resolve the suspended [signIn] call
     * with [LogiAuthError.UserCancelled] instead of hanging forever. Codex
     * flagged this on the v1 design.
     */
    @JvmStatic
    fun configure(context: Context, config: LogiAuthConfig) {
        this.config = config
        this.appContext = context.applicationContext
        registerCancelDetector(context.applicationContext as? Application)
    }

    /**
     * Open an authorization Uri that the RP's **backend** built, and hand back
     * only `{ code, state }`. The low-level primitive behind the backend-led
     * (BFF) flow, for RPs registered as `client_type=confidential`.
     *
     * [signIn] cannot serve those RPs: it does the token exchange inside the
     * app, which would require shipping `client_secret` in the APK. This splits
     * the flow so the secret and the PKCE verifier never leave the RP's server.
     *
     * ```kotlin
     * // 1. RP backend mints the transaction and the authorize Uri
     * val start = myBackend.startLogiSignIn()
     *
     * // 2. SDK opens it and recovers the callback — this call
     * val cb = LogiAuth.authorize(activity, Uri.parse(start.authorizeUrl)).getOrThrow()
     *
     * // 3. RP backend exchanges the code and issues its own session
     * myBackend.completeLogiSignIn(start.txnId, cb.code, cb.state)
     * ```
     *
     * [startUri] is logi's `/oauth/authorize` Uri — **not** the RP backend's
     * `/start` endpoint. Calling `/start` is the RP app's job, with its own HTTP
     * client; the SDK never talks to the RP backend.
     *
     * The SDK generates **no** PKCE verifier, state, or nonce here — the backend
     * owns all three, and generating them in the app would put the verifier back
     * on the device. `state` is read out of [startUri] purely to match the
     * callback against this flow.
     *
     * Same single-flight rule and the same launch handling as [signIn]:
     * app-to-app handoff first, Custom Tabs fallback, and the same cancel
     * detector. Pass an Activity context — Custom Tabs requires it.
     *
     * **Does not survive process death.** The suspended call lives in memory, so
     * if Android kills the app while the authorization surface is open, this
     * call dies with it and the returning callback finds nothing to resolve.
     * The recovery is a fresh `/start`: the RP backend owns the transaction, and
     * abandoning one costs nothing but its TTL. [signIn] has the same limit —
     * treat a login that never returns as a login to retry, not as one to
     * resume. Do not persist the code or state to work around this; that would
     * put a live authorization code in app storage.
     */
    @JvmStatic
    suspend fun authorize(
        activity: Context,
        startUri: Uri,
    ): Result<LogiCallback> {
        // `state` comes from the backend, embedded in the Uri it built. Read it
        // back so the callback can be matched to this flow — the SDK is not
        // generating or validating it as a credential, only using it to tell
        // this flow's callback from a stale or injected one.
        //
        // Checked before the config lookup and before the pending slot is armed
        // so a rejected argument never holds the single-flight lock — that would
        // block every later flow with AlreadyInProgress.
        val state = runCatching { startUri.getQueryParameter("state") }.getOrNull()
        if (state.isNullOrEmpty()) return Result.failure(LogiAuthError.MissingStateInStartUri)

        val store = pendingStore() ?: return Result.failure(LogiAuthError.NotConfigured)

        val deferred = CompletableDeferred<Result<LogiCallback>>()
        val claimed = claimAuthorize(deferred) {
            // The callback handler compares against this. No verifier and no
            // nonce are stored: both belong to the backend in this flow, and
            // leaving a stale one here would make the signIn() path read it.
            store.pkceVerifier = null
            store.pendingNonce = null
            store.pendingState = state
        }
        if (!claimed) return Result.failure(LogiAuthError.AlreadyInProgress)

        pendingSignInLaunchedAt = System.currentTimeMillis()
        sawBackgroundSinceLaunch = false

        // Deadline, teardown and cancellation handling all live in
        // [runPendingFlow] — shared with [signIn] so the two cannot diverge.
        // Only `state` is persisted for this flow: the verifier and nonce belong
        // to the RP backend here, so there is nothing else to clear.
        return runPendingFlow(
            deferred,
            clearPersisted = { store.pendingState = null },
        ) {
            // BFF flow: the host is the RP backend's decision (it issued
            // `startUri`), so the SDK does not apply the authorize host split
            // here — overriding a non-stock backend's host would break it.
            // Both legs use `startUri` as given. Same call as the iOS SDK's
            // `authorize(startURL:)`.
            launchAuthorizationSurface(activity, NativeLeg(startUri), WebLeg(startUri))
        }
    }

    /**
     * Begin Authorization Code + PKCE flow. Suspends until the user either
     * completes consent (callback delivered to [LogiAuthCallbackActivity]) or
     * cancels — or, if neither ever happens, until the SDK's five-minute wait
     * deadline fails the call with [LogiAuthError.HandoffTimeout]. To give up
     * sooner, cancel the calling coroutine (e.g. `withTimeout`); the flow is
     * released either way, so the next `signIn()` is accepted.
     *
     * Pass an Activity context — Custom Tabs requires it for startActivity.
     * (Codex flagged this on the Phase 3 internal app where an Application
     * context here threw AndroidRuntimeException.)
     */
    @JvmStatic
    suspend fun signIn(
        activity: Context,
        scopes: List<String>? = null,
    ): Result<LogiSession> {
        val cfg = config ?: return Result.failure(LogiAuthError.NotConfigured)
        val store = pendingStore() ?: return Result.failure(LogiAuthError.NotConfigured)

        // Reject concurrent signIn() calls — mirrors iOS
        // LogiAuthError.alreadyInProgress. Without this guard, a second
        // signIn() overwrites pendingSignIn and strands the first deferred
        // forever. (codex P1, 2026-05-18.)
        // Generated before the claim: these touch no shared state, so a failure
        // here cannot leave the single-flight slot stuck.
        val verifier = Pkce.generateVerifier()
        val challenge = Pkce.s256Challenge(verifier)
        val state = Pkce.randomState()
        // nonce is always generated and always verified — it binds the id_token
        // to this specific authorize request (replay defense). Server echoes it
        // through authorize → grant → id_token (id_token_issuer.rb).
        val nonce = Pkce.randomNonce()

        val deferred = CompletableDeferred<Result<LogiSession>>()
        val claimed = claimSignIn(deferred) {
            store.pkceVerifier = verifier
            store.pendingState = state
            store.pendingNonce = nonce
        }
        if (!claimed) return Result.failure(LogiAuthError.AlreadyInProgress)

        // The web leg, off the untouched issuer host — built first so the
        // fallback Uri cannot pick up a host swap by accident.
        val webAuthorizeUri = Uri.parse(cfg.issuer.trimEnd('/') + "/oauth/authorize")
            .buildUpon()
            .appendQueryParameter("response_type", "code")
            .appendQueryParameter("client_id", cfg.clientId)
            .appendQueryParameter("redirect_uri", cfg.redirectUri)
            .appendQueryParameter("scope", (scopes ?: cfg.scopes).joinToString(" "))
            .appendQueryParameter("state", state)
            .appendQueryParameter("nonce", nonce)
            .appendQueryParameter("code_challenge", challenge)
            .appendQueryParameter("code_challenge_method", "S256")
            .build()
        // Same authorization request, addressed to the handoff host. Only the
        // host differs — state/nonce/code_challenge come off the one Uri above,
        // so the two legs cannot become different requests. Deriving the native
        // leg *from* the web leg (rather than building it separately) is what
        // makes that structural rather than a convention.
        val nativeLeg = NativeLeg(
            Uri.parse(
                AuthorizeHostSplit.withHost(
                    webAuthorizeUri.toString(),
                    cfg.resolvedNativeAuthorizeHost,
                ),
            ),
        )
        val webLeg = WebLeg(webAuthorizeUri)

        pendingSignInLaunchedAt = System.currentTimeMillis()
        sawBackgroundSinceLaunch = false

        // First-try app-to-app handoff (mirrors iOS LogiAuth's
        // universalLinksOnly path + Kakao/Naver SDK pattern). If the logi
        // app is installed, route the authorize Uri to it via explicit
        // Intent.setPackage so the system doesn't show a chooser. On
        // failure (not installed, intent filter mismatch, ActivityNotFound)
        // fall back to Custom Tabs.
        //
        // tryNativeHandoff() returning true only means startActivity() didn't
        // throw — the framework silently converts BAL-aborted launches into a
        // success result. We deliberately do NOT race that with a timeout: a
        // cold-starting logi app can take arbitrarily long to become visible,
        // and launching a browser meanwhile would leave two competing
        // authorization surfaces for one request. Instead the fallback is
        // deferred to the lifecycle callback, which fires only once we know the
        // user is back on our screen with nothing ever having taken the
        // foreground. (codex review P1, 2026-07-28.)
        // Deadline, teardown and cancellation handling live in [runPendingFlow],
        // shared with authorize(). Its teardown also covers the "no browser
        // installed" failure, which used to need its own hand-written cleanup.
        // (codex review 2026-05-18: regression risk if we leave pendingSignIn
        // set.)
        return runPendingFlow(
            deferred,
            clearPersisted = {
                store.pkceVerifier = null
                store.pendingState = null
                store.pendingNonce = null
            },
        ) {
            launchAuthorizationSurface(activity, nativeLeg, webLeg)
        }
    }

    /**
     * App-to-app handoff: launch the logi Android app directly when present.
     * Returns true if the Intent fired, false if we should fall back to
     * Custom Tabs.
     *
     * Why explicit Intent + setPackage instead of an implicit ACTION_VIEW?
     * On Android 11+ the package visibility rules (and chooser UX) mean an
     * implicit VIEW on an https authorize URL won't reliably resolve to the
     * logi app even if it's installed. Checking PackageManager first +
     * pinning the package gives us a deterministic, no-chooser launch when
     * possible, exactly like `Kakao.loginWithKakaoTalk()` does. (The host
     * app needs `<queries><package android:name="com.dcodelabs.logi" />`
     * in its AndroidManifest — documented in the SDK README.)
     */
    /**
     * Open the authorization surface: app-to-app handoff first, Custom Tabs as
     * the fallback. Returns null on success, or the error to fail the caller
     * with. Shared by [signIn] and [authorize] — both need the identical
     * BAL-abort recovery, and duplicating it would let the two drift.
     *
     * The caller must have armed the pending slot, [pendingSignInLaunchedAt],
     * and [sawBackgroundSinceLaunch] *before* calling this: the swallowed-launch
     * detection below reads them.
     *
     * `tryNativeHandoff()` returning true only means startActivity() didn't
     * throw — the framework silently converts BAL-aborted launches into a
     * success result. A swallowed launch leaves the caller resumed, so no
     * lifecycle transition ever fires and the deferred fallback in the cancel
     * detector cannot be the only trigger, or the flow would hang forever.
     * (codex review P1, 2026-07-28.) Waiting on the *starting window* rather
     * than a loaded app keeps this from cutting a legitimately slow cold start
     * short; see [HANDOFF_FOREGROUND_TIMEOUT_MS].
     *
     * The two Uris are the same authorization request on different hosts:
     * [nativeUri] goes to the handoff host that claims `/oauth/authorize*`,
     * [webUri] stays on the issuer host. 🔴 [webUri] must never be the claimed
     * host — the only users who reach the browser leg are those without the
     * logi app, and for them that leg is the entire sign-in. See
     * [LogiAuthConfig.resolvedNativeAuthorizeHost].
     */
    private suspend fun launchAuthorizationSurface(
        activity: Context,
        native: NativeLeg,
        web: WebLeg,
    ): LogiAuthError? {
        // Fallback-only — the cancel detector re-launches this in a Custom Tab,
        // so it must hold the web leg, never the handoff host.
        pendingAuthorizeUri = web
        fallbackLaunched = false
        nativeHandoffAttempted = tryNativeHandoff(activity, native.uri)
        val canDetectHandoffFailure = (activity as? Activity)?.inMultiWindow() != true
        val needsFallback = !nativeHandoffAttempted ||
            canDetectHandoffFailure && !awaitForegroundHandoff() && claimFallback()
        if (needsFallback) {
            try {
                launchCustomTab(activity, web.uri)
            } catch (e: ActivityNotFoundException) {
                return LogiAuthError.Network(e)
            }
        }
        return null
    }

    /**
     * Wait for evidence that the app-to-app handoff took the foreground: our
     * app backgrounding. False on timeout ⇒ the launch was swallowed.
     *
     * A poll loop rather than a suspending signal because the lifecycle
     * callback fires on the main thread while this runs on the caller's
     * coroutine; the flag is @Volatile and the window is short.
     */
    private suspend fun awaitForegroundHandoff(): Boolean =
        withTimeoutOrNull(HANDOFF_FOREGROUND_TIMEOUT_MS) {
            while (!sawBackgroundSinceLaunch) delay(50L)
            true
        } ?: false

    /**
     * Backgrounding is only a meaningful signal when windows are exclusive. In
     * split-screen / freeform the logi app can open beside us with every RP
     * Activity still started, so absence of backgrounding proves nothing and we
     * must not "recover" a handoff that in fact succeeded — that would put two
     * authorization surfaces on one state/PKCE request. We forgo the fallback
     * there and keep the pre-existing behavior. (codex review P2, 2026-07-28.)
     */
    private fun Activity.inMultiWindow(): Boolean =
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.N && isInMultiWindowMode

    /**
     * Claim the one-shot fallback. Both the timeout path and the lifecycle path
     * can reach this concurrently (different threads), so the check-and-set is
     * guarded — otherwise a race opens two Custom Tabs for one request.
     */
    private fun claimFallback(): Boolean = synchronized(this) {
        if (fallbackLaunched) false else { fallbackLaunched = true; true }
    }

    /** Open the authorize URL in a Custom Tab. Throws if no browser handles it. */
    /**
     * Open the browser leg in a Custom Tab, **pinned to a browser package**.
     *
     * 🔴 The pin is the load-bearing part, not a nicety. `launchUrl()` fires a
     * plain `ACTION_VIEW`, and an app that has *verified* App Links for the
     * host wins that intent over any browser. `api.1pass.dev` is currently
     * verified for `com.dcodelabs.logi` (confirmed on-device via
     * `pm get-app-links`), so an unpinned fallback lands right back in the logi
     * app — the exact interception the host split exists to stop, reintroduced
     * on the one leg that has no other way out. Moving the handoff to
     * `open.1pass.dev` does not help here: this leg keeps using the issuer host
     * by design.
     *
     * Resolution order: the browser that advertises Custom Tabs support, then
     * whatever handles a bare `http:` intent, then unpinned. The last step only
     * happens when the device has no browser at all, where an unpinned launch
     * is no worse than failing outright.
     */
    private fun launchCustomTab(context: Context, authorizeUri: Uri) {
        val tabsIntent = CustomTabsIntent.Builder()
            .setShowTitle(true)
            .build()
        browserPackage(context)?.let { tabsIntent.intent.setPackage(it) }
        tabsIntent.launchUrl(context, authorizeUri)
    }

    /**
     * A package that will render a web page — never the logi app.
     *
     * `CustomTabsClient.getPackageName(context, null)` already excludes non
     * browsers, and the `http:` probe below resolves against the browser
     * category only, so neither can return an App Links claimant.
     */
    private fun browserPackage(context: Context): String? {
        CustomTabsClient.getPackageName(context, null)?.let { return it }
        val probe = Intent(Intent.ACTION_VIEW, Uri.parse("http://"))
            .addCategory(Intent.CATEGORY_BROWSABLE)
        @Suppress("DEPRECATION")
        return context.packageManager
            .resolveActivity(probe, PackageManager.MATCH_DEFAULT_ONLY)
            ?.activityInfo
            ?.packageName
            ?.takeIf { it != LOGI_APP_PACKAGE && !it.contains("resolver", ignoreCase = true) }
    }

    private fun tryNativeHandoff(context: Context, authorizeUri: Uri): Boolean {
        if (!isLogiAppInstalled(context)) return false
        return try {
            // signIn() requires an Activity context (documented), so no
            // FLAG_ACTIVITY_NEW_TASK — the logi app should launch as a
            // sibling on the same task stack so iOS-style returnAfterDone
            // semantics work and back-stack navigation behaves correctly.
            val intent = Intent(Intent.ACTION_VIEW, authorizeUri)
                .setPackage(LOGI_APP_PACKAGE)
            context.startActivity(intent)
            true
        } catch (_: ActivityNotFoundException) {
            // PackageManager said the app is installed but it doesn't claim
            // the authorize URI. Fall back to Custom Tabs.
            false
        }
    }

    /**
     * Cheap synchronous check — equivalent to iOS
     * `UIApplication.canOpenURL` for the logi scheme. Public so RPs can
     * render different UI when the app is/isn't installed (e.g. "Continue
     * with logi" button vs "Install logi" prompt).
     */
    @JvmStatic
    fun isLogiAppInstalled(context: Context): Boolean = try {
        val pm = context.packageManager
        // getPackageInfo throws NameNotFoundException when the app isn't
        // installed (or isn't visible under Android 11+ package visibility).
        @Suppress("DEPRECATION")
        pm.getPackageInfo(LOGI_APP_PACKAGE, 0)
        true
    } catch (_: PackageManager.NameNotFoundException) {
        false
    }

    // Token persistence, refresh(), and signOut() are NOT part of the auth
    // core — they live in the optional `:logi-auth-storage` module
    // (LogiAuthStorage). The core connector only proves identity and returns a
    // verified LogiSession; where/whether the session's tokens are stored is
    // the RP app's concern. Only the transient PKCE flow state (verifier /
    // state / nonce) is persisted here, because it must survive process death
    // across the Custom Tab round-trip.

    // ─── Callback handler ────────────────────────────────────────────────

    /**
     * Called by [LogiAuthCallbackActivity] (or a user-supplied Activity
     * that handles the redirect_uri). Resolves the suspended [signIn] call.
     *
     * Public so RPs that prefer to write their own callback Activity can
     * forward the redirect Uri here rather than using the SDK's built-in
     * Activity.
     *
     * **If you write your own callback Activity, set [callbackInFlight] to true
     * synchronously in `onCreate` before launching this suspend function.**
     * This function sets it at entry, but a coroutine dispatch can land after
     * your Activity finishes and the RP Activity resumes — and in that window
     * the cancel detector will read a valid return as a dismissal and complete
     * the flow with [LogiAuthError.UserCancelled]. [LogiAuthCallbackActivity]
     * does exactly this; mirror it. (codex review, 2026-08-10.)
     */
    @JvmStatic
    suspend fun handleAuthorizationCallback(callbackUri: Uri) {
        // [LogiAuthCallbackActivity] sets this before finish() so the cancel
        // detector cannot mistake a landing callback for a dismissal. Every exit
        // from here must clear it, including the early returns below — a stuck
        // flag would disable cancel detection for the rest of the process.
        // Set at entry, not inside the branches: RPs are documented to write
        // their own callback Activity and call this directly, and those never
        // touch [LogiAuthCallbackActivity]'s synchronous claim. Without it the
        // cancel detector can classify a landing callback as a dismissal.
        // (codex review P2, 2026-08-10.)
        callbackInFlight = true
        try {
            handleAuthorizationCallbackInner(callbackUri)
        } finally {
            callbackInFlight = false
        }
    }

    private suspend fun handleAuthorizationCallbackInner(callbackUri: Uri) {
        val cfg = config ?: return
        val store = pendingStore() ?: return

        // Backend-led flow: hand the pair straight back. No token exchange and
        // no id_token verification here — the RP backend owns both, and doing
        // either would need the verifier or the client_secret on the device.
        val authorizeDeferred = pendingAuthorize
        if (authorizeDeferred != null) {
            callbackInFlight = true
            // Compute the outcome first, tear down second, resume the caller
            // last. Two reasons, both found by codex review (2026-08-10):
            //   - `getQueryParameter` throws on an opaque or malformed Uri. If
            //     that escaped, the teardown still ran but nothing ever
            //     completed the deferred, so the caller hung forever.
            //   - completing the deferred can resume the awaiting coroutine
            //     immediately. If it starts another authorize() right away, a
            //     teardown running afterwards would wipe the NEW flow's
            //     pendingState and its callback would fail with StateMismatch.
            val outcome: Result<LogiCallback> = try {
                // State first. `state` is the only thing tying a callback to
                // this flow, so nothing acts on the callback until it matches —
                // otherwise an unsolicited `?error=access_denied&state=wrong`
                // aborts a live flow.
                val state = callbackUri.getQueryParameter("state")
                val error = callbackUri.getQueryParameter("error")
                val code = callbackUri.getQueryParameter("code")
                when {
                    state == null || state != store.pendingState ->
                        Result.failure(LogiAuthError.StateMismatch)
                    error != null -> {
                        val message = callbackUri.getQueryParameter("error_description") ?: error
                        Result.failure(
                            if (error == "access_denied") LogiAuthError.UserCancelled
                            else LogiAuthError.TokenEndpoint(message)
                        )
                    }
                    code == null -> Result.failure(LogiAuthError.InvalidAuthorizeUrl)
                    else -> Result.success(LogiCallback(code = code, state = state))
                }
            } catch (e: LogiAuthError) {
                Result.failure(e)
            } catch (e: Throwable) {
                Result.failure(LogiAuthError.Network(e))
            }

            // Owner-scoped, not unconditional: this callback may be arriving for
            // a flow that already gave up. See the sign-in branch below.
            releaseFlowIfOwner(authorizeDeferred) { store.pendingState = null }
            authorizeDeferred.complete(outcome)
            return
        }

        val deferred = pendingSignIn ?: return  // not awaiting any sign-in

        callbackInFlight = true  // suppress the cancel-detector race
        // Same shape as the authorize branch: compute the outcome, tear down,
        // then resume the caller. Completing first lets the resumed coroutine
        // start another sign-in whose state the teardown would then erase.
        // (codex review P2, 2026-08-10.)
        val outcome: Result<LogiSession> = try {
            // State first — same reasoning as the branch above: an injected
            // error callback must not be able to abort a live sign-in.
            val state = callbackUri.getQueryParameter("state")
            val error = callbackUri.getQueryParameter("error")
            val code = callbackUri.getQueryParameter("code")
            val verifier = store.pkceVerifier
            if (state == null || state != store.pendingState) {
                throw LogiAuthError.StateMismatch
            }
            if (error != null) {
                val message = callbackUri.getQueryParameter("error_description") ?: error
                throw if (error == "access_denied") LogiAuthError.UserCancelled
                      else LogiAuthError.TokenEndpoint(message)
            }
            if (code == null || verifier == null) {
                throw LogiAuthError.InvalidAuthorizeUrl
            }

            val result = TokenExchange(cfg.issuer)
                .exchangeCode(code, verifier, cfg.clientId, cfg.redirectUri)

            // Verify the id_token (public-client trust boundary). This is the
            // sole new safety contract of v1.0 — `sub` is set only after the
            // RS256 signature + claims (incl. nonce) check out. Persist tokens
            // ONLY after verification succeeds: a missing/invalid id_token or a
            // JWKS failure must not leave durable authenticated state that
            // currentAccessToken()/refresh() could later read. (codex P1.)
            val idToken = result.idToken
                ?: throw LogiAuthError.MissingIdToken
            val verified = verifyIdTokenWithRotationRetry(
                issuer = cfg.issuer,
                idToken = idToken,
                expected = VerifyExpected(cfg.tokenIssuer, cfg.clientId, store.pendingNonce),
                accessToken = result.accessToken,
            )
            val email = (verified.claims["email"] as? JsonPrimitive)
                ?.let { if (it.isString) it.content else null }
            val session = LogiSession(
                sub = verified.sub,
                email = email,
                idToken = idToken,
                accessToken = result.accessToken,
                refreshToken = result.refreshToken,
                tokenType = result.tokenType,
                scope = result.scope,
                expiresInSec = result.expiresInSec,
            )
            Result.success(session)
        } catch (e: LogiAuthError) {
            Result.failure(e)
        } catch (e: Throwable) {
            Result.failure(LogiAuthError.Network(e))
        }

        // Owner-scoped teardown, not the unconditional one this used to run. The
        // deferred was read out of the slot at entry, but the token exchange above
        // takes network time, and [HANDOFF_TIMEOUT_MS] can expire during it: the
        // awaiting caller gives up, its slot is released, the user retries, and a
        // NEW flow publishes its own verifier / state / nonce. An unconditional
        // clear here would then wipe the retry's state and free its slot, so the
        // retry's callback would fail with StateMismatch — or hang to its own
        // deadline with nothing left to recover it. (codex review P1, 2026-08-10.)
        //
        // Completing an orphaned deferred is still safe and still done: nobody is
        // awaiting it (the caller already has HandoffTimeout), so the outcome is
        // simply dropped. Dropping a session we can no longer hand to anyone is
        // the right end — the alternative is leaving a completed exchange's tokens
        // reachable by a flow that never asked for them.
        releaseFlowIfOwner(deferred) {
            store.pkceVerifier = null
            store.pendingState = null
            store.pendingNonce = null
        }
        deferred.complete(outcome)
    }

    /**
     * Fetch JWKS (1h cache) and verify. On `unknown_kid` served from a stale
     * cache — i.e. the IdP rotated signing keys within the TTL window — bust the
     * cache, refetch once, and re-verify so normal key rotation doesn't lock out
     * every sign-in for the rest of the hour. Throws [LogiAuthError.IdTokenInvalid]
     * on a genuine verification failure. (codex P1, iOS 2026-07-01.)
     */
    private suspend fun verifyIdTokenWithRotationRetry(
        issuer: String,
        idToken: String,
        expected: VerifyExpected,
        accessToken: String? = null,
    ): VerifiedIdToken {
        val (jwks, fromCache) = fetchJwks(issuer, forceRefresh = false)
        return try {
            verifyIdToken(idToken, jwks, expected, accessToken = accessToken)
        } catch (e: IdTokenVerificationException) {
            if (e.error == IdTokenVerifyError.UNKNOWN_KID && fromCache) {
                val (freshJwks, _) = fetchJwks(issuer, forceRefresh = true)
                try {
                    verifyIdToken(idToken, freshJwks, expected, accessToken = accessToken)
                } catch (retry: IdTokenVerificationException) {
                    throw LogiAuthError.IdTokenInvalid(retry.error.code)
                }
            } else {
                throw LogiAuthError.IdTokenInvalid(e.error.code)
            }
        }
    }

    /**
     * Re-verify an id_token returned by a **refresh_token** exchange before it
     * is trusted or persisted, reusing the same JWKS fetch + key-rotation-retry
     * path as [signIn]. There is no nonce on a refresh, so nonce is not checked
     * (signature / iss / aud / azp / exp / iat / sub are). If [accessToken] and
     * an `at_hash` claim are both present the access_token is bound too.
     *
     * Exposed as module-public so the optional `:logi-auth-storage` companion
     * can call it from `refresh()` without duplicating the (private) rotation
     * logic. The verification config is passed in explicitly so this does not
     * depend on [configure] having been called on this static object.
     *
     * Throws [LogiAuthError.IdTokenInvalid] / [LogiAuthError.JwksFetchFailed] /
     * [LogiAuthError.Network] on failure.
     */
    @JvmStatic
    suspend fun verifyRefreshedIdToken(
        idToken: String,
        accessToken: String?,
        issuer: String,
        tokenIssuer: String,
        clientId: String,
    ): VerifiedIdToken = verifyIdTokenWithRotationRetry(
        issuer = issuer,
        idToken = idToken,
        expected = VerifyExpected(tokenIssuer, clientId, nonce = null),
        accessToken = accessToken,
    )

    private suspend fun fetchJwks(issuer: String, forceRefresh: Boolean): Pair<Jwks, Boolean> {
        val cached = jwksCache
        if (!forceRefresh && cached != null && cached.first == issuer &&
            System.currentTimeMillis() - cached.third < JWKS_TTL_MS
        ) {
            return cached.second to true
        }
        val jwks = JwksClient(issuer).fetch()
        jwksCache = Triple(issuer, jwks, System.currentTimeMillis())
        return jwks to false
    }

    /**
     * Detect Custom Tab dismissal via Application-level lifecycle callback.
     * When the user closes the OAuth Custom Tab without completing consent,
     * no callback Activity is invoked — we'd otherwise sit forever on
     * `deferred.await()`. So when any RP-side Activity resumes after we
     * launched a Custom Tab, AND the callback Activity hasn't fired (i.e.
     * pendingSignIn is still set), AND a small grace period has elapsed
     * (so we don't fire on the same-tick resume that PRECEDES Custom Tabs),
     * we complete with UserCancelled.
     *
     * The 500ms grace handles the resume that fires immediately when
     * Custom Tabs hands focus to the system browser process.
     */
    private var cancelDetectorRegistered = false
    private fun registerCancelDetector(application: Application?) {
        if (application == null || cancelDetectorRegistered) return
        cancelDetectorRegistered = true
        application.registerActivityLifecycleCallbacks(object : Application.ActivityLifecycleCallbacks {
            override fun onActivityResumed(activity: Activity) {
                if (activity is LogiAuthCallbackActivity) return  // success path
                if (callbackInFlight) return  // token exchange racing in IO
                // Either flow can be the one interrupted — an abandoned
                // authorize() must not hang any more than an abandoned
                // signIn(). See [anyFlowPending].
                if (!anyFlowPending()) return
                // Never backgrounded since launch ⇒ no authorization surface was
                // ever shown, so the user cannot have cancelled one. The native
                // handoff was swallowed by the platform (see
                // [sawBackgroundSinceLaunch]); recover by opening the browser
                // now — at this point we know nothing else is competing for the
                // request. Keep the sign-in suspended rather than failing it.
                // Scoped to the un-fallen-back native handoff on purpose. Once
                // we're on the browser path — whether from the start or via the
                // fallback — a still-visible RP is normal (multi-window, partial
                // Custom Tab), so gating on backgrounding there would strand the
                // sign-in and poison later ones with AlreadyInProgress.
                // (codex review P2, 2026-07-28.)
                if (nativeHandoffAttempted && !fallbackLaunched &&
                    !sawBackgroundSinceLaunch && !activity.inMultiWindow()
                ) {
                    // `.uri` only here, at the Custom Tab call: the slot is typed
                    // [WebLeg] so this cannot silently become the handoff host.
                    val web = pendingAuthorizeUri
                    if (web != null && claimFallback()) {
                        runCatching { launchCustomTab(activity, web.uri) }.onFailure {
                            // Clear persisted state BEFORE completing: the
                            // resumed caller can start a new flow the instant
                            // the deferred resolves, and a clear() landing after
                            // that would wipe the NEW transaction's state.
                            // (codex review P2, 2026-08-10.)
                            pendingStore()?.clear()
                            pendingAuthorizeUri = null
                            failPendingFlow(LogiAuthError.Network(it))
                        }
                    }
                    return
                }
                val elapsed = System.currentTimeMillis() - pendingSignInLaunchedAt
                if (elapsed < 500L) return  // pre-Custom-Tabs resume; ignore
                // Persisted cleanup first — same ordering reason as above.
                pendingStore()?.clear()
                pendingAuthorizeUri = null
                failPendingFlow(LogiAuthError.UserCancelled)
            }
            override fun onActivityCreated(activity: Activity, savedInstanceState: Bundle?) {}
            override fun onActivityStarted(activity: Activity) {
                startedActivities++
            }
            override fun onActivityPaused(activity: Activity) {}
            override fun onActivityStopped(activity: Activity) {
                startedActivities = (startedActivities - 1).coerceAtLeast(0)
                // Zero started Activities = we lost the foreground to whatever
                // we just launched. A stop that is only a configuration-change
                // rebuild does not count. Gated on an in-flight sign-in so
                // unrelated backgrounding doesn't arm the cancel detector.
                if (startedActivities == 0 &&
                    !activity.isChangingConfigurations &&
                    anyFlowPending()
                ) {
                    sawBackgroundSinceLaunch = true
                }
            }
            override fun onActivitySaveInstanceState(activity: Activity, outState: Bundle) {}
            override fun onActivityDestroyed(activity: Activity) {}
        })
    }

    private fun pendingStore(): PendingAuthStore? {
        val ctx = appContext ?: return null
        val cfg = config ?: return null
        return PendingAuthStore(ctx, cfg.clientId)
    }
}
