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
import androidx.browser.customtabs.CustomTabsIntent
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

    private var config: LogiAuthConfig? = null
    private var appContext: Context? = null
    private var pendingSignIn: CompletableDeferred<Result<LogiSession>>? = null
    private var pendingSignInLaunchedAt: Long = 0L

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

    /** Authorize URL of the in-flight sign-in, kept for the deferred fallback. */
    @Volatile private var pendingAuthorizeUri: Uri? = null

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
     * Begin Authorization Code + PKCE flow. Suspends until the user either
     * completes consent (callback delivered to [LogiAuthCallbackActivity])
     * or cancels.
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
        if (pendingSignIn != null) return Result.failure(LogiAuthError.AlreadyInProgress)

        val verifier = Pkce.generateVerifier()
        val challenge = Pkce.s256Challenge(verifier)
        val state = Pkce.randomState()
        // nonce is always generated and always verified — it binds the id_token
        // to this specific authorize request (replay defense). Server echoes it
        // through authorize → grant → id_token (id_token_issuer.rb).
        val nonce = Pkce.randomNonce()
        store.pkceVerifier = verifier
        store.pendingState = state
        store.pendingNonce = nonce

        val authorizeUri = Uri.parse(cfg.issuer.trimEnd('/') + "/oauth/authorize")
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

        val deferred = CompletableDeferred<Result<LogiSession>>()
        pendingSignIn = deferred
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
        pendingAuthorizeUri = authorizeUri
        fallbackLaunched = false
        nativeHandoffAttempted = tryNativeHandoff(activity, authorizeUri)
        // A swallowed launch leaves the caller resumed, so no lifecycle
        // transition ever fires — the deferred fallback below cannot be the only
        // trigger or signIn() would hang forever. (codex review P1, 2026-07-28.)
        // Waiting on the starting window rather than a loaded app keeps this
        // from cutting a legitimately slow cold start short; see
        // [HANDOFF_FOREGROUND_TIMEOUT_MS].
        val canDetectHandoffFailure = (activity as? Activity)?.inMultiWindow() != true
        val needsFallback = !nativeHandoffAttempted ||
            canDetectHandoffFailure && !awaitForegroundHandoff() && claimFallback()
        if (needsFallback) {
            try {
                launchCustomTab(activity, authorizeUri)
            } catch (e: ActivityNotFoundException) {
                // No browser / Custom Tabs handler installed. Clean up the
                // suspended state so this call doesn't hang forever, then
                // surface the failure. (codex review 2026-05-18: regression
                // risk if we leave pendingSignIn set.)
                pendingSignIn = null
                pendingAuthorizeUri = null
                store.pkceVerifier = null
                store.pendingState = null
                store.pendingNonce = null
                return Result.failure(LogiAuthError.Network(e))
            }
        }

        return deferred.await()
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
    private fun launchCustomTab(context: Context, authorizeUri: Uri) {
        CustomTabsIntent.Builder()
            .setShowTitle(true)
            .build()
            .launchUrl(context, authorizeUri)
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
     */
    @JvmStatic
    suspend fun handleAuthorizationCallback(callbackUri: Uri) {
        val cfg = config ?: return
        val store = pendingStore() ?: return
        val deferred = pendingSignIn ?: return  // not awaiting any sign-in

        callbackInFlight = true  // suppress the cancel-detector race
        try {
            val error = callbackUri.getQueryParameter("error")
            if (error != null) {
                val message = callbackUri.getQueryParameter("error_description") ?: error
                deferred.complete(Result.failure(
                    if (error == "access_denied") LogiAuthError.UserCancelled
                    else LogiAuthError.TokenEndpoint(message)
                ))
                return
            }

            val code = callbackUri.getQueryParameter("code")
            if (code == null) {
                deferred.complete(Result.failure(LogiAuthError.InvalidAuthorizeUrl))
                return
            }
            val state = callbackUri.getQueryParameter("state")
            if (state != store.pendingState) {
                deferred.complete(Result.failure(LogiAuthError.StateMismatch))
                return
            }
            val verifier = store.pkceVerifier
            if (verifier == null) {
                deferred.complete(Result.failure(LogiAuthError.InvalidAuthorizeUrl))
                return
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
            deferred.complete(Result.success(session))
        } catch (e: LogiAuthError) {
            deferred.complete(Result.failure(e))
        } catch (e: Throwable) {
            deferred.complete(Result.failure(LogiAuthError.Network(e)))
        } finally {
            store.pkceVerifier = null
            store.pendingState = null
            store.pendingNonce = null
            pendingSignIn = null
            pendingAuthorizeUri = null
            callbackInFlight = false
        }
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
                val deferred = pendingSignIn ?: return
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
                    val uri = pendingAuthorizeUri
                    if (uri != null && claimFallback()) {
                        runCatching { launchCustomTab(activity, uri) }.onFailure {
                            deferred.complete(Result.failure(LogiAuthError.Network(it)))
                            pendingStore()?.clear()
                            pendingSignIn = null
                            pendingAuthorizeUri = null
                        }
                    }
                    return
                }
                val elapsed = System.currentTimeMillis() - pendingSignInLaunchedAt
                if (elapsed < 500L) return  // pre-Custom-Tabs resume; ignore
                deferred.complete(Result.failure(LogiAuthError.UserCancelled))
                pendingStore()?.clear()
                pendingSignIn = null
                pendingAuthorizeUri = null
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
                    pendingSignIn != null
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
