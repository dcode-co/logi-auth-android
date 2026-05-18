package com.dcodelabs.logi.sdk

import android.app.Activity
import android.app.Application
import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Bundle
import androidx.browser.customtabs.CustomTabsIntent
import com.dcodelabs.logi.sdk.internal.Pkce
import com.dcodelabs.logi.sdk.internal.TokenExchange
import com.dcodelabs.logi.sdk.internal.TokenStore
import kotlinx.coroutines.CompletableDeferred

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

    private var config: LogiAuthConfig? = null
    private var appContext: Context? = null
    private var pendingSignIn: CompletableDeferred<Result<LogiAuthResult>>? = null
    private var pendingSignInLaunchedAt: Long = 0L

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
    ): Result<LogiAuthResult> {
        val cfg = config ?: return Result.failure(LogiAuthError.NotConfigured)
        val store = tokenStore() ?: return Result.failure(LogiAuthError.NotConfigured)

        // Reject concurrent signIn() calls — mirrors iOS
        // LogiAuthError.alreadyInProgress. Without this guard, a second
        // signIn() overwrites pendingSignIn and strands the first deferred
        // forever. (codex P1, 2026-05-18.)
        if (pendingSignIn != null) return Result.failure(LogiAuthError.AlreadyInProgress)

        val verifier = Pkce.generateVerifier()
        val challenge = Pkce.s256Challenge(verifier)
        val state = Pkce.randomState()
        store.pkceVerifier = verifier
        store.pendingState = state

        val authorizeUri = Uri.parse(cfg.issuer.trimEnd('/') + "/oauth/authorize")
            .buildUpon()
            .appendQueryParameter("response_type", "code")
            .appendQueryParameter("client_id", cfg.clientId)
            .appendQueryParameter("redirect_uri", cfg.redirectUri)
            .appendQueryParameter("scope", (scopes ?: cfg.scopes).joinToString(" "))
            .appendQueryParameter("state", state)
            .appendQueryParameter("code_challenge", challenge)
            .appendQueryParameter("code_challenge_method", "S256")
            .build()

        val deferred = CompletableDeferred<Result<LogiAuthResult>>()
        pendingSignIn = deferred
        pendingSignInLaunchedAt = System.currentTimeMillis()

        // First-try app-to-app handoff (mirrors iOS LogiAuth's
        // universalLinksOnly path + Kakao/Naver SDK pattern). If the logi
        // app is installed, route the authorize Uri to it via explicit
        // Intent.setPackage so the system doesn't show a chooser. On
        // failure (not installed, intent filter mismatch, ActivityNotFound)
        // fall back to Custom Tabs.
        if (!tryNativeHandoff(activity, authorizeUri)) {
            try {
                CustomTabsIntent.Builder()
                    .setShowTitle(true)
                    .build()
                    .launchUrl(activity, authorizeUri)
            } catch (e: ActivityNotFoundException) {
                // No browser / Custom Tabs handler installed. Clean up the
                // suspended state so this call doesn't hang forever, then
                // surface the failure. (codex review 2026-05-18: regression
                // risk if we leave pendingSignIn set.)
                pendingSignIn = null
                store.pkceVerifier = null
                store.pendingState = null
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

    /**
     * Refresh the persisted access token. Returns failure if no refresh
     * token is on file — caller should drop into [signIn] in that case.
     */
    @JvmStatic
    suspend fun refresh(): Result<LogiAuthResult> {
        val cfg = config ?: return Result.failure(LogiAuthError.NotConfigured)
        val store = tokenStore() ?: return Result.failure(LogiAuthError.NotConfigured)
        val refreshToken = store.refreshToken
            ?: return Result.failure(LogiAuthError.NoRefreshToken)

        return runCatching {
            val result = TokenExchange(cfg.issuer)
                .refresh(refreshToken, cfg.clientId, cfg.clientSecret)
            persist(result)
            result
        }
    }

    @JvmStatic
    fun signOut() {
        tokenStore()?.clear()
    }

    /** Synchronous read for early-launch decisions (e.g. show signed-in UI). */
    @JvmStatic
    fun currentRefreshToken(): String? = tokenStore()?.refreshToken

    /** Same idea, the access token. Probably stale — call [refresh] first. */
    @JvmStatic
    fun currentAccessToken(): String? = tokenStore()?.accessToken

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
        val store = tokenStore() ?: return
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
                .exchangeCode(code, verifier, cfg.clientId, cfg.clientSecret, cfg.redirectUri)
            persist(result)
            deferred.complete(Result.success(result))
        } catch (e: LogiAuthError) {
            deferred.complete(Result.failure(e))
        } catch (e: Throwable) {
            deferred.complete(Result.failure(LogiAuthError.Network(e)))
        } finally {
            store.pkceVerifier = null
            store.pendingState = null
            pendingSignIn = null
            callbackInFlight = false
        }
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
                val elapsed = System.currentTimeMillis() - pendingSignInLaunchedAt
                if (elapsed < 500L) return  // pre-Custom-Tabs resume; ignore
                deferred.complete(Result.failure(LogiAuthError.UserCancelled))
                tokenStore()?.let {
                    it.pkceVerifier = null
                    it.pendingState = null
                }
                pendingSignIn = null
            }
            override fun onActivityCreated(activity: Activity, savedInstanceState: Bundle?) {}
            override fun onActivityStarted(activity: Activity) {}
            override fun onActivityPaused(activity: Activity) {}
            override fun onActivityStopped(activity: Activity) {}
            override fun onActivitySaveInstanceState(activity: Activity, outState: Bundle) {}
            override fun onActivityDestroyed(activity: Activity) {}
        })
    }

    private fun tokenStore(): TokenStore? {
        val ctx = appContext ?: return null
        val cfg = config ?: return null
        return TokenStore(ctx, cfg.clientId)
    }

    private fun persist(result: LogiAuthResult) {
        val store = tokenStore() ?: return
        store.accessToken = result.accessToken
        result.refreshToken?.let { store.refreshToken = it }
        result.idToken?.let { store.idToken = it }
    }
}
