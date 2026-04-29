package com.dcodelabs.logi.sdk

import android.content.Context
import android.net.Uri
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

    private var config: LogiAuthConfig? = null
    private var appContext: Context? = null
    private var pendingSignIn: CompletableDeferred<Result<LogiAuthResult>>? = null

    /**
     * Call once at Application.onCreate(). Storing the [Context] (as
     * applicationContext) is safe — it never holds an Activity reference.
     */
    @JvmStatic
    fun configure(context: Context, config: LogiAuthConfig) {
        this.config = config
        this.appContext = context.applicationContext
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

        CustomTabsIntent.Builder()
            .setShowTitle(true)
            .build()
            .launchUrl(activity, authorizeUri)

        return deferred.await()
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
            val result = TokenExchange(cfg.issuer).refresh(refreshToken, cfg.clientId)
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
        }
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
