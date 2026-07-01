package com.dcodelabs.logi.sdk

/**
 * Successful auth result returned from [LogiAuth.signIn] / [LogiAuth.refresh].
 *
 * Mirrors the iOS [LogiAuthResult] surface so server / client teams share a
 * mental model. Note id_token is only present when "openid" was in the
 * requested scope set.
 */
data class LogiAuthResult(
    val accessToken: String,
    val refreshToken: String?,
    val idToken: String?,
    val tokenType: String,
    val scope: String?,
    val expiresInSec: Long?,
)

/**
 * The verified outcome of a successful [LogiAuth.signIn]. [sub] is populated
 * only after this SDK has verified the id_token's RS256 signature and claims —
 * the sole new safety contract of v1.0. Identical shape across all 4 SDKs.
 */
data class LogiSession(
    /** Verified subject from the id_token — pairwise per client. */
    val sub: String,
    /** `email` claim, if present and the scope was granted. */
    val email: String?,
    /** Raw id_token (already verified by this SDK). */
    val idToken: String,
    val accessToken: String,
    val refreshToken: String?,
    val tokenType: String,
    val scope: String?,
    val expiresInSec: Long?,
)

/**
 * Sealed error hierarchy. Use [LogiAuthError] in a try/catch around
 * [LogiAuth.signIn] / [LogiAuth.refresh] for typed handling, or fall back to
 * the standard kotlin.Result success/failure pattern those methods return.
 */
sealed class LogiAuthError(message: String, cause: Throwable? = null) : RuntimeException(message, cause) {
    object NotConfigured : LogiAuthError(
        "LogiAuth not configured — call LogiAuth.configure(context, config) first."
    )
    object InvalidAuthorizeUrl : LogiAuthError("Could not build the OAuth authorize URL.")
    object StateMismatch : LogiAuthError(
        "OAuth state parameter did not match — possible CSRF / hijack."
    )
    object UserCancelled : LogiAuthError("User cancelled the OAuth flow.")
    object AlreadyInProgress : LogiAuthError(
        "A signIn() call is already in progress — await or cancel the previous one first."
    )
    object NoRefreshToken : LogiAuthError(
        "No refresh token persisted — user must call signIn() interactively."
    )
    object MissingIdToken : LogiAuthError(
        "Token response had no id_token — was `openid` in the requested scopes?"
    )
    class IdTokenInvalid(val code: String) : LogiAuthError("id_token verification failed ($code).")
    class JwksFetchFailed(val status: Int) : LogiAuthError("JWKS fetch failed (HTTP $status).")
    class TokenEndpoint(detail: String) : LogiAuthError("/oauth/token rejected the exchange: $detail")
    class Network(cause: Throwable) : LogiAuthError("Network error: ${cause.message}", cause)
}
