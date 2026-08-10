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
 * What [LogiAuth.authorize] hands back: the two values the authorization server
 * put on the redirect, and nothing else.
 *
 * Deliberately carries no tokens and no PKCE verifier. In the backend-led (BFF)
 * flow those live only on the RP's server — the app never sees them, so a
 * compromised app cannot leak them. The RP forwards [code] and [state] to its
 * own backend along with the `txn_id` it got from `/start`, and the backend does
 * the token exchange with `client_secret` + `code_verifier`.
 *
 * [state] is echoed back for the RP to pass along; it is **not** a credential.
 * The backend authenticates the completion request by its own transaction
 * record, not by this value.
 *
 * Mirrors iOS `LogiCallback`.
 */
data class LogiCallback(
    val code: String,
    val state: String,
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

    /**
     * [LogiAuth.authorize] was handed a start Uri with no `state` query
     * parameter. The RP's backend must put one there — without it the SDK
     * cannot tell this flow's callback from a stale or injected one.
     */
    object MissingStateInStartUri : LogiAuthError(
        "The authorize Uri has no state parameter — the RP backend must include one."
    )
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
