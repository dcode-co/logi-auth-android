package com.dcodelabs.logi.sdk

/**
 * Configuration for the logi RP SDK. Pass to [LogiAuth.configure] once at
 * Application.onCreate() time.
 *
 * @property issuer            base URL of the logi IdP, e.g. "https://api.1pass.dev"
 * @property clientId          the client_id issued when this app was registered
 *                             via `logi apps create` or the developer portal
 * @property redirectUri       the redirect_uri registered for this app. Either
 *                             a custom scheme ("myapp://callback") or an HTTPS
 *                             App Link your app handles. Must EXACTLY match
 *                             the value registered server-side.
 * @property scopes            default OAuth scopes if [LogiAuth.signIn] is
 *                             called without an explicit scope list. The most
 *                             common production set is [openid, profile, email].
 */
data class LogiAuthConfig(
    val issuer: String,
    val clientId: String,
    val redirectUri: String,
    val scopes: List<String> = listOf("openid", "profile", "email"),
    /**
     * The logi server's `authenticate_oauth_client!` currently rejects token
     * exchanges with a blank `client_secret` (returns 401 invalid_client) —
     * even on PKCE flows. So mobile RPs do still need to pass the secret
     * here until the server relaxes that for public clients.
     *
     * Storing a secret in a mobile app is a known compromise; minimize the
     * blast radius by:
     *   - using a per-installation secret you fetched at runtime if you have
     *     one (rare), OR
     *   - rotating regularly via `logi apps rotate-secret`, OR
     *   - migrating to short-lived assertions once the server supports them.
     */
    val clientSecret: String? = null,
)
