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
)
