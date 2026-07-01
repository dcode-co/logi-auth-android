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
    val scopes: List<String> = listOf("openid", "profile:basic", "email"),
    /**
     * Expected `iss` claim inside the id_token. This is the logi issuer STRING
     * ("logi"), NOT the [issuer] URL — it mirrors the server's `OIDC_ISSUER`
     * (`jwt_verifier.rb`). Only override for a non-standard deployment.
     */
    val tokenIssuer: String = "logi",
)
// NOTE (v1.0): `clientSecret` was removed. This SDK is a **public client** —
// the logi server now accepts (and requires) PKCE-only token exchanges for
// registered public clients (secret rejected + PKCE enforced server-side,
// oauth_application.rb CLIENT_TYPES). Never ship a client secret in a mobile
// app. Register your app as a public client with `logi apps create`.
