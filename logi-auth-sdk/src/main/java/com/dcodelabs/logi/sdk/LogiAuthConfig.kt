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
     * Expected `iss` claim inside the id_token. In production this is the logi
     * issuer URL "https://api.1pass.dev" — it mirrors the server's `OIDC_ISSUER`
     * (`jwt_verifier.rb`). (The bare string "logi" is a dev-only fallback.)
     * Only override for a non-standard deployment.
     */
    val tokenIssuer: String = "https://api.1pass.dev",
    /**
     * Host used **only** for the native app-to-app authorize handoff. Default
     * null → derived, see [resolvedNativeAuthorizeHost].
     *
     * Why the split exists: `api.1pass.dev` claims `/oauth/authorize*` as an
     * Android App Link so the logi app can be launched for native SSO. But that
     * same claim intercepts the **Custom Tabs fallback** of every RP — a browser
     * sign-in gets yanked into the logi app mid-flow and the callback comes back
     * to the wrong browser (the iOS side hit exactly this as the axhub
     * `state mismatch` incident). Keeping the claim on a separate bouncer host
     * lets the native leg keep its app launch while the web leg stays on an
     * unclaimed host.
     *
     * 🔴 This is NOT [issuer]. Token exchange, JWKS, id_token `iss` verification
     * and revoke all stay bound to [issuer]; moving those breaks every sign-in.
     * Only the authorize handoff URL is affected.
     */
    val nativeAuthorizeHost: String? = null,
) {
    /**
     * The host the native handoff Uri is actually built with — the single
     * definition [LogiAuth.signIn] and its tests both read.
     *
     * - An explicit non-blank [nativeAuthorizeHost] always wins.
     * - Otherwise the split applies **only to the stock production issuer**. A
     *   staging or self-hosted deployment gets its own issuer host back, i.e.
     *   the pre-split single-host behaviour.
     *
     * Deriving unconditionally would be wrong: `open.1pass.dev` is a production
     * host, so pointing a staging RP's handoff there would send the authorize
     * request to a different deployment. The SDK cannot know which host a custom
     * deployment claims, so it declines to guess and asks the RP to say so.
     */
    val resolvedNativeAuthorizeHost: String?
        get() {
            nativeAuthorizeHost?.takeIf { it.isNotBlank() }?.let { return it }
            // java.net.URI, not android.net.Uri: this module's tests are plain
            // JVM unit tests with no Robolectric, and the host split is exactly
            // the part that must be pinned by tests.
            // `trim()` before parsing: a stray space in the issuer string makes
            // URI() throw, which would silently resolve to null — i.e. no split,
            // leaving the browser leg on the claimed host with no error anywhere.
            val parsed = runCatching { java.net.URI(issuer.trim()) }.getOrNull() ?: return null
            // The whole issuer must be stock, not just its host. `https://
            // api.1pass.dev:8443` or `https://api.1pass.dev/tenant-a` is a
            // different deployment that merely shares a hostname; derivation
            // there would aim the native leg at production while the token
            // exchange stays on the configured issuer. (codex review P2.)
            val isStockIssuer = parsed.scheme.equals("https", ignoreCase = true) &&
                parsed.host?.lowercase() == DEFAULT_ISSUER_HOST &&
                (parsed.port == -1 || parsed.port == 443) &&
                parsed.path.orEmpty().trim('/').isEmpty() &&
                parsed.rawQuery == null &&
                parsed.rawUserInfo == null
            return if (isStockIssuer) DEFAULT_NATIVE_AUTHORIZE_HOST else parsed.host
        }

    companion object {
        /** The stock production issuer. Also the discriminator for derivation. */
        const val DEFAULT_ISSUER: String = "https://api.1pass.dev"

        /** Host part of [DEFAULT_ISSUER], compared lowercase. */
        const val DEFAULT_ISSUER_HOST: String = "api.1pass.dev"

        /** The bouncer host that keeps the `/oauth/authorize*` App Link claim. */
        const val DEFAULT_NATIVE_AUTHORIZE_HOST: String = "open.1pass.dev"
    }
}
// NOTE (v1.0): `clientSecret` was removed. This SDK is a **public client** —
// the logi server now accepts (and requires) PKCE-only token exchanges for
// registered public clients (secret rejected + PKCE enforced server-side,
// oauth_application.rb CLIENT_TYPES). Never ship a client secret in a mobile
// app. Register your app as a public client with `logi apps create`.
