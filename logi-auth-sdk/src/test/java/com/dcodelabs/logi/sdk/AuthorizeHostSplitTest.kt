package com.dcodelabs.logi.sdk

import com.dcodelabs.logi.sdk.internal.AuthorizeHostSplit
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Pins the authorize host split — the native app-to-app leg goes to the host
 * that claims `/oauth/authorize*`, the browser fallback stays on the issuer.
 *
 * Mirrors the iOS SDK's `AuthorizeHostSplitTests`. The contract these tests
 * defend is asymmetric: sending the **native** leg to the wrong host loses an
 * app launch, but sending the **web** leg to the claimed host loses the sign-in
 * outright for every user who does not have the logi app — that leg is their
 * whole flow.
 */
class AuthorizeHostSplitTest {

    private fun config(
        issuer: String = "https://api.1pass.dev",
        nativeAuthorizeHost: String? = null,
    ) = LogiAuthConfig(
        issuer = issuer,
        clientId = "logi_test",
        redirectUri = "rp://oauth/callback",
        nativeAuthorizeHost = nativeAuthorizeHost,
    )

    // MARK: - resolvedNativeAuthorizeHost

    @Test
    fun `stock production issuer derives the bouncer host`() {
        assertEquals("open.1pass.dev", config().resolvedNativeAuthorizeHost)
    }

    @Test
    fun `explicit host always wins`() {
        assertEquals(
            "open.staging.example",
            config(nativeAuthorizeHost = "open.staging.example").resolvedNativeAuthorizeHost,
        )
    }

    /**
     * `open.1pass.dev` is a production host. Deriving it for a staging or
     * self-hosted deployment would aim the authorize request at a completely
     * different deployment, so a non-stock issuer keeps its own host.
     */
    @Test
    fun `non-stock issuer keeps its own host`() {
        assertEquals(
            "staging.1pass.dev",
            config(issuer = "https://staging.1pass.dev").resolvedNativeAuthorizeHost,
        )
    }

    @Test
    fun `blank explicit host falls through to derivation`() {
        assertEquals("open.1pass.dev", config(nativeAuthorizeHost = "   ").resolvedNativeAuthorizeHost)
    }

    @Test
    fun `issuer host comparison is case insensitive`() {
        assertEquals("open.1pass.dev", config(issuer = "https://API.1Pass.Dev").resolvedNativeAuthorizeHost)
    }

    @Test
    fun `unparseable issuer resolves to null rather than throwing`() {
        assertNull(config(issuer = "not a url").resolvedNativeAuthorizeHost)
    }

    /**
     * A stray space would make `URI()` throw → null → no split at all, leaving
     * the browser leg on the claimed host with nothing logged. Trimming keeps a
     * cosmetic config typo from silently reinstating the bug this feature fixes.
     */
    @Test
    fun `surrounding whitespace in issuer still derives`() {
        assertEquals("open.1pass.dev", config(issuer = "  https://api.1pass.dev  ").resolvedNativeAuthorizeHost)
    }

    /**
     * Sharing a hostname is not being the stock deployment. A custom port or a
     * tenant path is a different server, and derivation there would aim the
     * native leg at production while token exchange stays on the configured
     * issuer — the two legs would hit different deployments.
     */
    @Test
    fun `same host on a custom port does not derive`() {
        assertEquals(
            "api.1pass.dev",
            config(issuer = "https://api.1pass.dev:8443").resolvedNativeAuthorizeHost,
        )
    }

    @Test
    fun `same host under a tenant path does not derive`() {
        assertEquals(
            "api.1pass.dev",
            config(issuer = "https://api.1pass.dev/tenant-a").resolvedNativeAuthorizeHost,
        )
    }

    @Test
    fun `explicit default port still counts as stock`() {
        assertEquals("open.1pass.dev", config(issuer = "https://api.1pass.dev:443").resolvedNativeAuthorizeHost)
    }

    @Test
    fun `trailing slash still counts as stock`() {
        assertEquals("open.1pass.dev", config(issuer = "https://api.1pass.dev/").resolvedNativeAuthorizeHost)
    }

    @Test
    fun `plain http on the stock host does not derive`() {
        assertEquals("api.1pass.dev", config(issuer = "http://api.1pass.dev").resolvedNativeAuthorizeHost)
    }

    // MARK: - withHost

    private val webUrl =
        "https://api.1pass.dev/oauth/authorize" +
            "?response_type=code&client_id=logi_test" +
            "&redirect_uri=rp%3A%2F%2Foauth%2Fcallback" +
            "&scope=openid%20profile%3Abasic&state=STATE&nonce=NONCE" +
            "&code_challenge=CHAL&code_challenge_method=S256"

    @Test
    fun `swaps only the host`() {
        val native = AuthorizeHostSplit.withHost(webUrl, "open.1pass.dev")
        assertEquals(
            webUrl.replace("https://api.1pass.dev/", "https://open.1pass.dev/"),
            native,
        )
    }

    /**
     * The two legs must remain the *same* authorization request — a drifting
     * `state`/`nonce`/`code_challenge` would make the fallback a different
     * request than the one the caller is tracking.
     */
    @Test
    fun `query survives the swap byte for byte`() {
        val native = AuthorizeHostSplit.withHost(webUrl, "open.1pass.dev")
        assertEquals(webUrl.substringAfter('?'), native.substringAfter('?'))
    }

    /** Double-encoding `redirect_uri`/`scope` would break the server match. */
    @Test
    fun `percent encoding is not applied twice`() {
        val native = AuthorizeHostSplit.withHost(webUrl, "open.1pass.dev")
        assertTrue(native.contains("redirect_uri=rp%3A%2F%2Foauth%2Fcallback"))
        assertTrue(native.contains("scope=openid%20profile%3Abasic"))
        assertTrue(!native.contains("%25"))
    }

    @Test
    fun `null or blank host leaves the url untouched`() {
        assertEquals(webUrl, AuthorizeHostSplit.withHost(webUrl, null))
        assertEquals(webUrl, AuthorizeHostSplit.withHost(webUrl, ""))
        assertEquals(webUrl, AuthorizeHostSplit.withHost(webUrl, "  "))
    }

    @Test
    fun `unparseable url is returned as is`() {
        assertEquals("not a url", AuthorizeHostSplit.withHost("not a url", "open.1pass.dev"))
    }

    @Test
    fun `non default port is preserved`() {
        val withPort = "https://staging.1pass.dev:8443/oauth/authorize?state=S"
        assertEquals(
            "https://open.staging.dev:8443/oauth/authorize?state=S",
            AuthorizeHostSplit.withHost(withPort, "open.staging.dev"),
        )
    }

    /**
     * 🔴 The load-bearing assertion. The browser fallback must never be built on
     * the host that claims `/oauth/authorize*` — that claim is what yanks a
     * browser sign-in into the logi app and returns the callback to the wrong
     * browser.
     */
    @Test
    fun `web fallback is never on the claimed handoff host`() {
        val cfg = config()
        val nativeHost = cfg.resolvedNativeAuthorizeHost
        assertEquals("open.1pass.dev", nativeHost)
        // The web leg is built straight off `issuer` and never passed through
        // withHost — this asserts the two hosts are actually distinct, which is
        // the only reason building the web leg off `issuer` is safe.
        assertNotEquals(nativeHost, java.net.URI(cfg.issuer).host)
        assertTrue(webUrl.startsWith("https://api.1pass.dev/"))
    }
}
