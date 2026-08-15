package com.dcodelabs.logi.sdk.internal

import java.net.URI

/**
 * Swaps the host of an `/oauth/authorize` URL and nothing else.
 *
 * Why this is a separate, pure object: the host split is the piece that has to
 * be pinned by tests — a web-leg URL that lands on the claimed handoff host
 * breaks browser sign-in for every user without the logi app installed. This
 * module's tests are plain JVM unit tests with no Robolectric, so the logic
 * cannot touch `android.net.Uri`. Working on the string with [URI] keeps it
 * testable while `signIn()` still parses the result into a `Uri`.
 *
 * @see com.dcodelabs.logi.sdk.LogiAuthConfig.resolvedNativeAuthorizeHost
 */
internal object AuthorizeHostSplit {

    /**
     * Return [url] with its host replaced by [host]. Scheme, port, path, query
     * and fragment are preserved verbatim — in particular `state`, `nonce` and
     * `code_challenge`, which must be identical across the two legs or they
     * stop being the same authorization request.
     *
     * Returns [url] unchanged when [host] is null/blank (no derivation was
     * possible — pre-split single-host behaviour) or when [url] cannot be
     * parsed. Declining to rewrite is always safer than emitting a half-built
     * URL: the caller still has a working, if unsplit, authorize request.
     */
    fun withHost(url: String, host: String?): String {
        val target = host?.takeIf { it.isNotBlank() } ?: return url
        return runCatching {
            val parsed = URI(url)
            if (parsed.host == null || parsed.host.equals(target, ignoreCase = true)) return url
            // Raw components: the query is already percent-encoded (redirect_uri
            // and scope carry `:`/`/`/spaces), and the multi-arg URI constructor
            // would encode it a second time.
            buildString {
                append(parsed.scheme).append("://")
                parsed.rawUserInfo?.let { append(it).append('@') }
                append(target)
                if (parsed.port != -1) append(':').append(parsed.port)
                append(parsed.rawPath.orEmpty())
                parsed.rawQuery?.let { append('?').append(it) }
                parsed.rawFragment?.let { append('#').append(it) }
            }
        }.getOrDefault(url)
    }
}
