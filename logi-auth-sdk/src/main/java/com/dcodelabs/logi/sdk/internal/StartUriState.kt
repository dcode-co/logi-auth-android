package com.dcodelabs.logi.sdk.internal

import java.net.URI
import java.net.URLDecoder

/**
 * Reads the `state` query parameter out of an authorize start URL, with the
 * three verdicts `authorize()`'s launch-time validation needs to tell apart.
 *
 * Pure and string-based for the same reason as [AuthorizeHostSplit]: this
 * module's tests are plain JVM unit tests with no Robolectric, and the input
 * validation is exactly the part that must be pinned by tests (a bad pair must
 * be rejected *before* anything is launched). `android.net.Uri` would make it
 * untestable; `authorize()` passes `uri.toString()`.
 *
 * Duplicated `state` keys are their own verdict rather than "first wins":
 * which of the two the server echoes back is server-dependent, and guessing
 * wrong fails the callback match after the user has already authenticated.
 */
/**
 * Launch-time validation of an `authorize(startUri, nativeStartUri)` pair.
 *
 * The contract is "the same authorization request, host swapped": everything
 * except the host — scheme, port, path and the **byte-exact** raw query — must
 * be identical. Comparing only `state` would let `redirect_uri` drift strand
 * the handoff until timeout, and let PKCE drift fail the backend exchange after
 * the user has already authenticated. (codex review P2, 2026-08-15.)
 */
internal sealed class StartUriPairVerdict {
    /** Pair is one request; carries the shared `state`. */
    data class Ok(val state: String) : StartUriPairVerdict()

    /** Web leg has no usable `state` → `MissingStateInStartUri`. */
    object MissingState : StartUriPairVerdict()

    /** Duplicated `state`, or the pair differs beyond the host → `StartUriPairMismatch`. */
    object PairMismatch : StartUriPairVerdict()

    companion object {
        fun validate(startUri: String, nativeStartUri: String?): StartUriPairVerdict {
            val state = when (val v = StartUriState.read(startUri)) {
                is StartUriState.One -> v.value
                StartUriState.Missing -> return MissingState
                StartUriState.Duplicated -> return PairMismatch
            }
            if (nativeStartUri == null) return Ok(state)

            val web = runCatching { URI(startUri.trim()) }.getOrNull() ?: return PairMismatch
            val native = runCatching { URI(nativeStartUri.trim()) }.getOrNull() ?: return PairMismatch
            val same = web.scheme.equals(native.scheme, ignoreCase = true) &&
                web.port == native.port &&
                web.rawPath == native.rawPath &&
                web.rawQuery == native.rawQuery
            return if (same) Ok(state) else PairMismatch
        }
    }
}

internal sealed class StartUriState {
    /** Exactly one non-empty `state`. */
    data class One(val value: String) : StartUriState()

    /** No `state`, an empty one, or an unparseable URL. */
    object Missing : StartUriState()

    /** More than one `state` key. */
    object Duplicated : StartUriState()

    companion object {
        fun read(url: String): StartUriState {
            val rawQuery = runCatching { URI(url).rawQuery }.getOrNull() ?: return Missing
            // Percent-decode values to match android.net.Uri.getQueryParameter's
            // behaviour — the state travels percent-encoded when it carries
            // reserved characters, and the callback side compares decoded.
            val states = rawQuery.split('&')
                .filter { it.substringBefore('=') == "state" }
                .map { param ->
                    param.substringAfter('=', missingDelimiterValue = "").let {
                        runCatching { URLDecoder.decode(it, "UTF-8") }.getOrDefault(it)
                    }
                }
            return when {
                states.size > 1 -> Duplicated
                states.singleOrNull().isNullOrEmpty() -> Missing
                else -> One(states.single())
            }
        }
    }
}
