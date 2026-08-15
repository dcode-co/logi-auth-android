package com.dcodelabs.logi.sdk

import android.net.Uri

/**
 * The app-to-app leg of a sign-in — the authorize Uri on the host that claims
 * `/oauth/authorize*`, so an explicit Intent can launch the logi app.
 */
@JvmInline
internal value class NativeLeg(val uri: Uri)

/**
 * The browser leg of a sign-in — the same authorize request on the **issuer**
 * host, which is meant to stay unclaimed.
 *
 * 🔴 The only users who ever reach this leg are the ones without the logi app
 * installed, and for them this leg is the entire sign-in. Putting it on the
 * claimed host is what yanks a browser sign-in into the logi app mid-flow and
 * returns the callback to the wrong browser (the iOS SDK shipped that bug as
 * the axhub `state mismatch` incident).
 *
 * ⚠️ As of 2026-08-15 `api.1pass.dev` is still *verified* for
 * `com.dcodelabs.logi` (checked on-device with `pm get-app-links`), so this
 * host is not actually unclaimed yet — the claim comes off only once every RP
 * has shipped a host-splitting SDK, because removing it earlier would kill the
 * app handoff for RPs still on an older one. Two things keep this leg safe in
 * the meantime: the handoff no longer *needs* this host, and
 * [LogiAuth.launchCustomTab] pins the Custom Tab to a browser package so a
 * verified claimant cannot win the intent.
 *
 * Why two wrapper types instead of two `Uri` parameters: the surface that
 * consumes them ([LogiAuth.launchAuthorizationSurface] and the deferred
 * fallback) cannot be unit-tested — it needs `android.net.Uri` plus a live
 * Activity lifecycle, and this module runs plain JVM tests with no Robolectric.
 * Swapping two same-typed arguments, or parking the wrong one in the pending
 * slot, would compile and pass every test. With these wrappers it does not
 * compile. The host derivation itself is separately pinned by
 * `AuthorizeHostSplitTest`.
 */
@JvmInline
internal value class WebLeg(val uri: Uri)
