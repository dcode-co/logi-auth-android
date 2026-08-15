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
 * host, which must stay unclaimed.
 *
 * 🔴 The only users who ever reach this leg are the ones without the logi app
 * installed, and for them this leg is the entire sign-in. Putting it on the
 * claimed host is what yanks a browser sign-in into the logi app mid-flow and
 * returns the callback to the wrong browser (the iOS SDK shipped that bug as
 * the axhub `state mismatch` incident).
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
