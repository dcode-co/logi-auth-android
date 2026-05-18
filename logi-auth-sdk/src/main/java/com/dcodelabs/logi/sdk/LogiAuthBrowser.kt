package com.dcodelabs.logi.sdk

import android.app.Activity
import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.net.Uri

/**
 * In-app browser detection + escape helpers — mirror of the iOS
 * [LogiAuthBrowser] surface.
 *
 * Most Korean / global social apps embed pages in a WebView that suppresses
 * App Links / Custom Tabs handoff. RPs that host their own WebView (or
 * that ship a JS surface in WebView for shared content) can call
 * [detect] on the incoming `User-Agent` header and, when an in-app browser
 * is identified, call [tryEscape] to bounce the URL back to the system
 * browser via the platform escape scheme.
 *
 * Native app→logi handoff via [LogiAuth.signIn] isn't affected by these
 * browsers — Custom Tabs already runs outside any RP WebView. These
 * helpers are for RP-owned WebViews and for shared marketing pages.
 *
 * Pattern catalog matches the iOS SDK exactly so behaviour is portable.
 */
object LogiAuthBrowser {

    /** Identified in-app browser environments. */
    enum class InApp(val pattern: Regex) {
        KAKAO_TALK(Regex("KAKAOTALK", RegexOption.IGNORE_CASE)),
        NAVER(Regex("NAVER\\(inapp", RegexOption.IGNORE_CASE)),
        FACEBOOK(Regex("FB_IAB|FBAN|FBAV", RegexOption.IGNORE_CASE)),
        INSTAGRAM(Regex("Instagram", RegexOption.IGNORE_CASE)),
        LINE(Regex("Line/", RegexOption.IGNORE_CASE)),
        WECHAT(Regex("MicroMessenger", RegexOption.IGNORE_CASE)),
        TIKTOK(Regex("BytedanceWebview|musical_ly", RegexOption.IGNORE_CASE)),
        TWITTER(Regex("Twitter for iPhone|Twitter for iPad", RegexOption.IGNORE_CASE)),
    }

    /**
     * Identify the in-app browser environment from a User-Agent string.
     * Returns null when the UA looks like a normal mobile browser.
     */
    @JvmStatic
    fun detect(userAgent: String): InApp? =
        InApp.values().firstOrNull { it.pattern.containsMatchIn(userAgent) }

    /**
     * Build a deep-link URI that asks the host in-app browser to re-open
     * [targetUrl] in the system browser. Returns null when the in-app
     * browser doesn't publish a workable escape scheme — caller should
     * render copy-URL UX instead.
     *
     * Sources (kept in sync with iOS LogiAuthBrowser):
     * - KakaoTalk: community-documented (Kakao DevTalk), not in official
     *   SDK docs. Production-stable but no SLA from Kakao.
     * - Naver: official NAVER Developers URL scheme guide.
     * - LINE: no public escape from inside the in-app browser. The
     *   `openExternalBrowser=1` query-param trick only works when opening
     *   the URL FROM a LINE chat, not after the user is already in the
     *   in-app browser. Return null.
     * - Facebook / Instagram / WeChat / TikTok / Twitter: no public
     *   scheme. On Android, the canonical fallback is [chromeIntentUri].
     */
    @JvmStatic
    fun escapeUri(inApp: InApp, targetUrl: String): Uri? {
        val encoded = Uri.encode(targetUrl)
        return when (inApp) {
            InApp.KAKAO_TALK -> Uri.parse("kakaotalk://web/openExternal?url=$encoded")
            InApp.NAVER      -> Uri.parse("naversearchapp://inappbrowser?url=$encoded&target=new")
            else             -> null
        }
    }

    /**
     * Fallback for in-app browsers without a public escape scheme: launch
     * Chrome directly via `intent://`. Caller decides whether to attempt
     * this (it surfaces a UI jump and only works if Chrome is installed).
     */
    @JvmStatic
    fun chromeIntentUri(targetUrl: String): String {
        val stripped = targetUrl.replace(Regex("^https?://"), "")
        return "intent://$stripped#Intent;scheme=https;package=com.android.chrome;" +
            "S.browser_fallback_url=${Uri.encode(targetUrl)};end"
    }

    /**
     * Convenience: detect via [userAgent] and launch the escape URI if one
     * exists. Returns true when an Intent fired, false when the caller
     * should fall back to manual UX (copy-URL prompt).
     *
     * Accepts any [Context]; if a non-Activity context is passed we add
     * FLAG_ACTIVITY_NEW_TASK to avoid the AndroidRuntimeException that
     * would otherwise be thrown (codex review 2026-05-18). Activity
     * context is still preferred so back-stack behaviour matches the
     * RP's expectation.
     */
    @JvmStatic
    fun tryEscape(context: Context, targetUrl: String, userAgent: String): Boolean {
        val inApp = detect(userAgent) ?: return false
        val uri = escapeUri(inApp, targetUrl) ?: return false
        val intent = Intent(Intent.ACTION_VIEW, uri).apply {
            if (context !is Activity) addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        return try {
            context.startActivity(intent)
            true
        } catch (_: ActivityNotFoundException) {
            false
        }
    }
}
