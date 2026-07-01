package com.dcodelabs.logi.sdk.internal

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

/**
 * Transient auth-flow state that must survive process death across the Custom
 * Tab / app-to-app round-trip: the PKCE verifier, the `state`, and the `nonce`.
 *
 * These are single-use flow parameters, cleared the moment the callback is
 * processed (or the sign-in is cancelled). They are NOT the long-lived session
 * tokens — those belong to the optional `:logi-auth-storage` module, per the
 * SDK boundary ("인증만; 토큰 저장은 RP 앱 기능"). We still encrypt them because
 * the PKCE verifier is the proof-of-possession secret for the code exchange.
 *
 * Scoped per-clientId so an RP integrating two logi tenants doesn't collide.
 */
internal class PendingAuthStore(context: Context, clientId: String) {
    private val prefs = EncryptedSharedPreferences.create(
        context.applicationContext,
        "logi_auth_pending_$clientId",
        MasterKey.Builder(context.applicationContext)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build(),
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
    )

    var pkceVerifier: String?
        get() = prefs.getString(KEY_PKCE, null)
        set(v) = prefs.edit().putString(KEY_PKCE, v).apply()

    var pendingState: String?
        get() = prefs.getString(KEY_STATE, null)
        set(v) = prefs.edit().putString(KEY_STATE, v).apply()

    var pendingNonce: String?
        get() = prefs.getString(KEY_NONCE, null)
        set(v) = prefs.edit().putString(KEY_NONCE, v).apply()

    /** Clear all in-flight flow state. Called after callback / on cancel. */
    fun clear() {
        prefs.edit()
            .remove(KEY_PKCE)
            .remove(KEY_STATE)
            .remove(KEY_NONCE)
            .apply()
    }

    private companion object {
        const val KEY_PKCE = "pkce_verifier"
        const val KEY_STATE = "pending_state"
        const val KEY_NONCE = "pending_nonce"
    }
}
