package com.dcodelabs.logi.sdk.internal

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

/**
 * Encrypted persistence for the SDK. Token files are scoped per-clientId so
 * an RP app that integrates two different logi tenants (rare but possible)
 * keeps their tokens isolated.
 */
internal class TokenStore(context: Context, clientId: String) {
    private val prefs = EncryptedSharedPreferences.create(
        context.applicationContext,
        "logi_auth_sdk_$clientId",
        MasterKey.Builder(context.applicationContext)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build(),
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
    )

    var accessToken: String?
        get() = prefs.getString(KEY_ACCESS, null)
        set(v) = prefs.edit().putString(KEY_ACCESS, v).apply()

    var refreshToken: String?
        get() = prefs.getString(KEY_REFRESH, null)
        set(v) = prefs.edit().putString(KEY_REFRESH, v).apply()

    var idToken: String?
        get() = prefs.getString(KEY_ID, null)
        set(v) = prefs.edit().putString(KEY_ID, v).apply()

    var pkceVerifier: String?
        get() = prefs.getString(KEY_PKCE, null)
        set(v) = prefs.edit().putString(KEY_PKCE, v).apply()

    var pendingState: String?
        get() = prefs.getString(KEY_STATE, null)
        set(v) = prefs.edit().putString(KEY_STATE, v).apply()

    var pendingNonce: String?
        get() = prefs.getString(KEY_NONCE, null)
        set(v) = prefs.edit().putString(KEY_NONCE, v).apply()

    fun clear() = prefs.edit().clear().apply()

    private companion object {
        const val KEY_ACCESS = "access_token"
        const val KEY_REFRESH = "refresh_token"
        const val KEY_ID = "id_token"
        const val KEY_PKCE = "pkce_verifier"
        const val KEY_STATE = "pending_state"
        const val KEY_NONCE = "pending_nonce"
    }
}
