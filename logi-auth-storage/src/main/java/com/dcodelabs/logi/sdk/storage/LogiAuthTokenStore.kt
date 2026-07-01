package com.dcodelabs.logi.sdk.storage

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

/**
 * Encrypted persistence for a verified session's long-lived tokens. Scoped
 * per-clientId so an RP integrating two logi tenants keeps them isolated.
 */
internal class LogiAuthTokenStore(context: Context, clientId: String) {
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

    fun clear() = prefs.edit().clear().apply()

    private companion object {
        const val KEY_ACCESS = "access_token"
        const val KEY_REFRESH = "refresh_token"
        const val KEY_ID = "id_token"
    }
}
