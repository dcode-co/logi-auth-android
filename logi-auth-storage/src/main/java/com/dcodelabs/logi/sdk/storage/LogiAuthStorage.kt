package com.dcodelabs.logi.sdk.storage

import android.content.Context
import com.dcodelabs.logi.sdk.LogiAuth
import com.dcodelabs.logi.sdk.LogiAuthConfig
import com.dcodelabs.logi.sdk.LogiAuthError
import com.dcodelabs.logi.sdk.LogiAuthResult
import com.dcodelabs.logi.sdk.LogiSession
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import okhttp3.FormBody
import okhttp3.OkHttpClient
import okhttp3.Request
import java.util.concurrent.TimeUnit

/**
 * Optional token persistence + refresh for LogiAuth.
 *
 * The `:logi-auth-sdk` core connector deliberately does NOT store the session's
 * tokens — per the SDK boundary ("인증만; 토큰 저장은 RP 앱 기능"), where and
 * whether a session is persisted is the RP's decision. This companion is the
 * batteries-included default for RPs that DO want EncryptedSharedPreferences-
 * backed token persistence and a public-client refresh_token exchange.
 *
 * Usage:
 *
 * ```kotlin
 * val storage = LogiAuthStorage(context, config)
 * val session = LogiAuth.signIn(activity).getOrThrow()
 * storage.persist(session)                    // save tokens (encrypted)
 * ...
 * if (storage.currentRefreshToken() != null) {
 *     val tokens = storage.refresh().getOrThrow()  // fresh access_token
 * }
 * storage.signOut()                           // drop stored tokens
 * ```
 *
 * RPs that keep tokens elsewhere (their own store, in-memory only, or a
 * backend) should not use this type at all.
 */
class LogiAuthStorage(
    private val context: Context,
    private val config: LogiAuthConfig,
) {
    private fun store() = LogiAuthTokenStore(context, config.clientId)

    /** Persist a verified session's tokens (encrypted). */
    fun persist(session: LogiSession) {
        val store = store()
        store.accessToken = session.accessToken
        session.refreshToken?.let { store.refreshToken = it }
        store.idToken = session.idToken
    }

    /** Synchronous read for early-launch decisions (e.g. show signed-in UI). */
    fun currentAccessToken(): String? = store().accessToken

    fun currentRefreshToken(): String? = store().refreshToken

    fun currentIdToken(): String? = store().idToken

    /** Drop all stored tokens. Call on explicit sign-out. */
    fun signOut() = store().clear()

    /**
     * Exchange the stored refresh_token for a fresh access_token (public
     * client — no client_secret), rotating and re-persisting the refresh_token
     * the server returns. Fails with [LogiAuthError.NoRefreshToken] when
     * nothing is stored.
     */
    suspend fun refresh(): Result<LogiAuthResult> {
        val store = store()
        val refreshToken = store.refreshToken
            ?: return Result.failure(LogiAuthError.NoRefreshToken)

        return runCatching {
            val result = postRefresh(refreshToken)
            // A3: a rotated id_token is untrusted input just like the sign-in
            // one — re-verify its signature + claims (no nonce on refresh)
            // BEFORE persisting, so a forged/mismatched id_token can never
            // reach durable state that currentIdToken() would later read. Reuses
            // the SDK's JWKS fetch + rotation-retry path (no duplication). A
            // failure throws → runCatching → Result.failure, nothing persisted.
            result.idToken?.let { rotatedIdToken ->
                LogiAuth.verifyRefreshedIdToken(
                    idToken = rotatedIdToken,
                    accessToken = result.accessToken,
                    issuer = config.issuer,
                    tokenIssuer = config.tokenIssuer,
                    clientId = config.clientId,
                )
            }
            store.accessToken = result.accessToken
            result.refreshToken?.let { store.refreshToken = it }
            result.idToken?.let { store.idToken = it }
            result
        }
    }

    private suspend fun postRefresh(refreshToken: String): LogiAuthResult = withContext(Dispatchers.IO) {
        val body = FormBody.Builder()
            .add("grant_type", "refresh_token")
            .add("refresh_token", refreshToken)
            .add("client_id", config.clientId)
            .build()
        val request = Request.Builder()
            .url(config.issuer.trimEnd('/') + "/oauth/token")
            .post(body)
            .header("Accept", "application/json")
            .build()

        val response = try {
            http.newCall(request).execute()
        } catch (e: Throwable) {
            throw LogiAuthError.Network(e)
        }

        response.use { res ->
            val raw = res.body?.string().orEmpty()
            if (!res.isSuccessful) {
                throw LogiAuthError.TokenEndpoint("HTTP ${res.code}: $raw")
            }
            val dto = runCatching { json.decodeFromString<TokenResponseDto>(raw) }
                .getOrElse { throw LogiAuthError.TokenEndpoint("Malformed JSON: $raw") }
            LogiAuthResult(
                accessToken = dto.accessToken,
                refreshToken = dto.refreshToken,
                idToken = dto.idToken,
                tokenType = dto.tokenType,
                scope = dto.scope,
                expiresInSec = dto.expiresIn,
            )
        }
    }

    private companion object {
        val http: OkHttpClient = OkHttpClient.Builder()
            .connectTimeout(15, TimeUnit.SECONDS)
            .readTimeout(15, TimeUnit.SECONDS)
            .build()
        val json = Json { ignoreUnknownKeys = true; explicitNulls = false }
    }

    @Serializable
    private data class TokenResponseDto(
        @SerialName("access_token") val accessToken: String,
        @SerialName("refresh_token") val refreshToken: String? = null,
        @SerialName("id_token") val idToken: String? = null,
        @SerialName("token_type") val tokenType: String = "Bearer",
        val scope: String? = null,
        @SerialName("expires_in") val expiresIn: Long? = null,
    )
}
