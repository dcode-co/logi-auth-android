package com.dcodelabs.logi.sdk.internal

import com.dcodelabs.logi.sdk.LogiAuthError
import com.dcodelabs.logi.sdk.LogiAuthResult
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerialName
import kotlinx.serialization.json.Json
import okhttp3.FormBody
import okhttp3.OkHttpClient
import okhttp3.Request
import java.util.concurrent.TimeUnit

/**
 * Minimal /oauth/token client. We deliberately avoid Retrofit so the public
 * SDK surface stays small (no annotations / KSP / reflection). Uses OkHttp +
 * kotlinx-serialization, which most modern Android apps already pull in.
 */
internal class TokenExchange(private val issuer: String) {

    private val http = OkHttpClient.Builder()
        .connectTimeout(15, TimeUnit.SECONDS)
        .readTimeout(15, TimeUnit.SECONDS)
        .build()

    private val json = Json { ignoreUnknownKeys = true; explicitNulls = false }

    // Public client — no client_secret. PKCE (code_verifier) is the proof.
    suspend fun exchangeCode(
        code: String,
        codeVerifier: String,
        clientId: String,
        redirectUri: String,
    ): LogiAuthResult = post(
        FormBody.Builder()
            .add("grant_type", "authorization_code")
            .add("code", code)
            .add("code_verifier", codeVerifier)
            .add("client_id", clientId)
            .add("redirect_uri", redirectUri)
            .build()
    )

    private suspend fun post(body: FormBody): LogiAuthResult = withContext(Dispatchers.IO) {
        val request = Request.Builder()
            .url(issuer.trimEnd('/') + "/oauth/token")
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
