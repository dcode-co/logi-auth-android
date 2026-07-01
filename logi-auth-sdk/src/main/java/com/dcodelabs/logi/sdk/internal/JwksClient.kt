package com.dcodelabs.logi.sdk.internal

import com.dcodelabs.logi.sdk.LogiAuthError
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import okhttp3.OkHttpClient
import okhttp3.Request
import java.util.concurrent.TimeUnit

/**
 * Fetches the IdP's JWKS (`/.well-known/jwks.json`) for id_token signature
 * verification. Minimal OkHttp client, same style as [TokenExchange].
 */
internal class JwksClient(private val issuer: String) {

    private val http = OkHttpClient.Builder()
        .connectTimeout(15, TimeUnit.SECONDS)
        .readTimeout(15, TimeUnit.SECONDS)
        .build()

    private val json = Json { ignoreUnknownKeys = true }

    suspend fun fetch(): Jwks = withContext(Dispatchers.IO) {
        val request = Request.Builder()
            .url(issuer.trimEnd('/') + "/.well-known/jwks.json")
            .get()
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
                throw LogiAuthError.JwksFetchFailed(res.code)
            }
            runCatching { json.decodeFromString<Jwks>(raw) }
                .getOrElse { throw LogiAuthError.JwksFetchFailed(res.code) }
        }
    }
}
