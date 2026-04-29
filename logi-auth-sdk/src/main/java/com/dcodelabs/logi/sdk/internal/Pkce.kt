package com.dcodelabs.logi.sdk.internal

import android.util.Base64
import java.security.MessageDigest
import java.security.SecureRandom

/**
 * Minimal PKCE (RFC 7636) helpers — we generate a 32-byte verifier, hash it
 * with SHA-256, and base64url-encode (no padding) for the challenge. Same
 * algorithm the logi server expects on the /oauth/authorize call.
 *
 * Lives in this SDK rather than reusing :core:auth so the public AAR has no
 * project-internal dependencies.
 */
internal object Pkce {
    private val rng = SecureRandom()

    fun generateVerifier(): String {
        val bytes = ByteArray(32).also { rng.nextBytes(it) }
        return base64Url(bytes)
    }

    fun s256Challenge(verifier: String): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(verifier.toByteArray())
        return base64Url(digest)
    }

    fun randomState(): String {
        val bytes = ByteArray(16).also { rng.nextBytes(it) }
        return base64Url(bytes)
    }

    private fun base64Url(bytes: ByteArray): String =
        Base64.encodeToString(bytes, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
}
