package com.dcodelabs.logi.sdk.internal

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.doubleOrNull
import kotlinx.serialization.json.jsonPrimitive
import java.math.BigInteger
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.RSAPublicKeySpec

// RS256 id_token 검증 — JDK java.security(zero third-party deps).
// 서버 검증 규칙 mirror: logi server/app/lib/oauth/jwt_verifier.rb
//   kid 필수 → JWKS 조회 → RS256 서명검증 → iss · aud · exp · iat · nonce · sub.
// 4플랫폼 공통 골든 벡터(../../test-vectors/id-token-vectors.json)를 동일 통과해야 함.
//
// 왜 서드파티 JWT 라이브러리를 안 쓰나: iOS(Security.framework)/Web(WebCrypto)가
// 각자 시스템 primitive로 zero-dep 검증한 것과 대칭. RP AAR에 전이 의존성을 추가하지
// 않는 "얇은 커넥터" 원칙. base64url은 API 23 + JVM 유닛테스트 양쪽에서 동작하도록
// 수동 디코딩(android.util.Base64/java.util.Base64 API26 모두 회피).
//
// 주의: 이 SDK는 public client(backend 없는 모바일)용 자체 검증 경로다. backend 있는
// confidential RP는 backend가 검증하는 게 표준이며 이 함수를 쓸 필요가 없다.

/** Failure reasons; `code` mirrors the Web verifier and golden-vector strings. */
enum class IdTokenVerifyError(val code: String) {
    MALFORMED("malformed"),
    MISSING_KID("missing_kid"),
    UNKNOWN_KID("unknown_kid"),
    BAD_SIGNATURE("bad_signature"),
    ISS_MISMATCH("iss_mismatch"),
    AUD_MISMATCH("aud_mismatch"),
    EXPIRED("expired"),
    NONCE_MISMATCH("nonce_mismatch"),
    MISSING_CLAIM("missing_claim"),
}

/** Thrown by [verifyIdToken]. Carries the machine [error] (and its `.code`). */
class IdTokenVerificationException(val error: IdTokenVerifyError) :
    Exception("id_token verification failed: ${error.code}")

@Serializable
data class Jwk(
    val kty: String,
    val n: String,
    val e: String,
    val kid: String,
    val alg: String? = null,
    val use: String? = null,
)

@Serializable
data class Jwks(val keys: List<Jwk>)

data class VerifyExpected(
    /** id_token.iss must equal this (logi issuer URL "https://api.1pass.dev" in prod; "logi" is a dev-only fallback). */
    val issuer: String,
    /** id_token.aud must contain this (the RP's client_id). */
    val clientId: String,
    /** If non-null, id_token.nonce must equal this (the value sent in authorize). */
    val nonce: String? = null,
)

data class VerifiedIdToken(val sub: String, val claims: JsonObject)

private val jsonParser = Json { ignoreUnknownKeys = true }

/**
 * Verify a logi-issued id_token and return its verified subject. Throws
 * [IdTokenVerificationException] on any failure — never returns an unverified
 * subject. Claim order matches server + Web/iOS:
 * signature → iss → aud → exp → iat → nonce → sub.
 *
 * @param now Unix seconds; defaults to now. Injectable for deterministic tests.
 * @param clockSkewSec allowed clock skew in seconds (default 60).
 */
fun verifyIdToken(
    idToken: String,
    jwks: Jwks,
    expected: VerifyExpected,
    now: Long = System.currentTimeMillis() / 1000,
    clockSkewSec: Long = 60,
): VerifiedIdToken {
    val parts = idToken.split(".")
    if (parts.size != 3 || parts[0].isEmpty() || parts[1].isEmpty() || parts[2].isEmpty()) {
        throw IdTokenVerificationException(IdTokenVerifyError.MALFORMED)
    }

    val header = decodeJsonSegment(parts[0]) ?: throw IdTokenVerificationException(IdTokenVerifyError.MALFORMED)
    val payload = decodeJsonSegment(parts[1]) ?: throw IdTokenVerificationException(IdTokenVerifyError.MALFORMED)

    // Only RS256 is accepted — never verify a token whose header declares
    // another (or no) algorithm, even if the RSA signature happens to match.
    if (stringClaim(header, "alg") != "RS256") {
        throw IdTokenVerificationException(IdTokenVerifyError.BAD_SIGNATURE)
    }

    // kid → JWKS key.
    val kid = stringClaim(header, "kid")
    if (kid.isNullOrEmpty()) throw IdTokenVerificationException(IdTokenVerifyError.MISSING_KID)
    val jwk = jwks.keys.firstOrNull { it.kid == kid }
        ?: throw IdTokenVerificationException(IdTokenVerifyError.UNKNOWN_KID)

    // RS256 signature verification via java.security (no dependency).
    val signature = base64UrlDecode(parts[2]) ?: throw IdTokenVerificationException(IdTokenVerifyError.BAD_SIGNATURE)
    if (!verifyRs256(signingInput = "${parts[0]}.${parts[1]}", signature = signature, jwk = jwk)) {
        throw IdTokenVerificationException(IdTokenVerifyError.BAD_SIGNATURE)
    }

    // Claim checks (order: iss → aud → exp → iat → nonce → sub).
    if (stringClaim(payload, "iss") != expected.issuer) {
        throw IdTokenVerificationException(IdTokenVerifyError.ISS_MISMATCH)
    }

    if (!audienceMatches(payload["aud"], expected.clientId)) {
        throw IdTokenVerificationException(IdTokenVerifyError.AUD_MISMATCH)
    }

    // OIDC §3.1.3.7 azp: with multiple audiences an azp MUST be present; whenever
    // azp is present it MUST equal our client_id.
    val audElement = payload["aud"]
    val azp = payload["azp"]
    val azpString = (azp as? JsonPrimitive)?.let { if (it.isString) it.content else null }
    if (audElement is JsonArray && audElement.size > 1) {
        if (azpString != expected.clientId) throw IdTokenVerificationException(IdTokenVerifyError.AUD_MISMATCH)
    } else if (azp != null && azp !is JsonNull) {
        if (azpString != expected.clientId) throw IdTokenVerificationException(IdTokenVerifyError.AUD_MISMATCH)
    }

    val exp = numericClaim(payload["exp"])
    if (exp == null || exp <= now - clockSkewSec) {
        throw IdTokenVerificationException(IdTokenVerifyError.EXPIRED)
    }

    val iat = numericClaim(payload["iat"])
    if (iat == null || iat > now + clockSkewSec) {
        // iat missing or in the future → malformed (mirrors Web/iOS verifier).
        throw IdTokenVerificationException(IdTokenVerifyError.MALFORMED)
    }

    if (expected.nonce != null && stringClaim(payload, "nonce") != expected.nonce) {
        throw IdTokenVerificationException(IdTokenVerifyError.NONCE_MISMATCH)
    }

    val sub = stringClaim(payload, "sub")
    if (sub.isNullOrEmpty()) throw IdTokenVerificationException(IdTokenVerifyError.MISSING_CLAIM)

    return VerifiedIdToken(sub, payload)
}

// MARK: - Helpers

private fun verifyRs256(signingInput: String, signature: ByteArray, jwk: Jwk): Boolean {
    val modulusBytes = base64UrlDecode(jwk.n) ?: return false
    val exponentBytes = base64UrlDecode(jwk.e) ?: return false
    return try {
        val spec = RSAPublicKeySpec(BigInteger(1, modulusBytes), BigInteger(1, exponentBytes))
        val publicKey = KeyFactory.getInstance("RSA").generatePublic(spec)
        Signature.getInstance("SHA256withRSA").run {
            initVerify(publicKey)
            update(signingInput.toByteArray(Charsets.UTF_8))
            verify(signature)
        }
    } catch (_: Throwable) {
        false
    }
}

private fun decodeJsonSegment(segment: String): JsonObject? {
    val bytes = base64UrlDecode(segment) ?: return null
    return try {
        jsonParser.parseToJsonElement(String(bytes, Charsets.UTF_8)) as? JsonObject
    } catch (_: Throwable) {
        null
    }
}

private fun stringClaim(obj: JsonObject, key: String): String? {
    val prim = obj[key] as? JsonPrimitive ?: return null
    return if (prim.isString) prim.content else null
}

private fun numericClaim(element: kotlinx.serialization.json.JsonElement?): Long? {
    val prim = element as? JsonPrimitive ?: return null
    if (prim.isString) return null
    return prim.doubleOrNull?.toLong()
}

private fun audienceMatches(aud: kotlinx.serialization.json.JsonElement?, clientId: String): Boolean {
    when (aud) {
        is JsonPrimitive -> return aud.isString && aud.content == clientId
        is JsonArray -> return aud.any { (it as? JsonPrimitive)?.let { p -> p.isString && p.content == clientId } == true }
        else -> return false
    }
}

/**
 * base64url → bytes, padding-optional. Streaming 6-bit decoder so it needs
 * neither android.util.Base64 (unavailable in JVM unit tests) nor
 * java.util.Base64 (API 26+). Returns null on any invalid character.
 */
private val B64URL_LOOKUP: IntArray = IntArray(128) { -1 }.also { table ->
    val alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    for (i in alphabet.indices) table[alphabet[i].code] = i
}

private fun base64UrlDecode(input: String): ByteArray? {
    val out = ArrayList<Byte>(input.length * 3 / 4 + 3)
    var buffer = 0
    var bits = 0
    for (c in input) {
        if (c == '=') break
        val code = c.code
        val value = if (code in 0..127) B64URL_LOOKUP[code] else -1
        if (value < 0) return null
        buffer = (buffer shl 6) or value
        bits += 6
        if (bits >= 8) {
            bits -= 8
            out.add(((buffer shr bits) and 0xFF).toByte())
        }
    }
    return out.toByteArray()
}
