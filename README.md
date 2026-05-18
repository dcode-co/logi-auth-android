# logi-auth-android

**Sign in with logi** — drop-in Android SDK for [logi (1pass.dev)](https://1pass.dev) Relying Parties.

OAuth 2.0 Authorization Code + PKCE (S256). Custom Tabs + Intent app-to-app handoff.

[![JitPack](https://jitpack.io/v/dcode-co/logi-auth-android.svg)](https://jitpack.io/#dcode-co/logi-auth-android)
[![API](https://img.shields.io/badge/API-23%2B-brightgreen.svg)](#)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## Install

### Option A — JitPack (recommended, 즉시 사용 가능)

`settings.gradle.kts` 에 JitPack repo 추가:
```kotlin
dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
        maven("https://jitpack.io")           // 추가
    }
}
```

`app/build.gradle.kts` 에 의존성 추가:
```kotlin
dependencies {
    implementation("com.github.dcode-co:logi-auth-android:0.2.0")
}
```

### Option B — Maven Central (P2, 준비 중)

```kotlin
implementation("com.dcodelabs.logi:logi-auth-android:0.2.0")
```
> 🚧 _2026 Q3 publish 예정. 그 전까지는 JitPack 사용._

---

## Quickstart

### 1. Application 초기화

```kotlin
// MyApplication.kt
class MyApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        LogiAuth.configure(this, LogiAuthConfig(
            issuer = "https://api.1pass.dev",
            clientId = "logi_xxxxxxxxxxxxxxxx",     // start.1pass.dev/developer 에서 발급
            redirectUri = "myapp://oauth/1pass/callback",
            scopes = listOf("openid", "profile:basic", "email"),
        ))
    }
}
```

`AndroidManifest.xml`:
```xml
<application android:name=".MyApplication" ...>

    <!-- SDK 가 제공하는 callback Activity. 본인의 scheme 만 채우면 됨. -->
    <activity
        android:name="com.dcodelabs.logi.sdk.LogiAuthCallbackActivity"
        android:exported="true"
        android:launchMode="singleTask">
        <intent-filter>
            <action android:name="android.intent.action.VIEW" />
            <category android:name="android.intent.category.DEFAULT" />
            <category android:name="android.intent.category.BROWSABLE" />
            <data android:scheme="myapp" android:host="oauth" />
        </intent-filter>
    </activity>

</application>
```

### 2. 로그인 호출

```kotlin
class LoginActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            Button(onClick = {
                lifecycleScope.launch {
                    val result = LogiAuth.signIn(this@LoginActivity).getOrElse { e ->
                        Toast.makeText(this@LoginActivity, e.message, Toast.LENGTH_LONG).show()
                        return@launch
                    }
                    // result.accessToken / result.idToken / result.refreshToken
                    Log.i("Login", "✅ ${result.accessToken.take(12)}…")
                }
            }) {
                Text("logi 로 로그인")
            }
        }
    }
}
```

---

## API

| Method | Returns | Notes |
|---|---|---|
| `LogiAuth.configure(context, config)` | `Unit` | Application.onCreate 에서 1회 |
| `LogiAuth.signIn(activity, scopes?)` | `Result<LogiAuthResult>` | suspend; Custom Tabs |
| `LogiAuth.refresh()` | `Result<LogiAuthResult>` | suspend; 저장된 refresh token 사용 |
| `LogiAuth.signOut()` | `Unit` | token store wipe |
| `LogiAuth.currentRefreshToken()` | `String?` | sync; cold-start 분기용 |
| `LogiAuth.currentAccessToken()` | `String?` | sync; 만료됐을 가능성 있음 |

에러 타입 (`LogiAuthError`): `NotConfigured`, `InvalidAuthorizeUrl`, `StateMismatch`, `UserCancelled`, `NoRefreshToken`, `TokenEndpoint`, `Network`.

---

## How it works

1. **App-to-app first**: `Intent(ACTION_VIEW, authorizeUrl).setPackage("com.dcodelabs.logi")` 로 logi 앱이 설치된 경우 즉시 핸드오프.
2. **Custom Tabs fallback**: 미설치 시 `CustomTabsIntent` 로 시스템 브라우저.
3. **EncryptedSharedPreferences**: refresh token 저장 (AES-256-GCM, AndroidKeyStore-backed).
4. **PKCE S256**: code_verifier 메모리, code_challenge 만 전송.
5. **Zero project deps**: `:core:*`, `:feature:*` 모듈 의존성 없음. Hilt/Compose/Retrofit 사용 여부 무관하게 drop-in.

---

## ProGuard / R8

SDK 가 `consumer-rules.pro` 를 동봉하므로 추가 설정 불필요.

---

## iOS 대응표

| iOS (`logi-auth-swift`) | Android (this SDK) |
|---|---|
| `LogiAuth.configure(LogiAuthConfig)` | `LogiAuth.configure(Context, LogiAuthConfig)` |
| `LogiAuth.signIn(scopes:)` async throws | `suspend fun signIn(activity, scopes)` |
| `LogiAuth.refresh()` async throws | `suspend fun refresh()` |
| `LogiAuth.signOut()` | `LogiAuth.signOut()` |
| Keychain (iOS) | `EncryptedSharedPreferences` |
| `ASWebAuthenticationSession` | `CustomTabsIntent` + `LogiAuthCallbackActivity` |

---

## Versioning

- `v0.2.x` — current stable. minSdk 23, target SDK 35, Kotlin 2.1+, JDK 17.
- Semantic versioning. Tag `vX.Y.Z`.

---

## License

MIT. See [LICENSE](LICENSE).

## Issues / Support

- 🐛 [GitHub Issues](https://github.com/dcode-co/logi-auth-android/issues)
- 📖 [docs.1pass.dev/integrations/android](https://docs.1pass.dev/integrations/android)
- 📧 dcode.labs.kr@gmail.com
