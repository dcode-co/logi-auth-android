# logi-auth-sdk (Android)

Public RP-facing SDK for integrating logi as your identity provider on Android.
Mirrors the iOS LogiAuth Swift Package — same API shape, same mental model.

## Why a separate SDK?

The :app of this repo also talks to logi, but it does so via Hilt-injected
internals (`:core:data`, `:core:auth`, ...). External RP apps shouldn't be
forced to adopt our DI graph or our networking choices. So this module:

- Has **zero** dependencies on `:core:*` / `:feature:*` modules
- Exposes a **plain Kotlin/Java** surface (no `@HiltViewModel`, no Compose)
- Bundles a minimal OkHttp + kotlinx-serialization token client instead of
  pulling Retrofit
- Ships with consumer ProGuard rules so R8 doesn't strip the public API

## Integration (5 lines)

```kotlin
// Application.onCreate
LogiAuth.configure(this, LogiAuthConfig(
    issuer = "https://api.1pass.dev",
    clientId = "logi_xxx",            // from `logi apps create` or dev portal
    redirectUri = "myapp://callback",
))
```

```xml
<!-- AndroidManifest.xml — the SDK ships LogiAuthCallbackActivity, you just
     wire its intent-filter to your own scheme -->
<activity
    android:name="com.dcodelabs.logi.sdk.LogiAuthCallbackActivity"
    android:exported="true"
    android:launchMode="singleTask">
    <intent-filter>
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.DEFAULT" />
        <category android:name="android.intent.category.BROWSABLE" />
        <data android:scheme="myapp" android:host="callback" />
    </intent-filter>
</activity>
```

```kotlin
// Anywhere you have an Activity Context
lifecycleScope.launch {
    val result = LogiAuth.signIn(activity).getOrElse { e ->
        Toast.makeText(this@MyActivity, e.message, Toast.LENGTH_LONG).show()
        return@launch
    }
    // result.accessToken / result.idToken / result.refreshToken
}
```

## API surface

| Method | Returns | Notes |
|---|---|---|
| `LogiAuth.configure(context, config)` | `Unit` | Call once at Application.onCreate |
| `LogiAuth.signIn(activity, scopes?)` | `Result<LogiAuthResult>` | suspend; uses Custom Tabs |
| `LogiAuth.refresh()` | `Result<LogiAuthResult>` | suspend; needs persisted refresh token |
| `LogiAuth.signOut()` | `Unit` | clears token store |
| `LogiAuth.currentRefreshToken()` | `String?` | sync; for early-launch decisions |
| `LogiAuth.currentAccessToken()` | `String?` | sync; probably stale |

Errors are typed via `LogiAuthError` — `NotConfigured`, `InvalidAuthorizeUrl`,
`StateMismatch`, `UserCancelled`, `NoRefreshToken`, `TokenEndpoint`, `Network`.

## Cross-platform symmetry

| iOS (LogiAuth Swift Package) | Android (this SDK) |
|---|---|
| `LogiAuth.configure(LogiAuthConfig)` | `LogiAuth.configure(Context, LogiAuthConfig)` |
| `LogiAuth.signIn(scopes:)` async throws | `suspend fun signIn(activity, scopes)` |
| `LogiAuth.refresh()` async throws | `suspend fun refresh()` |
| `LogiAuth.signOut()` | `LogiAuth.signOut()` |
| `Keychain` (iOS Keychain) | `EncryptedSharedPreferences` |
| `ASWebAuthenticationSession` | `CustomTabsIntent` + `LogiAuthCallbackActivity` |

## Why not a custom Activity from the RP?

You can absolutely supply your own callback Activity — just declare the
intent-filter on it instead of `LogiAuthCallbackActivity`, then call
`LogiAuth.handleAuthorizationCallback(intent.data!!)` from `onCreate`. The
built-in Activity is a convenience for the 80% case.
