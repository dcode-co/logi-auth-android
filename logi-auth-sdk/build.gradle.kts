plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.serialization)
    `maven-publish`
}

android {
    namespace = "com.dcodelabs.logi.sdk"
    compileSdk = 35

    defaultConfig {
        minSdk = 23
        consumerProguardFiles("consumer-rules.pro")
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
}

dependencies {
    // Phase 6 — public RP-facing SDK. STRICT RULE: no project dependencies
    // (no :core:*, no :feature:*). External RP apps must be able to drop the
    // produced AAR into any Android project regardless of whether they use
    // Hilt, Compose, or any specific networking stack.
    //
    // Direct dependencies are kept minimal:
    //   - Custom Tabs for OAuth (browser)
    //   - EncryptedSharedPreferences for token persistence
    //   - kotlinx-coroutines for the suspend public API
    //   - kotlinx-serialization + okhttp for the /oauth/token exchange
    //     (rolling our own minimal HTTP rather than dragging Retrofit in).
    implementation(libs.androidx.browser)
    implementation(libs.androidx.security.crypto)
    implementation(libs.kotlinx.coroutines.android)
    implementation(libs.kotlinx.serialization.json)
    implementation(libs.okhttp)

    // Local JVM unit tests only (golden id_token vectors, and the handoff
    // deadline driven on virtual time). Both are pure java.security /
    // kotlinx-coroutines, so no Android/Robolectric needed.
    testImplementation("junit:junit:4.13.2")
    testImplementation(libs.kotlinx.coroutines.test)
}

// JitPack publishing — consumers add via:
//   implementation("com.github.dcode-co:logi-auth-android:0.2.1")
// Maven Central (com.dcodelabs:logi-auth-android) is P2; see
// MIGRATION-PLAN.md.
afterEvaluate {
    publishing {
        publications {
            create<MavenPublication>("release") {
                from(components["release"])
                groupId = "com.github.dcode-co.logi-auth-android"
                artifactId = "logi-auth-android"
                // 1.1.0: the callback wait grew a deadline
                // (LogiAuthError.HandoffTimeout). Binary compatible; minor
                // because a `when` over LogiAuthError with no `else` needs one
                // more branch to recompile.
                // 1.2.0: authorize handoff host split — the app-to-app leg moves
                // to `open.1pass.dev` while the browser fallback stays on the
                // issuer. Additive API (`nativeAuthorizeHost` defaults to null),
                // but the native leg's target changes on recompile alone.
                // 🔴 Bump this together with logi-auth-storage's version: that
                // module publishes `api(project(":logi-auth-sdk"))` as a POM
                // dependency pinned to whatever is written here, so leaving it
                // behind makes storage consumers silently pull the old core.
                // 1.2.1: the Custom Tab fallback is pinned to a browser package.
                // Cut as a new version rather than re-tagging 1.2.0 because
                // JitPack caches an artifact per tag — moving the tag leaves
                // consumers on the already-built one.
                // 1.3.0: BFF surface grows the host split — authorize() takes an optional
                // nativeStartUri (validated to be the same transaction) and
                // handleAuthorizationCallback() reports whether it consumed the
                // callback, so RPs with their own transaction stash can fall back
                // deterministically after process death.
                version = "1.3.1"
                pom {
                    name.set("logi-auth-android")
                    licenses {
                        license {
                            name.set("Apache License, Version 2.0")
                            url.set("https://www.apache.org/licenses/LICENSE-2.0")
                        }
                    }
                }
            }
        }
    }
}
