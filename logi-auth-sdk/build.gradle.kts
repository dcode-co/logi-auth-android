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

    // Local JVM unit tests only (golden id_token vectors). The verifier is pure
    // java.security + kotlinx-serialization, so no Android/Robolectric needed.
    testImplementation("junit:junit:4.13.2")
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
                groupId = "com.github.dcode-co"
                artifactId = "logi-auth-android"
                version = "1.0.1"
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
