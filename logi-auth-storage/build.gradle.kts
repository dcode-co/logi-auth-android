plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.serialization)
    `maven-publish`
}

// Optional token-persistence + refresh companion to :logi-auth-sdk. RPs depend
// on this ONLY if they want the SDK to store the session's tokens (Keychain-
// equivalent EncryptedSharedPreferences) and offer refresh()/signOut(); apps
// that keep tokens elsewhere use :logi-auth-sdk alone.
android {
    namespace = "com.dcodelabs.logi.sdk.storage"
    compileSdk = 35

    defaultConfig {
        minSdk = 23
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
    // `api` so consumers see LogiSession / LogiAuthResult / LogiAuthConfig,
    // which appear on this module's public surface.
    api(project(":logi-auth-sdk"))
    implementation(libs.androidx.security.crypto)
    implementation(libs.kotlinx.coroutines.android)
    implementation(libs.kotlinx.serialization.json)
    implementation(libs.okhttp)
}

afterEvaluate {
    publishing {
        publications {
            create<MavenPublication>("release") {
                from(components["release"])
                groupId = "com.github.dcode-co"
                artifactId = "logi-auth-storage"
                version = "0.2.2"
            }
        }
    }
}
