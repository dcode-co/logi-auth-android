# Phase 6 — consumer ProGuard rules. Applied automatically by RP apps that
# include this AAR. Keep the public surface + kotlinx.serialization metadata
# so R8 doesn't strip them.

# Public API entry points
-keep class com.dcodelabs.logi.sdk.LogiAuth { *; }
-keep class com.dcodelabs.logi.sdk.LogiAuthConfig { *; }
-keep class com.dcodelabs.logi.sdk.LogiAuthResult { *; }
-keep class com.dcodelabs.logi.sdk.LogiAuthError { *; }
-keep class com.dcodelabs.logi.sdk.LogiAuthError$* { *; }
-keep class com.dcodelabs.logi.sdk.LogiAuthCallbackActivity { *; }

# kotlinx-serialization @Serializable companions
-keepattributes *Annotation*, InnerClasses
-keep,includedescriptorclasses class com.dcodelabs.logi.sdk.**$$serializer { *; }
-keepclassmembers class com.dcodelabs.logi.sdk.** {
    *** Companion;
}
-keepclasseswithmembers class com.dcodelabs.logi.sdk.** {
    kotlinx.serialization.KSerializer serializer(...);
}
