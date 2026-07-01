pluginManagement {
    repositories { google(); mavenCentral(); gradlePluginPortal() }
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories { google(); mavenCentral() }
    // NOTE: Gradle 8.5+ auto-imports gradle/libs.versions.toml as the `libs`
    // catalog. An explicit `versionCatalogs { create("libs") { from(...) } }`
    // block conflicts with the implicit import and fails with
    // "you can only call the 'from' method a single time". (JitPack v0.2.1
    // build failed for exactly this reason — bump tag, do not re-add.)
}
rootProject.name = "logi-auth-android"
include(":logi-auth-sdk")
include(":logi-auth-storage")
