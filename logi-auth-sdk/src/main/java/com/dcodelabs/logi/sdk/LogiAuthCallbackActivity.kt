package com.dcodelabs.logi.sdk

import android.app.Activity
import android.os.Bundle
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

/**
 * Built-in Activity that catches the OAuth callback (the redirect_uri
 * registered with logi). RP apps just declare it in their AndroidManifest:
 *
 * ```xml
 * <activity
 *     android:name="com.dcodelabs.logi.sdk.LogiAuthCallbackActivity"
 *     android:exported="true"
 *     android:launchMode="singleTask">
 *     <intent-filter>
 *         <action android:name="android.intent.action.VIEW" />
 *         <category android:name="android.intent.category.DEFAULT" />
 *         <category android:name="android.intent.category.BROWSABLE" />
 *         <!-- match your redirect_uri scheme -->
 *         <data android:scheme="myapp" android:host="callback" />
 *     </intent-filter>
 * </activity>
 * ```
 *
 * After delivering the callback to [LogiAuth] this Activity finishes
 * immediately — Custom Tabs returns the user to whichever Activity
 * launched the sign-in. RPs that need a fancier completion screen can
 * implement their own Activity with the same intent-filter and call
 * [LogiAuth] directly.
 */
class LogiAuthCallbackActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val data = intent?.data
        if (data != null) {
            // Fire-and-forget: hand off to LogiAuth on a background scope.
            // The pending CompletableDeferred inside LogiAuth completes
            // whichever launching Activity is awaiting signIn().
            CoroutineScope(Dispatchers.IO).launch {
                LogiAuth.handleAuthorizationCallback(data)
            }
        }
        finish()
    }
}
