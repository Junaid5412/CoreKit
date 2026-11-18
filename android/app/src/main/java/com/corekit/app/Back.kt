package com.corekit.app

import android.app.Activity
import android.os.Build
import android.window.OnBackInvokedDispatcher

/**
 * Android 16 apps (target API 36) no longer get onBackPressed(): send the new back callback to
 * the same handler. Older Android versions keep calling onBackPressed(), so both stay.
 */
fun Activity.routeBack(handler: () -> Unit) {
    if (Build.VERSION.SDK_INT >= 33) {
        onBackInvokedDispatcher.registerOnBackInvokedCallback(OnBackInvokedDispatcher.PRIORITY_DEFAULT) { handler() }
    }
}
