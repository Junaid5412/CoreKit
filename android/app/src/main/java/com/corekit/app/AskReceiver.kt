package com.corekit.app

import android.app.NotificationManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import org.json.JSONObject

/**
 * Handles the Allow / Deny buttons on the "wants to connect" notification. A broadcast reaches the
 * app even when the sharing service is idle or the screen is locked, and the answer is sent before
 * the receiver finishes, so a tap always does something.
 */
class AskReceiver : BroadcastReceiver() {
    override fun onReceive(ctx: Context, intent: Intent) {
        val id = intent.getStringExtra(RemoteService.EXTRA_ID).orEmpty()
        val allow = intent.getBooleanExtra(RemoteService.EXTRA_ALLOW, false)
        (ctx.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager).cancel(RemoteService.NID_ASK)
        if (id.isEmpty()) return
        val pending = goAsync()
        Thread {
            try {
                RemoteEngine.cmdNow(ctx.applicationContext, JSONObject().put("t", "answer").put("id", id).put("allow", allow).toString())
            } catch (_: Throwable) {
            } finally { pending.finish() }
        }.start()
    }
}
