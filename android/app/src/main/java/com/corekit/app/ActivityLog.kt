package com.corekit.app

import android.app.AppOpsManager
import android.app.usage.UsageEvents
import android.app.usage.UsageStatsManager
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.Process
import org.json.JSONArray
import org.json.JSONObject

/**
 * Android Activity Log: which apps were opened, and when, using the official Usage
 * Access API (UsageStatsManager). This is the only app-usage history Android lets an
 * app read, and only after the user grants "Usage access" in Settings. It cannot see
 * inside other apps (messages, which chat, typed text) - Android blocks that by design.
 */
object ActivityLog {

    fun hasAccess(ctx: Context): Boolean {
        return try {
            val ops = ctx.getSystemService(Context.APP_OPS_SERVICE) as AppOpsManager
            val mode = if (Build.VERSION.SDK_INT >= 29)
                ops.unsafeCheckOpNoThrow(AppOpsManager.OPSTR_GET_USAGE_STATS, Process.myUid(), ctx.packageName)
            else
                @Suppress("DEPRECATION") ops.checkOpNoThrow(AppOpsManager.OPSTR_GET_USAGE_STATS, Process.myUid(), ctx.packageName)
            mode == AppOpsManager.MODE_ALLOWED
        } catch (_: Throwable) { false }
    }

    fun collect(ctx: Context, days: Int): JSONObject {
        val out = JSONObject()
            .put("device", Build.MODEL)
            .put("user", "")
            .put("now", System.currentTimeMillis() / 1000)
            .put("admin", true)
        if (!hasAccess(ctx)) return out.put("needGrant", true).put("events", JSONArray())

        val events = JSONArray()
        val pm = ctx.packageManager
        val labels = HashMap<String, String>()
        fun label(pkg: String): String = labels.getOrPut(pkg) {
            try { pm.getApplicationLabel(pm.getApplicationInfo(pkg, 0)).toString() } catch (_: Throwable) { pkg }
        }
        val end = System.currentTimeMillis()
        val begin = end - days.toLong().coerceIn(1, 90) * 86_400_000L
        val usm = ctx.getSystemService(Context.USAGE_STATS_SERVICE) as UsageStatsManager
        val ue = usm.queryEvents(begin, end)
        val ev = UsageEvents.Event()
        var lastPkg = ""
        var lastAt = 0L
        var n = 0
        val self = ctx.packageName
        while (ue.hasNextEvent() && n < 1200) {
            ue.getNextEvent(ev)
            when (ev.eventType) {
                UsageEvents.Event.ACTIVITY_RESUMED -> {
                    val pkg = ev.packageName ?: continue
                    if (pkg == self) continue
                    // collapse the same app reappearing within 30s (tab switches, dialogs)
                    if (pkg == lastPkg && ev.timeStamp - lastAt < 30_000) { lastAt = ev.timeStamp; continue }
                    lastPkg = pkg; lastAt = ev.timeStamp
                    events.put(JSONObject().put("k", "app").put("t", ev.timeStamp / 1000)
                        .put("ti", "Opened " + label(pkg)).put("d", pkg).put("s", "info"))
                    n++
                }
                UsageEvents.Event.KEYGUARD_HIDDEN -> {
                    events.put(JSONObject().put("k", "unlock").put("t", ev.timeStamp / 1000)
                        .put("ti", "Phone unlocked").put("d", "").put("s", "info"))
                    n++
                }
            }
        }
        // newest first
        val list = ArrayList<JSONObject>(events.length())
        for (i in 0 until events.length()) list.add(events.getJSONObject(i))
        list.sortByDescending { it.optLong("t") }
        val sorted = JSONArray()
        for (o in list) sorted.put(o)
        return out.put("events", sorted)
    }
}
