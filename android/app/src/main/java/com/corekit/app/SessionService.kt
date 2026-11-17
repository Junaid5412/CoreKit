package com.corekit.app

import android.Manifest
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.net.wifi.WifiManager
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import org.json.JSONObject

/**
 * Keeps a Remote Access session alive while CoreKit is in the background: when this phone
 * is viewing another device, or is in a call with it. It shows a notification (with a
 * Disconnect button) for the whole time and holds Wi-Fi and CPU awake. It does not capture
 * anything itself; sharing this phone's screen is RemoteService.
 */
class SessionService : Service() {

    companion object {
        private const val ACTION_UPDATE = "com.corekit.session.UPDATE"
        private const val ACTION_DISCONNECT = "com.corekit.session.DISCONNECT"
        private const val CH = "remote"
        private const val NID = 43
        @Volatile var running = false; private set

        /** Called by the page: {on, peer, viewing, call, video}. */
        fun update(ctx: Context, json: String) {
            val m = try { JSONObject(json) } catch (_: Throwable) { return }
            val i = Intent(ctx, SessionService::class.java).setAction(ACTION_UPDATE).putExtra("m", json)
            try {
                if (running) ctx.startService(i) // already in the foreground: just update it
                else if (m.optBoolean("on")) ctx.startForegroundService(i)
            } catch (_: Throwable) {}
        }
    }

    private var wlock: WifiManager.WifiLock? = null
    private var cpu: PowerManager.WakeLock? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_DISCONNECT -> {
                RemoteEngine.cmd(this, JSONObject().put("t", "disconnect").toString())
                stop()
            }
            ACTION_UPDATE -> {
                val m = try { JSONObject(intent.getStringExtra("m") ?: "{}") } catch (_: Throwable) { JSONObject() }
                if (m.optBoolean("on")) show(m) else stop()
            }
            else -> if (!running) stop()
        }
        return START_NOT_STICKY
    }

    private fun show(m: JSONObject) {
        val peer = m.optString("peer").ifBlank { "the other device" }
        val inCall = m.optBoolean("call")
        val title = when {
            m.optBoolean("viewing") && inCall -> "Connected to $peer · in a call"
            m.optBoolean("viewing") -> "Connected to $peer"
            else -> "In a call with $peer"
        }
        val n = notice(title, "Runs in the background. Tap to return to CoreKit.")
        var type = 0
        if (Build.VERSION.SDK_INT >= 29) {
            type = ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE
            // a call keeps its microphone (and camera) when CoreKit is in the background
            if (inCall && granted(Manifest.permission.RECORD_AUDIO)) type = type or ServiceInfo.FOREGROUND_SERVICE_TYPE_MICROPHONE
            if (inCall && m.optBoolean("video") && granted(Manifest.permission.CAMERA)) type = type or ServiceInfo.FOREGROUND_SERVICE_TYPE_CAMERA
        }
        try {
            if (Build.VERSION.SDK_INT >= 29) startForeground(NID, n, type) else startForeground(NID, n)
        } catch (_: Throwable) {
            // e.g. the call type is refused while CoreKit isn't on screen: keep the session only
            try { if (Build.VERSION.SDK_INT >= 29) startForeground(NID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE) else startForeground(NID, n) }
            catch (_: Throwable) { stop(); return }
        }
        running = true
        locks(true)
    }

    private fun granted(p: String) = checkSelfPermission(p) == PackageManager.PERMISSION_GRANTED

    private fun notice(title: String, text: String): Notification {
        val nm = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
        if (nm.getNotificationChannel(CH) == null) {
            nm.createNotificationChannel(NotificationChannel(CH, "Remote Access", NotificationManager.IMPORTANCE_LOW).apply { description = "Shown while a Remote Access session runs" })
        }
        val open = PendingIntent.getActivity(this, 11,
            Intent(this, MainActivity::class.java).setAction(MainActivity.ACTION_OPEN_REMOTE)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        val end = PendingIntent.getService(this, 12, Intent(this, SessionService::class.java).setAction(ACTION_DISCONNECT),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        return Notification.Builder(this, CH)
            .setSmallIcon(android.R.drawable.ic_menu_view)
            .setContentTitle(title).setContentText(text)
            .setOngoing(true).setOnlyAlertOnce(true).setContentIntent(open)
            .addAction(Notification.Action.Builder(null as android.graphics.drawable.Icon?, "Disconnect", end).build())
            .build()
    }

    private fun locks(on: Boolean) {
        try {
            if (on) {
                if (wlock == null) {
                    val wm = applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
                    @Suppress("DEPRECATION")
                    wlock = wm.createWifiLock(if (Build.VERSION.SDK_INT >= 29) WifiManager.WIFI_MODE_FULL_LOW_LATENCY else WifiManager.WIFI_MODE_FULL_HIGH_PERF, "corekit-session")
                        .apply { setReferenceCounted(false); acquire() }
                }
                if (cpu == null) {
                    cpu = (getSystemService(POWER_SERVICE) as PowerManager).newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "CoreKit:session")
                        .apply { setReferenceCounted(false); acquire(6 * 60 * 60 * 1000L) }
                }
            } else {
                wlock?.takeIf { it.isHeld }?.release(); wlock = null
                cpu?.takeIf { it.isHeld }?.release(); cpu = null
            }
        } catch (_: Throwable) {}
    }

    private fun stop() {
        running = false
        locks(false)
        if (Build.VERSION.SDK_INT >= 24) stopForeground(STOP_FOREGROUND_REMOVE) else @Suppress("DEPRECATION") stopForeground(true)
        stopSelf()
    }

    override fun onDestroy() { running = false; locks(false); super.onDestroy() }
}
