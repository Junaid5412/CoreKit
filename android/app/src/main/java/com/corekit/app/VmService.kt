package com.corekit.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import org.json.JSONObject

/**
 * Keeps Virtual Environment devices running while CoreKit is in the background or the
 * screen is off: a notification for as long as one runs (with "Stop all"), and the CPU
 * kept awake. Stops by itself when no virtual device is running.
 */
class VmService : Service() {

    companion object {
        private const val ACTION_STOP_ALL = "com.corekit.vm.STOP_ALL"
        private const val CH = "vm"
        private const val NID = 44
        @Volatile var running = false; private set

        fun start(ctx: Context) {
            if (running) return
            val i = Intent(ctx, VmService::class.java)
            try { if (Build.VERSION.SDK_INT >= 26) ctx.startForegroundService(i) else ctx.startService(i) } catch (_: Throwable) {}
        }
    }

    private var cpu: PowerManager.WakeLock? = null
    @Volatile private var quit = false

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP_ALL) {
            Thread { forEachRunning { id -> RemoteEngine.vm(this, "cmd", JSONObject().put("t", "stop").put("id", id).toString()) } }.start()
            update("Stopping virtual devices…")
            return START_NOT_STICKY
        }
        val n = notice("Virtual device running", "Tap to open. It keeps running in the background.")
        try {
            if (Build.VERSION.SDK_INT >= 34) startForeground(NID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
            else startForeground(NID, n)
        } catch (_: Throwable) { stopSelf(); return START_NOT_STICKY }
        if (!running) {
            running = true; quit = false
            try {
                cpu = (getSystemService(POWER_SERVICE) as PowerManager).newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "CoreKit:vm")
                    .apply { setReferenceCounted(false); acquire(12 * 60 * 60 * 1000L) }
            } catch (_: Throwable) {}
            Thread { watch() }.apply { isDaemon = true }.start()
        }
        return START_NOT_STICKY
    }

    private fun forEachRunning(f: (String) -> Unit): List<JSONObject> {
        val s = try { JSONObject(RemoteEngine.vm(this, "state", null)) } catch (_: Throwable) { return emptyList() }
        val arr = s.optJSONArray("machines") ?: return emptyList()
        val on = (0 until arr.length()).map { arr.getJSONObject(it) }.filter { it.optString("state") != "off" }
        on.forEach { f(it.optString("id")) }
        return on
    }

    private fun watch() {
        var idle = 0
        Thread.sleep(4000)
        while (!quit) {
            val on = forEachRunning { }
            if (on.isEmpty()) { if (++idle >= 2) break } else {
                idle = 0
                val booting = on.count { it.optString("state") != "running" }
                val names = on.joinToString(", ") { it.optString("name") }
                update(if (on.size == 1) "${on[0].optString("name")} is ${if (booting > 0) "starting" else "running"}" else "${on.size} virtual devices running",
                    if (booting > 0) on.first { it.optString("state") != "running" }.optString("detail") else names)
            }
            Thread.sleep(10000)
        }
        stopNow()
    }

    private fun stopNow() {
        running = false
        try { cpu?.takeIf { it.isHeld }?.release() } catch (_: Throwable) {}
        if (Build.VERSION.SDK_INT >= 24) stopForeground(STOP_FOREGROUND_REMOVE) else @Suppress("DEPRECATION") stopForeground(true)
        stopSelf()
    }

    private fun notice(title: String, text: String): Notification {
        val nm = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
        if (nm.getNotificationChannel(CH) == null) {
            nm.createNotificationChannel(NotificationChannel(CH, "Virtual Environment", NotificationManager.IMPORTANCE_LOW).apply { description = "Shown while a virtual device runs" })
        }
        val open = PendingIntent.getActivity(this, 21, Intent(this, MainActivity::class.java).setAction(MainActivity.ACTION_OPEN_VM)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        val stop = PendingIntent.getService(this, 22, Intent(this, VmService::class.java).setAction(ACTION_STOP_ALL),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        return Notification.Builder(this, CH).setSmallIcon(android.R.drawable.ic_menu_manage)
            .setContentTitle(title).setContentText(text).setOngoing(true).setOnlyAlertOnce(true).setContentIntent(open)
            .addAction(Notification.Action.Builder(null as android.graphics.drawable.Icon?, "Stop all", stop).build())
            .build()
    }

    private fun update(title: String, text: String = "") {
        try { (getSystemService(NOTIFICATION_SERVICE) as NotificationManager).notify(NID, notice(title, text)) } catch (_: Throwable) {}
    }

    override fun onDestroy() { quit = true; running = false; try { cpu?.takeIf { it.isHeld }?.release() } catch (_: Throwable) {}; super.onDestroy() }
}
