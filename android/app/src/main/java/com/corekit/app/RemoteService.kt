package com.corekit.app

import android.app.Activity
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.content.res.Configuration
import android.graphics.Bitmap
import android.graphics.PixelFormat
import android.hardware.display.DisplayManager
import android.hardware.display.VirtualDisplay
import android.media.ImageReader
import android.media.projection.MediaProjection
import android.media.projection.MediaProjectionManager
import android.net.wifi.WifiManager
import android.os.Build
import android.os.Handler
import android.os.HandlerThread
import android.os.IBinder
import android.os.Looper
import android.util.DisplayMetrics
import android.view.Display
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import kotlin.math.max
import kotlin.math.roundToInt

/**
 * Screen sharing for Remote Access. Runs only while the user shares this phone: it holds
 * the system screen-capture permission (Android shows its own cast indicator), keeps a
 * notification with a Stop button on screen the whole time, sends frames to the engine
 * while a session is running, and passes the viewer's input to RemoteControlService.
 */
class RemoteService : Service() {

    companion object {
        const val ACTION_START = "com.corekit.remote.START"
        const val ACTION_STOP = "com.corekit.remote.STOP"
        const val EXTRA_CODE = "code"
        const val EXTRA_DATA = "data"
        private const val CH = "remote"
        private const val CH_ASK = "remote_ask"
        private const val NID = 41
        private const val NID_ASK = 42
        @Volatile var running = false; private set
    }

    private var projection: MediaProjection? = null
    private var display: VirtualDisplay? = null
    private var reader: ImageReader? = null
    private val thread = HandlerThread("ck-capture").apply { start() }
    private val handler = Handler(thread.looper)
    private val main = Handler(Looper.getMainLooper())
    @Volatile private var capturing = false
    @Volatile private var jpegQ = 60
    @Volatile private var everyMs = 100L
    private var lastAt = 0L
    private var capW = 0; private var capH = 0; private var landscape = false
    private var mlock: WifiManager.MulticastLock? = null
    @Volatile private var glueThread: Thread? = null
    @Volatile private var stopping = false
    private var peerName = ""

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> { stopAll(); return START_NOT_STICKY }
            ACTION_START -> start(intent)
        }
        return START_NOT_STICKY
    }

    private fun start(intent: Intent) {
        channels()
        val n = notice("Sharing this phone", "Waiting for a connection. Tap to open CoreKit.")
        if (Build.VERSION.SDK_INT >= 29) startForeground(NID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_MEDIA_PROJECTION)
        else startForeground(NID, n)
        val code = intent.getIntExtra(EXTRA_CODE, Activity.RESULT_CANCELED)
        val data: Intent? = if (Build.VERSION.SDK_INT >= 33) intent.getParcelableExtra(EXTRA_DATA, Intent::class.java) else @Suppress("DEPRECATION") intent.getParcelableExtra(EXTRA_DATA)
        val mpm = getSystemService(Context.MEDIA_PROJECTION_SERVICE) as MediaProjectionManager
        val mp = try { if (data != null) mpm.getMediaProjection(code, data) else null } catch (_: Throwable) { null }
        if (mp == null) { toastPage("Screen sharing could not start."); stopAll(); return }
        projection = mp
        mp.registerCallback(object : MediaProjection.Callback() {
            override fun onStop() { main.post { stopAll() } }
        }, main)
        createDisplay()
        running = true
        try {
            val wm = applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
            mlock = wm.createMulticastLock("corekit-remote").apply { setReferenceCounted(false); acquire() }
        } catch (_: Throwable) {}
        RemoteEngine.cmd(this, JSONObject().put("t", "host").put("on", true).toString())
        RemoteEngine.cmd(this, JSONObject().put("t", "glue").put("a11y", RemoteControlService.isOn(this)).toString())
        listenGlue()
    }

    // ---------------------------------------------------------------- capture

    private fun realSize(): Triple<Int, Int, Int> {
        val dm = DisplayMetrics()
        val d = (getSystemService(Context.DISPLAY_SERVICE) as DisplayManager).getDisplay(Display.DEFAULT_DISPLAY)
        @Suppress("DEPRECATION") d.getRealMetrics(dm)
        return Triple(dm.widthPixels, dm.heightPixels, dm.densityDpi)
    }

    private fun createDisplay() {
        val (rw, rh, dpi) = realSize()
        val scale = minOf(1f, 1600f / max(rw, rh))
        capW = (rw * scale).roundToInt() and 1.inv()
        capH = (rh * scale).roundToInt() and 1.inv()
        landscape = rw > rh
        val r = ImageReader.newInstance(capW, capH, PixelFormat.RGBA_8888, 2)
        r.setOnImageAvailableListener({ onImage(it) }, handler)
        val old = reader
        reader = r
        val vd = display
        if (vd == null) {
            display = projection?.createVirtualDisplay("corekit-remote", capW, capH, dpi, DisplayManager.VIRTUAL_DISPLAY_FLAG_AUTO_MIRROR, r.surface, null, handler)
        } else {
            vd.resize(capW, capH, dpi)
            vd.surface = r.surface
        }
        old?.close()
    }

    override fun onConfigurationChanged(newConfig: Configuration) {
        super.onConfigurationChanged(newConfig)
        if (projection == null) return
        val (rw, rh, _) = realSize()
        if ((rw > rh) != landscape) handler.post { try { createDisplay() } catch (_: Throwable) {} }
    }

    private var bmp: Bitmap? = null
    private val out = ByteArrayOutputStream(256 * 1024)

    private fun onImage(r: ImageReader) {
        val img = try { r.acquireLatestImage() } catch (_: Throwable) { null } ?: return
        try {
            val now = System.currentTimeMillis()
            if (!capturing || now - lastAt < everyMs) return
            lastAt = now
            val plane = img.planes[0]
            val rowPx = plane.rowStride / plane.pixelStride
            var b = bmp
            if (b == null || b.width != rowPx || b.height != img.height) { b?.recycle(); b = Bitmap.createBitmap(rowPx, img.height, Bitmap.Config.ARGB_8888); bmp = b }
            b!!.copyPixelsFromBuffer(plane.buffer)
            val frame = if (rowPx != img.width) Bitmap.createBitmap(b, 0, 0, img.width, img.height) else b
            out.reset()
            frame.compress(Bitmap.CompressFormat.JPEG, jpegQ, out)
            if (frame !== b) frame.recycle()
            RemoteEngine.frame(out.toByteArray(), img.width, img.height)
        } catch (_: Throwable) {
        } finally { img.close() }
    }

    // ---------------------------------------------------------------- engine → phone

    private fun listenGlue() {
        if (glueThread != null) return
        glueThread = Thread {
            while (!stopping) {
                val s = RemoteEngine.events(this, true)
                if (s == null) { Thread.sleep(800); continue }
                try {
                    s.bufferedReader().forEachLine { line ->
                        if (stopping) throw InterruptedException()
                        if (line.startsWith("data: ")) handle(line.substring(6))
                    }
                } catch (_: Throwable) {}
                if (!stopping) Thread.sleep(500)
            }
        }.apply { isDaemon = true; start() }
    }

    private fun handle(raw: String) {
        val m = try { JSONObject(raw) } catch (_: Throwable) { return }
        when (m.optString("t")) {
            "capture" -> {
                capturing = m.optBoolean("on")
                when (m.optString("q")) { "fast" -> { jpegQ = 45; everyMs = 70 }; "sharp" -> { jpegQ = 80; everyMs = 140 }; "auto" -> { jpegQ = 60; everyMs = 100 } }
                lastAt = 0
            }
            "in" -> RemoteControlService.instance?.let { svc -> main.post { try { svc.perform(m) } catch (_: Throwable) {} } }
            "request" -> {
                val who = m.optJSONObject("peer")?.optString("name").orEmpty().ifEmpty { "A device" }
                askNotice(who)
            }
            "session" -> {
                val p = m.optJSONObject("peer")
                peerName = p?.optString("name").orEmpty()
                (getSystemService(NOTIFICATION_SERVICE) as NotificationManager).cancel(NID_ASK)
                update(if (p != null) "$peerName is controlling this phone" else "Sharing this phone",
                    if (p != null) "Tap Stop to end the session at once." else "Waiting for a connection. Tap to open CoreKit.")
            }
        }
    }

    // ---------------------------------------------------------------- notifications

    private fun channels() {
        if (Build.VERSION.SDK_INT < 26) return
        val nm = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
        nm.createNotificationChannel(NotificationChannel(CH, "Remote Access", NotificationManager.IMPORTANCE_LOW).apply { description = "Shown while this phone is shared" })
        nm.createNotificationChannel(NotificationChannel(CH_ASK, "Connection requests", NotificationManager.IMPORTANCE_HIGH).apply { description = "A device asks to connect" })
    }

    private fun openApp(): PendingIntent = PendingIntent.getActivity(this, 1,
        Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_REORDER_TO_FRONT),
        PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)

    private fun notice(title: String, text: String): Notification {
        val stop = PendingIntent.getService(this, 2, Intent(this, RemoteService::class.java).setAction(ACTION_STOP), PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        val b = if (Build.VERSION.SDK_INT >= 26) Notification.Builder(this, CH) else @Suppress("DEPRECATION") Notification.Builder(this)
        return b.setSmallIcon(android.R.drawable.ic_menu_share)
            .setContentTitle(title).setContentText(text)
            .setOngoing(true).setContentIntent(openApp())
            .addAction(Notification.Action.Builder(null as android.graphics.drawable.Icon?, "Stop", stop).build())
            .build()
    }

    private fun update(title: String, text: String) {
        try { (getSystemService(NOTIFICATION_SERVICE) as NotificationManager).notify(NID, notice(title, text)) } catch (_: Throwable) {}
    }

    private fun askNotice(who: String) {
        val b = if (Build.VERSION.SDK_INT >= 26) Notification.Builder(this, CH_ASK) else @Suppress("DEPRECATION") Notification.Builder(this)
        val n = b.setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setContentTitle("$who wants to connect")
            .setContentText("Open CoreKit to allow or deny.")
            .setAutoCancel(true).setContentIntent(openApp())
            .setCategory(Notification.CATEGORY_CALL)
            .build()
        try { (getSystemService(NOTIFICATION_SERVICE) as NotificationManager).notify(NID_ASK, n) } catch (_: Throwable) {}
    }

    private fun toastPage(msg: String) = MainActivity.current?.jsToast(msg)

    // ---------------------------------------------------------------- stop

    private fun stopAll() {
        if (stopping) return
        stopping = true
        running = false
        capturing = false
        RemoteEngine.cmd(this, JSONObject().put("t", "host").put("on", false).toString())
        try { display?.release() } catch (_: Throwable) {}
        try { reader?.close() } catch (_: Throwable) {}
        try { projection?.stop() } catch (_: Throwable) {}
        display = null; reader = null; projection = null
        try { mlock?.release() } catch (_: Throwable) {}
        (getSystemService(NOTIFICATION_SERVICE) as NotificationManager).cancel(NID_ASK)
        if (Build.VERSION.SDK_INT >= 24) stopForeground(STOP_FOREGROUND_REMOVE) else @Suppress("DEPRECATION") stopForeground(true)
        stopSelf()
    }

    override fun onDestroy() {
        if (!stopping) stopAll()
        thread.quitSafely()
        super.onDestroy()
    }
}
