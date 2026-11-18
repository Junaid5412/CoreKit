package com.corekit.app

import android.Manifest
import android.annotation.SuppressLint
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.media.projection.MediaProjectionManager
import android.os.Build
import android.os.Bundle
import android.print.PrintAttributes
import android.print.PrintManager
import android.view.View
import android.view.ViewGroup
import android.view.WindowManager
import android.webkit.PermissionRequest
import android.webkit.WebChromeClient
import android.webkit.WebView
import android.widget.FrameLayout
import androidx.core.view.ViewCompat
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.WindowInsetsControllerCompat

/**
 * CoreKit for Android: one activity hosting the shared CoreKit screens (ui/) in the system
 * WebView. The screens talk to [Host] exactly as they talk to the Windows app.
 */
class MainActivity : Activity() {
    private lateinit var root: FrameLayout
    private lateinit var web: WebView
    private lateinit var host: Host
    private var pendingPermission: PermissionRequest? = null
    private var fullView: View? = null
    private var fullCallback: WebChromeClient.CustomViewCallback? = null

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        current = this
        // Screenshots, screen recording and remote-viewing apps see a black screen.
        if (Prefs(this).captureShield) {
            window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        }
        // Draw edge to edge (required on Android 15) and keep content clear of the
        // status bar, navigation bar, camera cut-out and keyboard.
        WindowCompat.setDecorFitsSystemWindows(window, false)
        root = FrameLayout(this)
        root.setBackgroundColor(BG)
        web = WebView(this)
        web.setBackgroundColor(BG)
        root.addView(web, FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT))
        setContentView(root)
        ViewCompat.setOnApplyWindowInsetsListener(root) { v, insets ->
            if (fullView == null) {
                val bars = insets.getInsets(WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.displayCutout())
                val ime = insets.getInsets(WindowInsetsCompat.Type.ime())
                v.setPadding(bars.left, bars.top, bars.right, maxOf(bars.bottom, ime.bottom))
            } else v.setPadding(0, 0, 0, 0)
            WindowInsetsCompat.CONSUMED
        }

        host = Host(this, web)
        with(web.settings) {
            javaScriptEnabled = true
            domStorageEnabled = true
            allowFileAccess = false
            allowContentAccess = false
            setSupportZoom(false)
            builtInZoomControls = false
            mediaPlaybackRequiresUserGesture = false
        }
        web.webViewClient = host.client
        web.webChromeClient = chrome
        web.addJavascriptInterface(host.bridge, "CoreKitNative")
        WebView.setWebContentsDebuggingEnabled(false)
        if (savedInstanceState != null) web.restoreState(savedInstanceState)
        else web.loadUrl(Host.BASE + when (intent?.action) { ACTION_OPEN_REMOTE -> "remote"; else -> "home" })
    }

    /** A Remote Access notification was tapped: show the Remote Access screen. */
    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        if (intent.action == ACTION_OPEN_REMOTE && !(web.url ?: "").endsWith("/remote")) web.loadUrl(Host.BASE + "remote")
        else web.evaluateJavascript("window.__ckStatus&&__ckStatus()", null)
    }

    /** While viewing another device: screen stays on; wide screens turn the phone sideways. */
    fun setViewerMode(on: Boolean, landscape: Boolean) = runOnUiThread {
        if (on) window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        else window.clearFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        requestedOrientation = if (on && landscape) android.content.pm.ActivityInfo.SCREEN_ORIENTATION_SENSOR_LANDSCAPE
            else android.content.pm.ActivityInfo.SCREEN_ORIENTATION_UNSPECIFIED
        // the remote screen gets the whole display; swipe from an edge to see the system bars
        WindowInsetsControllerCompat(window, root).apply {
            if (on) { hide(WindowInsetsCompat.Type.systemBars()); systemBarsBehavior = WindowInsetsControllerCompat.BEHAVIOR_SHOW_TRANSIENT_BARS_BY_SWIPE }
            else if (fullView == null) show(WindowInsetsCompat.Type.systemBars())
        }
    }

    /** Camera / microphone for the hands-on tests, and full screen for the screen tests. */
    private val chrome = object : WebChromeClient() {
        override fun onPermissionRequest(request: PermissionRequest) {
            runOnUiThread {
                if (request.origin.host != "appassets.androidplatform.net") { request.deny(); return@runOnUiThread }
                val need = mutableListOf<String>()
                for (r in request.resources) when (r) {
                    PermissionRequest.RESOURCE_VIDEO_CAPTURE -> need += Manifest.permission.CAMERA
                    PermissionRequest.RESOURCE_AUDIO_CAPTURE -> need += Manifest.permission.RECORD_AUDIO
                }
                val missing = need.filter { checkSelfPermission(it) != PackageManager.PERMISSION_GRANTED }
                if (missing.isEmpty()) request.grant(request.resources)
                else { pendingPermission = request; requestPermissions(missing.toTypedArray(), REQ_MEDIA) }
            }
        }

        override fun onShowCustomView(view: View, callback: CustomViewCallback) {
            if (fullView != null) { callback.onCustomViewHidden(); return }
            fullView = view; fullCallback = callback
            root.addView(view, FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT))
            root.setPadding(0, 0, 0, 0)
            WindowInsetsControllerCompat(window, root).apply {
                hide(WindowInsetsCompat.Type.systemBars())
                systemBarsBehavior = WindowInsetsControllerCompat.BEHAVIOR_SHOW_TRANSIENT_BARS_BY_SWIPE
            }
        }

        override fun onHideCustomView() {
            fullView?.let { root.removeView(it) }
            fullView = null
            fullCallback?.onCustomViewHidden(); fullCallback = null
            WindowInsetsControllerCompat(window, root).show(WindowInsetsCompat.Type.systemBars())
            ViewCompat.requestApplyInsets(root)
        }
    }

    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == REQ_NOTIF) { askScreenCapture(); return }
        if (requestCode != REQ_MEDIA) return
        val req = pendingPermission ?: return
        pendingPermission = null
        val granted = req.resources.filter { r ->
            val p = when (r) {
                PermissionRequest.RESOURCE_VIDEO_CAPTURE -> Manifest.permission.CAMERA
                PermissionRequest.RESOURCE_AUDIO_CAPTURE -> Manifest.permission.RECORD_AUDIO
                else -> null
            }
            p != null && checkSelfPermission(p) == PackageManager.PERMISSION_GRANTED
        }
        if (granted.isNotEmpty()) req.grant(granted.toTypedArray()) else req.deny()
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        web.saveState(outState)
    }

    fun setCaptureShield(on: Boolean) = runOnUiThread {
        if (on) window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        else window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
    }

    /** "Export PDF": Android's print dialog, where "Save as PDF" is built in. */
    fun printPage(title: String) = runOnUiThread {
        val pm = getSystemService(PRINT_SERVICE) as PrintManager
        pm.print(title, web.createPrintDocumentAdapter(title), PrintAttributes.Builder().setMediaSize(PrintAttributes.MediaSize.ISO_A4).build())
    }

    fun startCameraTest() = runOnUiThread {
        startActivityForResult(Intent(this, CameraTestActivity::class.java), REQ_CAMERA_TEST)
    }

    // ---------------------------------------------------------------- Remote Access: share this phone

    /** Start sharing: notification permission (Android 13+) first, then Android's own screen-capture prompt. */
    fun startRemoteSharing() = runOnUiThread {
        if (RemoteService.running) { RemoteEngine.cmd(this, org.json.JSONObject().put("t", "host").put("on", true).toString()); return@runOnUiThread }
        if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), REQ_NOTIF)
        } else askScreenCapture()
    }

    private fun askScreenCapture() {
        val mpm = getSystemService(MEDIA_PROJECTION_SERVICE) as MediaProjectionManager
        // Android 14+: offer only "entire screen" (no "a single app" choice)
        val ask = if (Build.VERSION.SDK_INT >= 34) mpm.createScreenCaptureIntent(android.media.projection.MediaProjectionConfig.createConfigForDefaultDisplay())
            else mpm.createScreenCaptureIntent()
        try { startActivityForResult(ask, REQ_PROJECTION) } catch (_: Throwable) { jsToast("Screen sharing is not available on this phone.") }
    }

    fun stopRemoteSharing() = runOnUiThread {
        if (RemoteService.running) startService(Intent(this, RemoteService::class.java).setAction(RemoteService.ACTION_STOP))
        RemoteEngine.cmd(this, org.json.JSONObject().put("t", "host").put("on", false).toString())
    }

    fun requestNotifications() = runOnUiThread {
        if (Build.VERSION.SDK_INT >= 33) requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), REQ_NOTIF_ONLY)
    }

    fun jsToast(msg: String) = runOnUiThread { web.evaluateJavascript("window.__ckToast&&__ckToast(${org.json.JSONObject.quote(msg)},true)", null) }

    override fun onResume() {
        super.onResume()
        web.evaluateJavascript("window.__ckStatus&&__ckStatus()", null)
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQ_PROJECTION) {
            if (resultCode == RESULT_OK && data != null) {
                val i = Intent(this, RemoteService::class.java).setAction(RemoteService.ACTION_START)
                    .putExtra(RemoteService.EXTRA_CODE, resultCode).putExtra(RemoteService.EXTRA_DATA, data)
                if (Build.VERSION.SDK_INT >= 26) startForegroundService(i) else startService(i)
            } else jsToast("Screen sharing was not allowed, so this phone isn't shared.")
            return
        }
        if (requestCode != REQ_CAMERA_TEST) return
        val r = data?.getStringExtra("result")
            ?: org.json.JSONObject().put("lenses", org.json.JSONArray()).put("error", "The camera test was closed.").toString()
        web.evaluateJavascript("window.__camResult&&__camResult(JSON.parse(${org.json.JSONObject.quote(r)}))", null)
    }

    /** Wi-Fi name and band need location permission on Android 8+. */
    fun ensureLocationPermission() = runOnUiThread {
        if (checkSelfPermission(Manifest.permission.ACCESS_FINE_LOCATION) != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(arrayOf(Manifest.permission.ACCESS_FINE_LOCATION, Manifest.permission.ACCESS_COARSE_LOCATION), REQ_LOCATION)
        }
    }

    @Deprecated("Back navigation inside the CoreKit screens")
    override fun onBackPressed() {
        if (fullView != null) { chrome.onHideCustomView(); return }
        val u = web.url ?: ""
        // let the page handle Back first (close a menu, leave the viewer safely, …)
        web.evaluateJavascript("(window.__ckBack&&window.__ckBack())===true") { handled ->
            if (handled == "true") return@evaluateJavascript
            when {
                u.endsWith("/home") -> @Suppress("DEPRECATION") super.onBackPressed()
                else -> { setViewerMode(false, false); web.loadUrl(Host.BASE + "home") }
            }
        }
    }

    override fun onDestroy() {
        if (current === this) current = null
        host.shutdown()
        web.destroy()
        super.onDestroy()
    }

    companion object {
        const val BG = 0xFF0A0E13.toInt()
        private const val REQ_MEDIA = 11
        private const val REQ_LOCATION = 7
        private const val REQ_CAMERA_TEST = 31
        private const val REQ_PROJECTION = 32
        private const val REQ_NOTIF = 33
        private const val REQ_NOTIF_ONLY = 34
        const val ACTION_OPEN_REMOTE = "com.corekit.OPEN_REMOTE"
        @Volatile var current: MainActivity? = null
    }
}
