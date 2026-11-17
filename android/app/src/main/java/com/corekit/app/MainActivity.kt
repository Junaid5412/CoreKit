package com.corekit.app

import android.Manifest
import android.annotation.SuppressLint
import android.app.Activity
import android.content.pm.PackageManager
import android.os.Bundle
import android.view.WindowManager
import android.webkit.WebView

/**
 * CoreKit for Android: one activity hosting the shared CoreKit screens (ui/) in the system
 * WebView. The screens talk to [Host] exactly as they talk to the Windows app.
 */
class MainActivity : Activity() {
    private lateinit var web: WebView
    private lateinit var host: Host

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Screenshots, screen recording and remote-viewing apps see a black screen.
        if (Prefs(this).captureShield) {
            window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        }
        web = WebView(this)
        web.setBackgroundColor(BG)
        setContentView(web)
        host = Host(this, web)
        with(web.settings) {
            javaScriptEnabled = true
            domStorageEnabled = true
            allowFileAccess = false
            allowContentAccess = false
            setSupportZoom(false)
            builtInZoomControls = false
            mediaPlaybackRequiresUserGesture = true
        }
        web.webViewClient = host.client
        web.addJavascriptInterface(host.bridge, "CoreKitNative")
        WebView.setWebContentsDebuggingEnabled(false)
        if (savedInstanceState != null) web.restoreState(savedInstanceState)
        else web.loadUrl(Host.BASE + "home")
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        web.saveState(outState)
    }

    fun setCaptureShield(on: Boolean) = runOnUiThread {
        if (on) window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        else window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
    }

    /** Wi-Fi name and band need location permission on Android 8+. */
    fun ensureLocationPermission() = runOnUiThread {
        if (checkSelfPermission(Manifest.permission.ACCESS_FINE_LOCATION) != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(arrayOf(Manifest.permission.ACCESS_FINE_LOCATION, Manifest.permission.ACCESS_COARSE_LOCATION), 7)
        }
    }

    @Deprecated("Back navigation inside the CoreKit screens")
    override fun onBackPressed() {
        val u = web.url ?: ""
        when {
            u.endsWith("/home") -> @Suppress("DEPRECATION") super.onBackPressed()
            web.canGoBack() -> web.goBack()
            else -> web.loadUrl(Host.BASE + "home")
        }
    }

    override fun onDestroy() {
        host.shutdown()
        web.destroy()
        super.onDestroy()
    }

    companion object {
        const val BG = 0xFF0A0E13.toInt()
    }
}
