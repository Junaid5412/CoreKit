package com.corekit.app

import android.content.ActivityNotFoundException
import android.content.ClipData
import android.content.ClipboardManager
import android.content.ContentValues
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.provider.MediaStore
import android.provider.Settings
import android.webkit.JavascriptInterface
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import android.webkit.WebView
import android.webkit.WebViewClient
import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayInputStream
import java.io.OutputStream
import java.io.PipedInputStream
import java.io.PipedOutputStream
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

class Prefs(ctx: Context) {
    private val p = ctx.getSharedPreferences("corekit", Context.MODE_PRIVATE)
    var captureShield: Boolean
        get() = p.getBoolean("captureShield", true)
        set(v) = p.edit().putBoolean("captureShield", v).apply()
}

/**
 * Serves the shared screens and answers their API calls (same paths and JSON as the
 * Windows app: api/scan, api/net/scan, api/net/fix, api/net/fixstatus, api/open ...).
 */
class Host(private val act: MainActivity, private val web: WebView) {
    private val pool = Executors.newCachedThreadPool()
    private val busy = AtomicBoolean(false)
    @Volatile private var job: FixJob? = null

    companion object {
        const val ORIGIN = "https://appassets.androidplatform.net"
        const val BASE = "$ORIGIN/ck/"
        private val PAGES = mapOf("home" to "mobile/home.html", "health" to "health.html", "net" to "net.html")
    }

    val client = object : WebViewClient() {
        override fun shouldInterceptRequest(view: WebView, req: WebResourceRequest): WebResourceResponse? {
            val u = req.url
            if (u.scheme != "https" || u.host != "appassets.androidplatform.net") return null
            val path = u.path ?: return notFound()
            if (!path.startsWith("/ck/")) return notFound()
            val rest = path.removePrefix("/ck/")
            PAGES[rest]?.let { return asset("ui/$it") }
            if (rest.startsWith("api/")) return api(rest.removePrefix("api/"), u, req.method ?: "GET")
            return notFound()
        }

        override fun shouldOverrideUrlLoading(view: WebView, req: WebResourceRequest): Boolean {
            val u = req.url
            if (u.host == "appassets.androidplatform.net") return false
            openExternal(u)
            return true
        }
    }

    private fun asset(name: String): WebResourceResponse = try {
        val r = WebResourceResponse("text/html", "utf-8", act.assets.open(name))
        r.responseHeaders = mapOf("Cache-Control" to "no-store")
        r
    } catch (e: Exception) { notFound() }

    private fun notFound() = WebResourceResponse("text/plain", "utf-8", 404, "Not Found", emptyMap(), ByteArrayInputStream(ByteArray(0)))

    private fun json(o: Any, code: Int = 200) = WebResourceResponse(
        "application/json", "utf-8", code, if (code == 200) "OK" else "Error",
        mapOf("Cache-Control" to "no-store"), ByteArrayInputStream(o.toString().toByteArray())
    )

    private fun text(s: String, code: Int) = WebResourceResponse("text/plain", "utf-8", code, if (code == 200) "OK" else "Error", emptyMap(), ByteArrayInputStream(s.toByteArray()))

    private fun api(route: String, u: Uri, method: String): WebResourceResponse = when (route) {
        "ping", "bye" -> json(JSONObject().put("ok", true))
        "scan" -> stream { out ->
            HealthCollector(act).collect { pct, label -> out.event("progress", JSONObject().put("pct", pct).put("label", label)) }
                .let { out.event("done", it) }
        }
        "net/scan" -> {
            act.ensureLocationPermission()
            val sites = u.getQueryParameter("sites") ?: ""
            val speed = u.getQueryParameter("speed") != "0"
            stream { out ->
                val p = { pct: Int, label: String -> out.event("progress", JSONObject().put("pct", pct).put("label", label)) }
                val net = NetCollector(act).scan(sites, p)
                val sp: Any = if (speed && net.optBoolean("online")) SpeedTest.run { ph, pct, mbps ->
                    p(pct, if (mbps > 0) "%s  %.1f Mbps".format(ph, mbps) else ph)
                } else JSONObject.NULL
                out.event("done", JSONObject().put("net", net).put("speed", sp))
            }
        }
        "net/fix" -> startFix(u.getQueryParameter("actions") ?: "")
        "net/fixstatus" -> fixStatus(u.getQueryParameter("id") ?: "", u.getQueryParameter("since")?.toIntOrNull() ?: 0)
        "open" -> { openSettings(u.getQueryParameter("what") ?: ""); text("", 204) }
        else -> notFound()
    }

    // ---------------------------------------------------------------- server-sent events

    class Sse(private val o: OutputStream) {
        @Synchronized fun event(name: String, data: Any) {
            o.write("event: $name\ndata: $data\n\n".toByteArray())
            o.flush()
        }
    }

    private fun stream(work: (Sse) -> Unit): WebResourceResponse {
        if (!busy.compareAndSet(false, true)) return text("busy", 409)
        val input = PipedInputStream(1 shl 16)
        val output = PipedOutputStream(input)
        pool.execute {
            val s = Sse(output)
            try { work(s) } catch (e: Throwable) {
                try { s.event("fail", JSONObject().put("error", e.message ?: e.javaClass.simpleName)) } catch (_: Throwable) {}
            } finally {
                busy.set(false)
                try { output.close() } catch (_: Throwable) {}
            }
        }
        return WebResourceResponse("text/event-stream", "utf-8", 200, "OK", mapOf("Cache-Control" to "no-store"), input)
    }

    // ---------------------------------------------------------------- repairs (polled, like Windows)

    class FixJob(val id: String) {
        val events = JSONArray()
        @Volatile var done = false
        @Volatile var error = ""
        @Volatile var result: JSONObject? = null
    }

    private fun startFix(actions: String): WebResourceResponse {
        val acts = actions.split(",").map { it.trim() }.filter { NetFixer.allowed(it) }
        if (acts.isEmpty()) return text("no valid actions", 400)
        if (busy.get() || job?.done == false) return text("busy", 409)
        val j = FixJob(java.util.UUID.randomUUID().toString().take(12))
        job = j
        pool.execute {
            try {
                j.result = NetFixer(act).run(acts) { type, kind, textS, pct ->
                    synchronized(j.events) {
                        j.events.put(JSONObject().put("type", type).put("kind", kind).put("text", textS).put("pct", pct))
                    }
                }
            } catch (e: Throwable) { j.error = e.message ?: "repair failed" }
            j.done = true
        }
        return json(JSONObject().put("id", j.id))
    }

    private fun fixStatus(id: String, since: Int): WebResourceResponse {
        val j = job
        if (j == null || j.id != id) return text("unknown job", 404)
        val out = JSONObject()
        synchronized(j.events) {
            val ev = JSONArray()
            val from = if (since < 0 || since > j.events.length()) 0 else since
            for (i in from until j.events.length()) ev.put(j.events.get(i))
            out.put("events", ev).put("next", j.events.length())
        }
        out.put("done", j.done).put("error", j.error)
        if (j.done) j.result?.let { out.put("result", it) }
        return json(out)
    }

    // ---------------------------------------------------------------- system screens

    fun openSettings(what: String) = act.runOnUiThread { HostSettings.open(act, what) }

    private fun openExternal(u: Uri) = act.runOnUiThread {
        try { act.startActivity(Intent(Intent.ACTION_VIEW, u).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)) } catch (_: Throwable) {}
    }

    fun shutdown() { pool.shutdownNow() }

    // ---------------------------------------------------------------- JavaScript bridge

    val bridge = object {
        @JavascriptInterface fun platform(): String = "android"

        @JavascriptInterface fun info(): String = JSONObject()
            .put("model", "${Build.MANUFACTURER.replaceFirstChar { it.uppercase() }} ${Build.MODEL}")
            .put("android", Build.VERSION.RELEASE).put("api", Build.VERSION.SDK_INT)
            .put("version", appVersion()).put("shield", Prefs(act).captureShield).toString()

        /** Saves an HTML report to Downloads/CoreKit and returns {path} or {error}. */
        @JavascriptInterface fun save(name: String, html: String): String = try {
            val safe = name.replace(Regex("[^A-Za-z0-9 _.\\-]+"), "").take(120).ifBlank { "CoreKit-Report" } + ".html"
            val uri = if (Build.VERSION.SDK_INT >= 29) {
                val cv = ContentValues().apply {
                    put(MediaStore.MediaColumns.DISPLAY_NAME, safe)
                    put(MediaStore.MediaColumns.MIME_TYPE, "text/html")
                    put(MediaStore.MediaColumns.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS + "/CoreKit")
                }
                act.contentResolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, cv) ?: error("storage unavailable")
            } else {
                val dir = act.getExternalFilesDir(Environment.DIRECTORY_DOCUMENTS) ?: act.filesDir
                Uri.fromFile(java.io.File(dir, safe))
            }
            act.contentResolver.openOutputStream(uri)!!.use { it.write(html.toByteArray()) }
            JSONObject().put("path", uri.toString()).put("label", "Downloads/CoreKit/$safe").toString()
        } catch (e: Throwable) { JSONObject().put("error", e.message ?: "could not save").toString() }

        /** Opens a saved report with the user's choice of app. */
        @JavascriptInterface fun open(path: String) {
            act.runOnUiThread {
                try {
                    val i = Intent(Intent.ACTION_VIEW).setDataAndType(Uri.parse(path), "text/html")
                        .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_ACTIVITY_NEW_TASK)
                    act.startActivity(Intent.createChooser(i, "Open report").addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
                } catch (_: Throwable) {}
            }
        }

        @JavascriptInterface fun copy(text: String) {
            act.runOnUiThread {
                (act.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager)
                    .setPrimaryClip(ClipData.newPlainText("CoreKit", text))
            }
        }

        @JavascriptInterface fun print(title: String) = act.printPage(title.take(80).ifBlank { "CoreKit Report" })

        @JavascriptInterface fun setShield(on: Boolean) {
            Prefs(act).captureShield = on
            act.setCaptureShield(on)
        }

        @JavascriptInterface fun go(page: String) {
            if (page in PAGES) act.runOnUiThread { web.loadUrl(BASE + page) }
        }

        @JavascriptInterface fun exit() { act.runOnUiThread { act.finishAndRemoveTask() } }
    }

    private fun appVersion(): String = try {
        act.packageManager.getPackageInfo(act.packageName, 0).versionName ?: ""
    } catch (_: Throwable) { "" }
}

/** Opens Android system settings screens used by the troubleshooter. */
object HostSettings {
    fun open(ctx: Context, what: String) {
        if (what == "portal") {
            try {
                ctx.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse("http://connectivitycheck.gstatic.com/generate_204")).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
            } catch (_: Throwable) {}
            return
        }
        val action = when (what) {
            "wifi" -> Settings.ACTION_WIFI_SETTINGS
            "network", "ncpa" -> Settings.ACTION_WIRELESS_SETTINGS
            "privatedns" -> "android.settings.PRIVATE_DNS_SETTINGS"
            "datetime" -> Settings.ACTION_DATE_SETTINGS
            "vpn" -> Settings.ACTION_VPN_SETTINGS
            "mobile" -> Settings.ACTION_DATA_ROAMING_SETTINGS
            "devmgmt", "about" -> Settings.ACTION_DEVICE_INFO_SETTINGS
            else -> Settings.ACTION_SETTINGS
        }
        try { ctx.startActivity(Intent(action).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)) } catch (e: ActivityNotFoundException) {
            try { ctx.startActivity(Intent(Settings.ACTION_WIRELESS_SETTINGS).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)) } catch (_: Throwable) {}
        }
    }
}
