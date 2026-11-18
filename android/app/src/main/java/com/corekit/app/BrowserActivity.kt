package com.corekit.app

import android.Manifest
import android.annotation.SuppressLint
import android.app.Activity
import android.content.ActivityNotFoundException
import android.content.ContentValues
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.net.Uri
import android.content.res.Configuration
import android.graphics.Color
import android.os.Build
import android.os.LocaleList
import android.os.Bundle
import android.os.Environment
import android.os.Handler
import android.os.Looper
import android.os.Message
import android.provider.MediaStore
import android.view.View
import android.view.ViewGroup
import android.view.WindowManager
import android.webkit.CookieManager
import android.webkit.GeolocationPermissions
import android.webkit.JavascriptInterface
import android.webkit.PermissionRequest
import android.webkit.URLUtil
import android.webkit.ValueCallback
import android.webkit.WebChromeClient
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import android.webkit.WebStorage
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.FrameLayout
import androidx.core.view.ViewCompat
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.WindowInsetsControllerCompat
import androidx.webkit.ProfileStore
import androidx.webkit.ProxyConfig
import androidx.webkit.ProxyController
import androidx.webkit.WebViewCompat
import androidx.webkit.WebViewFeature
import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayInputStream
import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.URL
import java.util.concurrent.Executors
import kotlin.math.roundToInt

/**
 * CoreKit Browser for Android. The browser's own screen is the shared ui/browser.html
 * (same messages as Windows); each tab is a WebView placed in the page area it reports.
 * Started without a profile it shows the shared profile picker first.
 */
class BrowserActivity : Activity() {
    private class Tab(val id: Int) {
        var view: WebView? = null
        var url = ""; var title = ""; var pending = ""
        var loading = false; var canBack = false; var canFwd = false; var crashed = false; var gone = false
        var pageLang = ""; var trState = ""; var trMsg = ""; var trSeq = 0
        var alt = false // "Desktop site"
    }

    private val main = Handler(Looper.getMainLooper())
    private val bg = Executors.newCachedThreadPool()
    private val io = Executors.newSingleThreadExecutor() // config writes, one at a time and in order
    private val helper by lazy { Helper(this) }
    private val vault by lazy { Vault(this) }
    private val xray by lazy { Xray(this, helper) }

    private lateinit var root: FrameLayout
    private lateinit var chrome: WebView
    private lateinit var content: FrameLayout
    private var picker = false
    private var ready = false
    private var cfg = JSONObject()
    private var profId = ""
    private var info = JSONObject()
    private var scripts = JSONObject()
    private val tabs = mutableListOf<Tab>()
    private var active: Tab? = null
    private var nextId = 1
    private val closed = mutableListOf<JSONObject>()
    private val history = mutableListOf<JSONObject>()
    private var covered = false
    private var overlay = false // covered only by a small menu: page stays visible under it
    private var layoutOk = false
    private var state = ""
    private var stateMsg = ""
    private var checks = JSONArray()
    private var checkSeq = 0
    private var proxyOn = false
    private var tunnelIp = ""
    private var country = ""
    private var ms = 0
    private var geo = JSONObject()
    private var fullView: View? = null
    private var fullCb: WebChromeClient.CustomViewCallback? = null
    private var fileCb: ValueCallback<Array<Uri>>? = null
    private var pendingPerm: PermissionRequest? = null
    private var restored = false
    private var saveTask: Runnable? = null
    private var adHosts = HashSet<String>()
    private val sysLocales: LocaleList = LocaleList.getDefault()

    private val density get() = resources.displayMetrics.density
    private val multiProfile by lazy { WebViewFeature.isFeatureSupported(WebViewFeature.MULTI_PROFILE) }
    private val docStart by lazy { WebViewFeature.isFeatureSupported(WebViewFeature.DOCUMENT_START_SCRIPT) }

    // ---------------------------------------------------------------- lifecycle

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        routeBack { handleBack() }
        WindowCompat.setDecorFitsSystemWindows(window, false)
        root = FrameLayout(this).apply { setBackgroundColor(MainActivity.BG) }
        chrome = WebView(this).apply { setBackgroundColor(Color.TRANSPARENT) } // the page paints its own background; see-through over pages while a menu is open
        content = FrameLayout(this).apply { setBackgroundColor(MainActivity.BG); visibility = View.INVISIBLE }
        root.addView(chrome, FrameLayout.LayoutParams(-1, -1))
        root.addView(content, FrameLayout.LayoutParams(1, 1))
        setContentView(root)
        ViewCompat.setOnApplyWindowInsetsListener(root) { v, ins ->
            if (fullView == null) {
                val b = ins.getInsets(WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.displayCutout())
                val ime = ins.getInsets(WindowInsetsCompat.Type.ime())
                v.setPadding(b.left, b.top, b.right, maxOf(b.bottom, ime.bottom))
            }
            WindowInsetsCompat.CONSUMED
        }
        loadConfig()
        val want = intent.getStringExtra("profile")
        picker = want == null
        if (!picker) {
            profId = pickProfile(want!!)
            if (!keepData()) wipeProfileData()
            applyShield()
        } else window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)

        with(chrome.settings) { javaScriptEnabled = true; domStorageEnabled = true; allowFileAccess = false; setSupportZoom(false) }
        chrome.addJavascriptInterface(Bridge(), "CoreKitBrowser")
        chrome.webViewClient = object : WebViewClient() {
            override fun shouldInterceptRequest(view: WebView, req: WebResourceRequest) = serveLocal(req.url, true)
            override fun shouldOverrideUrlLoading(view: WebView, req: WebResourceRequest): Boolean {
                if (req.url.host != HOST) { main.post { newTab(req.url.toString(), true) } }
                return req.url.host != HOST
            }
        }
        chrome.loadUrl("$BASE${if (picker) "picker" else "browser"}")
        bg.execute {
            val i = helper.call("info")
            main.post { info = i; if (ready) sendState() }
        }
    }

    override fun onDestroy() {
        saveNow()
        checkSeq++
        for (t in tabs) t.view?.destroy()
        if (!picker) {
            xray.stop()
            if (WebViewFeature.isFeatureSupported(WebViewFeature.PROXY_OVERRIDE) && proxyOn)
                ProxyController.getInstance().clearProxyOverride({ it.run() }, {})
            if (!keepData()) wipeProfileData()
        }
        chrome.destroy()
        if (LocaleList.getDefault() != sysLocales) { LocaleList.setDefault(sysLocales); java.util.Locale.setDefault(sysLocales[0]) }
        bg.shutdownNow()
        io.shutdown() // pending saves still finish
        super.onDestroy()
    }

    @Deprecated("system back")
    override fun onBackPressed() = handleBack()

    private fun handleBack() {
        if (fullView != null) { tabChrome.onHideCustomView(); return }
        if (covered) { js("document.dispatchEvent(new KeyboardEvent('keydown',{key:'Escape'}))"); return }
        val v = active?.view
        if (v != null && v.canGoBack()) { v.goBack(); return }
        finish()
    }

    // ---------------------------------------------------------------- config (encrypted)

    private fun loadConfig() {
        cfg = vault.read("config.bin")?.let { try { JSONObject(it) } catch (_: Throwable) { null } } ?: JSONObject()
        if (!cfg.has("profiles")) cfg.put("profiles", JSONArray())
        if (!cfg.has("proxies")) cfg.put("proxies", JSONArray())
    }
    private fun saveConfig() { val s = cfg.toString(); io.execute { vault.write("config.bin", s) } }
    /** Waits until the config is on disk (before another screen reads it). */
    private fun flushConfig() { val s = cfg.toString(); try { io.submit(Runnable { vault.write("config.bin", s) }).get(5, java.util.concurrent.TimeUnit.SECONDS) } catch (_: Throwable) {} }
    private fun profiles() = cfg.getJSONArray("profiles")
    private fun proxies() = cfg.getJSONArray("proxies")
    private fun list(a: JSONArray) = (0 until a.length()).map { a.getJSONObject(it) }
    private fun prof(): JSONObject = list(profiles()).firstOrNull { it.optString("id") == profId } ?: JSONObject().put("id", profId).put("name", "Profile")
    private fun proxyById(id: String) = list(proxies()).firstOrNull { it.optString("id") == id }
    private fun chosenProxy(p: JSONObject = prof()): JSONObject? = when (val x = p.optString("proxy")) {
        "" -> null; "default" -> proxyById(cfg.optString("default")); else -> proxyById(x)
    }
    /** What the profile does on close / next start: restore (default) | newtab | page | clear. */
    private fun startMode(p: JSONObject = prof()): String = p.optString("startup").takeIf { it in setOf("newtab", "page", "clear") } ?: "restore"
    private fun keepData() = startMode() != "clear"

    /** Stores the start/close choice; the page address goes through the shared normalizer. */
    private fun setStartup(p: JSONObject, mode: String, page: String, then: () -> Unit) {
        when (mode) {
            "restore", "newtab", "clear" -> { p.put("startup", mode); then() }
            "page" -> {
                if (page.isBlank()) { p.put("startup", "newtab"); then(); return }
                bg.execute {
                    val u = helper.call("normalize", JSONObject().put("input", page.trim()).put("engine", p.optString("search", "google"))).optString("url")
                    main.post { if (u.isNotEmpty()) p.put("startup", "page").put("startUrl", u) else p.put("startup", "newtab"); then() }
                }
            }
            else -> then()
        }
    }

    /** Clear everything: logins, cookies, site data, cache, history and tabs of this profile. */
    private fun wipeProfileData() {
        if (multiProfile) try { ProfileStore.getInstance().deleteProfile(profileName()) } catch (_: Throwable) {}
        else { CookieManager.getInstance().removeAllCookies(null); WebStorage.getInstance().deleteAllData() }
        try { WebView(this).apply { clearCache(true); destroy() } } catch (_: Throwable) {}
        vault.delete("p/$profId/session.bin")
        vault.delete("p/$profId/history.bin")
    }

    private fun newId() = java.util.UUID.randomUUID().toString().replace("-", "").take(12)
    private fun colors(): List<String> = info.optJSONArray("colors")?.let { a -> (0 until a.length()).map { a.getString(it) } }
        ?: listOf("#2dd4bf", "#60a5fa", "#a78bfa", "#f472b6", "#fb923c", "#facc15", "#4ade80", "#f87171")

    private fun pickProfile(id: String): String {
        var p = list(profiles()).firstOrNull { it.optString("id") == id } ?: list(profiles()).maxByOrNull { it.optLong("lastUsed") }
        if (p == null) {
            p = JSONObject().put("id", newId()).put("name", "Personal").put("color", "#2dd4bf").put("search", "google").put("created", now())
            profiles().put(p)
        }
        p.put("lastUsed", now())
        saveConfig()
        return p.getString("id")
    }
    private fun now() = System.currentTimeMillis() / 1000
    private fun lang() = prof().optString("lang").ifEmpty { "en" }

    private fun applyShield() {
        if (!prof().optBoolean("allowCapture")) window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        else window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
    }

    // ---------------------------------------------------------------- local pages (shared ui/)

    private fun serveLocal(u: Uri, chromeView: Boolean): WebResourceResponse? {
        if (u.host != HOST) return null
        val page = u.path?.removePrefix("/ck/") ?: return null
        val name = when (page) { "browser" -> "browser.html"; "picker" -> "picker.html"; "start" -> "start.html"; else -> return notFound() }
        if (!chromeView && page != "start") return notFound()
        var html = assets.open("ui/$name").bufferedReader().readText()
        if (page == "start") {
            val e = engine()
            val hl = if (e.optString("id") == "google" && !prof().optBoolean("noGoogleFix")) "<input type=\"hidden\" name=\"hl\" value=\"${lang().substringBefore('-')}\">" else ""
            html = html.replace("{{ENGINE_URL}}", e.optString("url", "https://www.google.com/search"))
                .replace("{{ENGINE_NAME}}", e.optString("name", "Google")).replace("{{HLINPUT}}", hl)
        } else {
            html = html.replaceFirst("<script>", "<script>window.chrome=window.chrome||{};window.chrome.webview={postMessage:o=>CoreKitBrowser.post(JSON.stringify(o)),addEventListener:()=>{}};\n")
        }
        return WebResourceResponse("text/html", "utf-8", ByteArrayInputStream(html.toByteArray()))
    }
    private fun notFound() = WebResourceResponse("text/plain", "utf-8", 404, "Not Found", emptyMap(), ByteArrayInputStream(ByteArray(0)))
    private fun engine(): JSONObject {
        val id = prof().optString("search", "google")
        val arr = info.optJSONArray("engines") ?: return JSONObject().put("id", "google").put("name", "Google").put("url", "https://www.google.com/search")
        return list(arr).firstOrNull { it.optString("id") == id } ?: arr.getJSONObject(0)
    }
    private fun isStart(u: String) = u.isEmpty() || u == "about:blank" || u.startsWith("${BASE}start")
    private fun display(u: String) = if (isStart(u)) "" else u

    // ---------------------------------------------------------------- UI messages

    private fun js(code: String) = main.post { chrome.evaluateJavascript(code, null) }
    private fun post(o: JSONObject) { if (ready) js("window.__corekit&&window.__corekit(${o})") }
    private fun toast(msg: String, bad: Boolean = false) = post(JSONObject().put("t", "toast").put("msg", msg).put("bad", bad))

    inner class Bridge {
        @JavascriptInterface fun post(json: String) {
            val m = try { JSONObject(json) } catch (_: Throwable) { return }
            main.post { if (picker) onPickerMessage(m) else onMessage(m) }
        }
    }

    private fun onPickerMessage(m: JSONObject) {
        when (m.optString("t")) {
            "ready" -> {
                ready = true
                val ps = JSONArray()
                for (p in list(profiles())) ps.put(JSONObject().put("id", p.optString("id")).put("name", p.optString("name")).put("color", p.optString("color"))
                    .put("proxy", chosenProxy(p)?.optString("name") ?: "").put("lastUsed", p.optLong("lastUsed")).put("running", false))
                val pxs = JSONArray()
                for (x in list(proxies())) pxs.put(JSONObject().put("id", x.optString("id")).put("name", x.optString("name")))
                post(JSONObject().put("t", "state").put("profiles", ps).put("colors", JSONArray(colors())).put("proxies", pxs).put("default", cfg.optString("default")))
            }
            "open" -> openProfile(m.optString("id"))
            "new" -> {
                val name = m.optString("name").trim().take(32)
                if (name.isEmpty()) return
                // asked when the profile is made: proxy (none, a saved one or a new link) and ad blocker
                val p = JSONObject().put("id", newId()).put("name", name).put("color", m.optString("color", "#60a5fa")).put("search", "google").put("created", now())
                    .put("noAdblock", !m.optBoolean("on"))
                val choice = m.optString("id")
                fun create() = setStartup(p, m.optString("engine"), m.optString("url")) { profiles().put(p); saveConfig(); openProfile(p.getString("id")) }
                when (choice) {
                    "" -> create()
                    "new" -> {
                        val link = m.optString("link").trim()
                        bg.execute {
                            val r = helper.call("parse", JSONObject().put("link", link))
                            main.post {
                                if (r.has("error")) { post(JSONObject().put("t", "error").put("msg", r.optString("error")).put("field", "link")); return@post }
                                val px = JSONObject().put("id", newId()).put("name", r.optString("name").ifEmpty { r.optString("kind").uppercase() }.take(40))
                                    .put("link", link).put("kind", r.optString("kind")).put("added", now())
                                proxies().put(px); if (cfg.optString("default").isEmpty()) cfg.put("default", px.optString("id"))
                                p.put("proxy", px.optString("id")); create()
                            }
                        }
                    }
                    else -> { if (proxyById(choice) != null) p.put("proxy", choice); create() }
                }
            }
        }
    }

    private fun openProfile(id: String) {
        flushConfig() // the new window reads the config at once: a new profile and its proxy must be saved first
        startActivity(Intent(this, BrowserActivity::class.java).putExtra("profile", id).addFlags(Intent.FLAG_ACTIVITY_NO_ANIMATION))
        finish()
    }

    private fun onMessage(m: JSONObject) {
        when (m.optString("t")) {
            "ready" -> { ready = true; sendState(); pushTabs(); pushStatus(); if (state.isEmpty()) begin() }
            "layout" -> {
                val sw = m.optDouble("sw", 56.0); val th = m.optDouble("th", 52.0)
                val lp = content.layoutParams as FrameLayout.LayoutParams
                lp.leftMargin = (sw * density).roundToInt(); lp.topMargin = (th * density).roundToInt()
                lp.width = ViewGroup.LayoutParams.MATCH_PARENT; lp.height = ViewGroup.LayoutParams.MATCH_PARENT
                content.layoutParams = lp
                layoutOk = true; updateVisibility()
            }
            "cover" -> { covered = m.optBoolean("on"); overlay = covered && m.optBoolean("light"); updateVisibility() }
            "nav" -> {
                val input = m.optString("url"); val newTab = m.optBoolean("on")
                bg.execute {
                    val r = helper.call("normalize", JSONObject().put("input", input).put("engine", prof().optString("search", "google"))
                        .put("lang", lang()).put("googleFix", !prof().optBoolean("noGoogleFix")))
                    val u = r.optString("url")
                    if (u.isNotEmpty()) main.post { val a = active; if (newTab || a == null) newTab(u, true) else navigate(a, u) }
                }
            }
            "newtab" -> newTab("", true)
            "activate" -> tabById(m.optInt("tab"))?.let { activate(it) }
            "close" -> tabById(m.optInt("tab"))?.let { closeTab(it) }
            "move" -> moveTab(m.optInt("tab"), m.optInt("to"))
            "back" -> active?.view?.goBack()
            "fwd" -> active?.view?.goForward()
            "reload" -> active?.let { it.crashed = false; it.view?.reload() }
            "stop" -> active?.view?.stopLoading()
            "focusTab" -> active?.view?.requestFocus()
            "reopen" -> reopenClosed()
            "collapsed" -> {}
            "search" -> { prof().put("search", m.optString("engine")); saveConfig(); sendState() }
            "profileSave" -> {
                val n = m.optString("name").trim()
                if (n.isEmpty() || n.length > 32) { toast("Name must be 1–32 characters", true); return }
                prof().put("name", n); if (Regex("^#[0-9a-fA-F]{6}$").matches(m.optString("color"))) prof().put("color", m.optString("color"))
                saveConfig(); sendState(); toast("Profile saved")
            }
            "profileNew" -> {
                val n = m.optString("name").trim().take(32); if (n.isEmpty()) return
                val p = JSONObject().put("id", newId()).put("name", n).put("color", m.optString("color", "#60a5fa")).put("search", prof().optString("search", "google")).put("created", now())
                profiles().put(p); saveConfig(); openProfile(p.getString("id"))
            }
            "profileOpen" -> if (m.optString("id") != profId) openProfile(m.optString("id"))
            "profileDel" -> deleteProfile(m.optString("id"))
            "proxyAdd" -> addProxy(m.optString("name"), m.optString("link"))
            "proxyTest" -> testProxy(m.optString("id"))
            "proxyDel" -> deleteProxy(m.optString("id"))
            "proxyApply" -> applyProxy(m.optBoolean("on"), m.optString("id"), m.optString("bypass"))
            "proxyOff" -> applyProxy(false, "", prof().optString("bypass"))
            "startup" -> setStartup(prof(), m.optString("id"), m.optString("url")) { saveConfig(); sendState(); if (!keepData()) history.clear() }
            "retry" -> begin()
            "reset" -> resetIdentity()
            "privacy" -> {
                when (m.optString("id")) {
                    "capture" -> { prof().put("allowCapture", !m.optBoolean("on")); applyShield(); if (proxyOn) setCheck("capture", if (m.optBoolean("on")) "ok" else "warn", if (m.optBoolean("on")) "Screenshots & screen recording see nothing" else "Off in settings") }
                }
                saveConfig(); sendState()
            }
            "tr" -> onTranslateOp(m.optString("id"))
            "adblock", "langMatch" -> {
                if (m.optString("t") == "adblock") prof().put("noAdblock", !m.optBoolean("on")) else prof().put("noLangMatch", !m.optBoolean("on"))
                saveConfig(); sendState(); restartTunnel()
            }
            "siteMode" -> active?.let { t ->
                t.alt = m.optBoolean("on")
                t.view?.let { v ->
                    v.settings.userAgentString = if (t.alt) desktopUA else null
                    v.settings.useWideViewPort = true; v.settings.loadWithOverviewMode = true
                    v.reload()
                }
                pushTabs()
            }
            "exit" -> finish()
            "home" -> active?.let { navigate(it, "${BASE}start") }
            "mainMenu" -> finish() // the CoreKit main menu is the screen under the browser
            "history" -> sendHistory(m.optString("name"))
            "histDel" -> { val u = m.optString("url"); val at = m.optLong("to"); history.removeAll { it.optString("u") == u && (at == 0L || it.optLong("at") == at) }; sendHistory(m.optString("name")); scheduleSave() }
            "histClear" -> { history.clear(); vault.delete("p/$profId/history.bin"); sendHistory("") }
            "lang" -> { prof().put("lang", m.optString("id")); saveConfig(); sendState(); active?.let { decideTranslate(it) } }
            "transOpt" -> {
                when (m.optString("id")) { "offer" -> prof().put("noTransOffer", !m.optBoolean("on")); "auto" -> prof().put("transAuto", m.optBoolean("on")); "google" -> prof().put("noGoogleFix", !m.optBoolean("on")) }
                saveConfig(); sendState()
            }
            "langList" -> { val l = m.optString("id"); prof().put("alwaysLangs", without(prof().optJSONArray("alwaysLangs"), l)); prof().put("neverLangs", without(prof().optJSONArray("neverLangs"), l)); saveConfig(); sendState() }
        }
    }

    // ---------------------------------------------------------------- state for the UI

    private fun sendState() {
        val p = prof()
        val ps = JSONArray()
        for (x in list(profiles())) ps.put(JSONObject().put("id", x.optString("id")).put("name", x.optString("name")).put("color", x.optString("color")).put("current", x.optString("id") == profId).put("running", false))
        val pxs = JSONArray()
        for (x in list(proxies())) pxs.put(JSONObject().put("id", x.optString("id")).put("name", x.optString("name")).put("kind", x.optString("kind", "proxy")).put("test", x.opt("test") ?: JSONObject.NULL))
        val chosen = chosenProxy(p)
        post(JSONObject().put("t", "state").put("version", info.optString("version")).put("webview", webViewVersion()).put("xray", "Xray (built in)")
            .put("profile", JSONObject().put("id", profId).put("name", p.optString("name")).put("color", p.optString("color")).put("search", p.optString("search", "google")).put("bypass", p.optString("bypass")))
            .put("profiles", ps).put("proxies", pxs).put("proxyActive", if (proxyOn) chosen?.optString("id") ?: "" else "").put("proxyChosen", chosen?.optString("id") ?: "")
            .put("proxyOn", p.optString("proxy").isNotEmpty()).put("engines", info.optJSONArray("engines") ?: JSONArray()).put("collapsed", true)
            .put("colors", JSONArray(colors())).put("shield", !p.optBoolean("allowCapture")).put("noTrace", startMode(p) == "clear").put("startup", startMode(p)).put("startPage", p.optString("startUrl")).put("tz", geo.optString("tz"))
            .put("lang", lang()).put("langs", info.optJSONArray("langs") ?: JSONArray()).put("transOffer", !p.optBoolean("noTransOffer")).put("transAuto", p.optBoolean("transAuto"))
            .put("googleFix", !p.optBoolean("noGoogleFix")).put("alwaysLangs", named(p.optJSONArray("alwaysLangs"))).put("neverLangs", named(p.optJSONArray("neverLangs")))
            .put("platform", "android").put("adblock", !p.optBoolean("noAdblock")).put("langMatch", !p.optBoolean("noLangMatch")))
    }

    private fun webViewVersion() = WebViewCompat.getCurrentWebViewPackage(this)?.versionName ?: ""
    private fun langName(c: String): String = info.optJSONObject("langNames")?.optString(c.substringBefore('-').lowercase())?.ifEmpty { null } ?: c.uppercase()
    private fun named(a: JSONArray?): JSONArray { val o = JSONArray(); if (a != null) for (i in 0 until a.length()) o.put(JSONObject().put("code", a.getString(i)).put("name", langName(a.getString(i)))); return o }
    private fun without(a: JSONArray?, l: String): JSONArray { val o = JSONArray(); if (a != null) for (i in 0 until a.length()) if (a.getString(i).substringBefore('-') != l.substringBefore('-')) o.put(a.getString(i)); return o }
    private fun has(a: JSONArray?, l: String) = a != null && (0 until a.length()).any { a.getString(it).substringBefore('-').equals(l.substringBefore('-'), true) }

    private fun setStatus(s: String, msg: String) { state = s; stateMsg = msg; updateVisibility(); pushStatus() }
    private fun pushStatus() {
        post(JSONObject().put("t", "status").put("state", state).put("msg", stateMsg).put("proxy", if (proxyOn) chosenProxy()?.optString("name") ?: "" else "")
            .put("ip", maskIp(tunnelIp)).put("country", country).put("ms", ms).put("checks", checks).put("tz", geo.optString("tz")))
    }
    private fun maskIp(ip: String): String { val p = ip.split("."); return if (p.size == 4) "${p[0]}.•••.•••.${p[3]}" else if (ip.length > 8) ip.take(4) + "•••" + ip.takeLast(4) else "" }
    private fun setCheck(id: String, st: String, detail: String) {
        for (i in 0 until checks.length()) { val c = checks.getJSONObject(i); if (c.optString("id") == id) c.put("state", st).put("detail", detail) }
        pushStatus()
    }

    private var pushQueued = false
    private fun pushTabs() {
        if (pushQueued) return
        pushQueued = true
        main.post {
            pushQueued = false
            val arr = JSONArray()
            for (t in tabs) arr.put(JSONObject().put("id", t.id).put("title", tabTitle(t)).put("url", display(tabUrl(t))).put("loading", t.loading).put("crashed", t.crashed))
            val m = JSONObject().put("t", "tabs").put("tabs", arr).put("active", active?.id ?: 0).put("closedCount", closed.size)
            active?.let { t ->
                m.put("alt", t.alt)
                m.put("canBack", t.canBack).put("canFwd", t.canFwd).put("loading", t.loading).put("url", display(tabUrl(t)))
                m.put("tr", JSONObject().put("state", t.trState).put("from", t.pageLang).put("fromName", if (t.pageLang.isEmpty()) "" else langName(t.pageLang))
                    .put("to", lang()).put("toName", langName(lang())).put("msg", t.trMsg).put("page", tabUrl(t).startsWith("http") && !isStart(tabUrl(t))))
            }
            post(m)
        }
    }
    private fun tabUrl(t: Tab) = t.url.ifEmpty { t.pending }
    private fun tabTitle(t: Tab): String = if (isStart(tabUrl(t))) "New tab" else t.title.ifEmpty { tabUrl(t) }

    private fun updateVisibility() {
        val show = fullView == null && ready && layoutOk && state == "ready" && (!covered || overlay)
        // a small menu is drawn above the page (this screen is see-through then); otherwise the page is on top
        val top = if (overlay && show) chrome else content
        if (root.indexOfChild(top) != root.childCount - 1 && fullView == null) top.bringToFront()
        content.visibility = if (show) View.VISIBLE else View.INVISIBLE
    }

    // ---------------------------------------------------------------- start-up: tunnel + leak checks

    private fun resetChecks() {
        checks = JSONArray()
        for ((id, label) in listOf("tunnel" to "Encrypted tunnel", "ip" to "Real IP hidden", "dns" to "DNS only through the tunnel", "webrtc" to "WebRTC leak blocked",
            "tz" to "Time zone matches the proxy", "geo" to "Location masked", "dnt" to "Do Not Track on", "capture" to "Hidden from screen capture"))
            checks.put(JSONObject().put("id", id).put("label", label).put("state", "wait").put("detail", ""))
    }

    private fun begin() {
        val px = chosenProxy()
        val seq = ++checkSeq
        tunnelIp = ""; country = ""; ms = 0
        if (px == null) {
            proxyOn = false; checks = JSONArray(); geo = JSONObject()
            if (WebViewFeature.isFeatureSupported(WebViewFeature.PROXY_OVERRIDE)) ProxyController.getInstance().clearProxyOverride({ it.run() }, {})
            bg.execute {
                val s = helper.call("scripts", JSONObject())
                main.post { if (seq == checkSeq) { setScripts(s); setStatus("ready", ""); restoreTabs() } }
            }
            return
        }
        if (!WebViewFeature.isFeatureSupported(WebViewFeature.PROXY_OVERRIDE)) {
            setStatus("error", "This phone's Android System WebView is too old for proxy browsing. Update \"Android System WebView\" from the Play Store.")
            return
        }
        proxyOn = true
        resetChecks(); setCheck("tunnel", "run", "Connecting to ${px.optString("name")}")
        setStatus("connecting", "Starting secure tunnel")
        val link = px.optString("link")
        bg.execute {
            val err = xray.start(link)
            if (err != null) { main.post { if (seq == checkSeq) { setCheck("tunnel", "fail", "Engine could not start"); setStatus("error", "The proxy engine could not start: $err") } }; return@execute }
            val port = xray.port
            // fail closed: from now on every page request goes to the tunnel (or nowhere)
            val latch = java.util.concurrent.CountDownLatch(1)
            main.post {
                val b = ProxyConfig.Builder().addProxyRule("127.0.0.1:${port + 1}")
                prof().optString("bypass").split(',', ';', ' ', '\n').map { it.trim().removePrefix("https://").removePrefix("http://").substringBefore('/') }
                    .filter { Regex("^[a-z0-9.\\-]+$").matches(it) }.forEach { b.addBypassRule(it); b.addBypassRule("*.$it") }
                ProxyController.getInstance().setProxyOverride(b.build(), { it.run() }, { latch.countDown() })
            }
            latch.await(5, java.util.concurrent.TimeUnit.SECONDS)
            main.post { if (seq == checkSeq) setStatus("connecting", "Checking the proxy connection") }
            val t = helper.call("tunnel", JSONObject().put("port", port))
            px.put("test", JSONObject().put("ok", t.optBoolean("ok")).put("ms", t.optInt("ms")).put("country", t.optString("country")).put("hidden", true).put("error", t.optString("error")).put("at", now()))
            saveConfig()
            if (!t.optBoolean("ok")) { main.post { if (seq == checkSeq) { setCheck("tunnel", "fail", t.optString("error")); setStatus("error", "No connection through ${px.optString("name")}: ${t.optString("error")}") } }; return@execute }
            main.post { if (seq == checkSeq) { ms = t.optInt("ms"); tunnelIp = t.optString("ip"); setCheck("tunnel", "ok", "${px.optString("kind")} · ${ms} ms"); setCheck("tz", "run", "Looking up the proxy location"); setStatus("connecting", "Matching time zone and location") } }
            val g = helper.call("geo", JSONObject().put("port", port).put("country", t.optString("country")))
            val s = helper.call("scripts", JSONObject().put("tz", g.optString("tz")).put("country", g.optString("country").ifEmpty { t.optString("country") }))
            main.post { if (seq == checkSeq) { geo = g; setScripts(s); setStatus("connecting", "Running leak tests"); browserCheck(seq) } }
            watchTunnel(seq)
        }
    }

    private fun watchTunnel(seq: Int) {
        main.postDelayed({
            if (seq != checkSeq || isFinishing) return@postDelayed
            if (!xray.alive()) setStatus("error", "The proxy tunnel stopped. Browsing is paused so your real IP stays hidden.")
            else watchTunnel(seq)
        }, 3000)
    }

    @SuppressLint("SetJavaScriptEnabled")
    private fun browserCheck(seq: Int) {
        var done = false
        val v = WebView(this)
        if (multiProfile) { ProfileStore.getInstance().getOrCreateProfile(profileName()); WebViewCompat.setProfile(v, profileName()) }
        v.settings.javaScriptEnabled = true
        installScripts(v)
        fun finish(ok: Boolean, st: String, msg: String) {
            if (done) return
            done = true
            main.post { v.destroy() }
            if (seq != checkSeq) return
            if (!ok) { setStatus(st, msg); return }
            setStatus("ready", ""); restoreTabs()
        }
        fun fail(id: String, d: String, st: String, msg: String) { setCheck(id, "fail", d); finish(false, st, msg) }
        main.postDelayed({ finish(false, "error", "The protection checks timed out. The proxy may be slow or blocked.") }, 45000)
        setCheck("dns", "ok", "Names are resolved by the proxy, not this network")
        setCheck("capture", if (!prof().optBoolean("allowCapture")) "ok" else "warn", if (!prof().optBoolean("allowCapture")) "Screenshots & screen recording see nothing" else "Off in settings")
        fun eval(code: String, next: (String) -> Unit) = v.evaluateJavascript(code) { r ->
            val s = try { org.json.JSONTokener(r).nextValue() as? String } catch (_: Throwable) { null }
            if (s == null) fail("ip", "Script error", "error", "A protection check could not run.") else next(s)
        }
        v.webViewClient = object : WebViewClient() {
            override fun onPageFinished(view: WebView, url: String) {
                if (done || !url.contains("cdn-cgi/trace")) return
                setCheck("ip", "run", "Checking")
                eval("document.body ? document.body.innerText : ''") { txt ->
                    val kv = txt.lines().mapNotNull { l -> l.indexOf('=').takeIf { it > 0 }?.let { l.substring(0, it) to l.substring(it + 1).trim() } }.toMap()
                    val ip = kv["ip"] ?: ""
                    when {
                        ip.isEmpty() -> fail("ip", "No answer", "error", "The IP check returned nothing.")
                        tunnelIp.isNotEmpty() && ip != tunnelIp -> fail("ip", "Different address than the tunnel", "leak", "")
                        else -> {
                            country = kv["loc"] ?: country
                            setCheck("ip", "ok", "Sites see ${maskIp(ip)} · $country")
                            setCheck("webrtc", "run", "Testing")
                            eval(scripts.optString("webrtc")) {
                                main.postDelayed({
                                    if (done) return@postDelayed
                                    eval("JSON.stringify(window.__ck||{})") { res ->
                                        val c = try { JSONObject(res).optJSONArray("c") ?: JSONArray() } catch (_: Throwable) { JSONArray() }
                                        if (c.length() > 0) { fail("webrtc", "Address exposed", "leak", ""); return@eval }
                                        setCheck("webrtc", "ok", "WebRTC is switched off")
                                        eval("[Intl.DateTimeFormat().resolvedOptions().timeZone, navigator.doNotTrack].join('|')") { r ->
                                            val f = r.split("|")
                                            val tz = geo.optString("tz")
                                            when {
                                                tz.isEmpty() -> setCheck("tz", "warn", "Proxy location unknown · phone time zone kept")
                                                f[0] == tz -> setCheck("tz", "ok", tz.replace('_', ' '))
                                                else -> { fail("tz", "Could not apply $tz", "error", "The time zone could not be matched to the proxy, so pages stay hidden."); return@eval }
                                            }
                                            setCheck("geo", "ok", "Location requests are refused")
                                            setCheck("dnt", if (f.getOrNull(1) == "1") "ok" else "warn", if (f.getOrNull(1) == "1") "Sites are asked not to track you" else "Not supported here")
                                            finish(true, "", "")
                                        }
                                    }
                                }, 3500)
                            }
                        }
                    }
                }
            }
            override fun onReceivedError(view: WebView, req: WebResourceRequest, err: android.webkit.WebResourceError) {
                if (req.isForMainFrame) fail("ip", "Page did not load", "error", "The browser could not connect through the proxy (${err.description}).")
            }
        }
        v.loadUrl("https://www.cloudflare.com/cdn-cgi/trace")
    }

    private fun profileName() = "ck-$profId"

    private fun setScripts(s: JSONObject) {
        scripts = s
        adHosts = HashSet<String>().also { h -> s.optJSONArray("adHosts")?.let { a -> for (i in 0 until a.length()) h += a.getString(i) } }
        applyLocale()
    }

    /**
     * WebView builds the Accept-Language header (what whoer and sites read) from the app's
     * locale list, picked up when a WebView is created or told the configuration changed.
     * With the proxy on, it becomes the VPN country's list (de-DE, de, en-US, en); otherwise
     * the phone's own. Tabs are always created after this runs.
     */
    private fun applyLocale() {
        val l = scripts.optJSONArray("langList")
        val want = if (proxyOn && !prof().optBoolean("noLangMatch") && l != null && l.length() > 0)
            LocaleList(*Array(l.length()) { java.util.Locale.forLanguageTag(l.getString(it)) }) else sysLocales
        if (LocaleList.getDefault() != want) { LocaleList.setDefault(want); java.util.Locale.setDefault(want[0]) }
    }

    override fun onConfigurationChanged(newConfig: Configuration) {
        super.onConfigurationChanged(newConfig)
        if (picker) return
        applyLocale() // the system may put its own list back on a configuration change
        main.post { val c = resources.configuration; for (t in tabs) t.view?.dispatchConfigurationChanged(c) }
    }
    private fun adblockOn() = !prof().optBoolean("noAdblock")
    private fun isAd(host: String?): Boolean {
        var h = host?.lowercase() ?: return false
        while (true) {
            if (h in adHosts) return true
            val i = h.indexOf('.'); if (i < 0) return false
            h = h.substring(i + 1)
        }
    }
    private val desktopUA by lazy {
        android.webkit.WebSettings.getDefaultUserAgent(this).replace(Regex("\\(Linux; Android [^)]*\\)"), "(X11; Linux x86_64)")
            .replace(" Mobile", "").replace("Version/4.0 ", "")
    }

    /** Privacy scripts every page gets before its own code: DNT, time zone, no WebRTC (proxy). */
    private fun installScripts(v: WebView) {
        if (!docStart) return
        val all = StringBuilder(scripts.optString("privacy"))
        if (adblockOn()) all.append(scripts.optString("adCss"))
        if (proxyOn) all.append(scripts.optString("noWebrtc")).append(scripts.optString("tz"))
        if (proxyOn && !prof().optBoolean("noLangMatch")) all.append(scripts.optString("lang"))
        if (all.isNotEmpty()) WebViewCompat.addDocumentStartJavaScript(v, all.toString(), setOf("*"))
    }

    // ---------------------------------------------------------------- tabs

    private fun tabById(id: Int) = tabs.firstOrNull { it.id == id }

    private fun restoreTabs() {
        if (restored) { active?.let { activate(it) }; updateVisibility(); return }
        restored = true
        val mode = startMode()
        val keep = mode != "clear"
        if (keep) vault.read("p/$profId/history.bin")?.let { s -> try { val a = JSONArray(s); for (i in 0 until a.length()) history += a.getJSONObject(i) } catch (_: Throwable) {} }
        val sess = vault.read("p/$profId/session.bin")?.let { try { JSONObject(it) } catch (_: Throwable) { null } }
        if (mode == "page" && prof().optString("startUrl").isNotEmpty()) { newTab(prof().optString("startUrl"), true); return }
        if (mode == "restore" && sess != null) {
            val a = sess.optJSONArray("tabs") ?: JSONArray()
            for (i in 0 until a.length()) { val r = a.getJSONObject(i); tabs += Tab(nextId++).apply { pending = r.optString("u"); title = r.optString("t") } }
            sess.optJSONArray("closed")?.let { for (i in 0 until it.length()) closed += it.getJSONObject(i) }
            if (tabs.isNotEmpty()) { activate(tabs[sess.optInt("active").coerceIn(0, tabs.size - 1)]); return }
        }
        newTab("", true)
    }

    private fun newTab(u: String, activate: Boolean): Tab {
        val t = Tab(nextId++).apply { pending = u }
        val i = if (active != null && u.isNotEmpty()) tabs.indexOf(active) + 1 else tabs.size
        tabs.add(i.coerceIn(0, tabs.size), t)
        if (activate || active == null) activate(t) else ensureView(t)
        pushTabs(); scheduleSave()
        return t
    }

    private fun activate(t: Tab) {
        active?.takeIf { it != t }?.view?.visibility = View.GONE
        active = t
        if (t.view == null) ensureView(t)
        t.view?.visibility = View.VISIBLE
        if (isStart(tabUrl(t))) js("document.getElementById('url')&&(document.getElementById('url').focus())")
        pushTabs(); scheduleSave()
    }

    @SuppressLint("SetJavaScriptEnabled")
    private fun makeView(t: Tab): WebView {
        val v = WebView(this)
        if (multiProfile) { ProfileStore.getInstance().getOrCreateProfile(profileName()); WebViewCompat.setProfile(v, profileName()) }
        v.setBackgroundColor(0xFFFFFFFF.toInt())
        with(v.settings) {
            javaScriptEnabled = true; domStorageEnabled = true; databaseEnabled = true
            setSupportMultipleWindows(true); javaScriptCanOpenWindowsAutomatically = true
            loadWithOverviewMode = true; useWideViewPort = true; builtInZoomControls = true; displayZoomControls = false
            allowFileAccess = false; allowContentAccess = false; mediaPlaybackRequiresUserGesture = true
            mixedContentMode = android.webkit.WebSettings.MIXED_CONTENT_NEVER_ALLOW
            setGeolocationEnabled(false)
        }
        CookieManager.getInstance().setAcceptThirdPartyCookies(v, true)
        installScripts(v)
        v.webViewClient = tabClient(t)
        v.webChromeClient = tabChrome
        v.setDownloadListener { url, ua, cd, mime, _ -> download(url, ua, cd, mime) }
        content.addView(v, FrameLayout.LayoutParams(-1, -1))
        v.visibility = if (t == active) View.VISIBLE else View.GONE
        return v
    }

    private fun ensureView(t: Tab) {
        if (t.view != null) return
        val v = makeView(t); t.view = v
        v.loadUrl(t.pending.ifEmpty { "${BASE}start" })
    }

    private fun navigate(t: Tab, u: String) { t.pending = u; t.crashed = false; if (t.view == null) ensureView(t) else t.view!!.loadUrl(u) }

    private fun tabClient(t: Tab) = object : WebViewClient() {
        override fun shouldInterceptRequest(view: WebView, req: WebResourceRequest): WebResourceResponse? {
            if (adblockOn() && !req.isForMainFrame && isAd(req.url.host))
                return WebResourceResponse("text/plain", "utf-8", 204, "No Content", emptyMap(), ByteArrayInputStream(ByteArray(0)))
            return serveLocal(req.url, false)
        }
        override fun shouldOverrideUrlLoading(view: WebView, req: WebResourceRequest): Boolean {
            val u = req.url; val s = u.scheme ?: ""
            if (s == "http" || s == "https") {
                if (req.isForMainFrame && (u.host ?: "").contains("google.") && !prof().optBoolean("noGoogleFix")) {
                    val r = helper.call("googlefix", JSONObject().put("url", u.toString()).put("lang", lang()), 5)
                    if (r.optBoolean("changed")) { view.loadUrl(r.optString("url")); return true }
                }
                return false
            }
            // other schemes open their app (intent://, mailto:, tel:, whatsapp: ...)
            try {
                val i = if (s == "intent") Intent.parseUri(u.toString(), Intent.URI_INTENT_SCHEME) else Intent(Intent.ACTION_VIEW, u)
                i.addCategory(Intent.CATEGORY_BROWSABLE); i.component = null; i.selector = null
                startActivity(i)
            } catch (_: Throwable) { toast("No app can open this link", true) }
            return true
        }
        override fun onPageStarted(view: WebView, url: String, favicon: Bitmap?) {
            if (!docStart) { // older WebView: best effort
                view.evaluateJavascript(scripts.optString("privacy") + (if (adblockOn()) scripts.optString("adCss") else "") +
                    (if (proxyOn) scripts.optString("noWebrtc") + scripts.optString("tz") else ""), null)
            }
            t.loading = true; t.url = url; t.trSeq++; t.pageLang = ""; t.trState = ""; t.trMsg = ""
            pushTabs()
        }
        override fun onPageFinished(view: WebView, url: String) {
            t.loading = false; t.url = url; t.title = view.title ?: ""; t.canBack = view.canGoBack(); t.canFwd = view.canGoForward()
            if (url.startsWith("http") && !isStart(url)) { addHistory(url, t.title); afterLoad(t) }
            pushTabs(); scheduleSave()
        }
        override fun doUpdateVisitedHistory(view: WebView, url: String, isReload: Boolean) {
            t.url = url; t.canBack = view.canGoBack(); t.canFwd = view.canGoForward()
            if (t.trState == "done" || t.trState == "doneHidden") translate(t, true)
            pushTabs()
        }
        override fun onRenderProcessGone(view: WebView, detail: android.webkit.RenderProcessGoneDetail): Boolean {
            t.crashed = true; t.title = "Page crashed — reload"; t.view = null
            content.removeView(view); view.destroy(); pushTabs()
            return true
        }
    }

    private val tabChrome = object : WebChromeClient() {
        override fun onReceivedTitle(view: WebView, title: String) {
            tabs.firstOrNull { it.view == view }?.let { it.title = title; history.lastOrNull()?.takeIf { h -> h.optString("u") == it.url }?.put("t", title); pushTabs() }
        }
        override fun onCreateWindow(view: WebView, isDialog: Boolean, isUserGesture: Boolean, resultMsg: Message): Boolean {
            val t = Tab(nextId++)
            tabs.add((tabs.indexOf(active) + 1).coerceIn(0, tabs.size), t)
            val nv = makeView(t); t.view = nv
            (resultMsg.obj as WebView.WebViewTransport).webView = nv
            resultMsg.sendToTarget()
            activate(t)
            return true
        }
        override fun onCloseWindow(window: WebView) { tabs.firstOrNull { it.view == window }?.let { closeTab(it) } }
        override fun onGeolocationPermissionsShowPrompt(origin: String, callback: GeolocationPermissions.Callback) = callback.invoke(origin, false, false)
        override fun onPermissionRequest(request: PermissionRequest) {
            if (proxyOn) { request.deny(); return } // camera/mic need WebRTC, which is off with the proxy
            val need = request.resources.mapNotNull { when (it) { PermissionRequest.RESOURCE_VIDEO_CAPTURE -> Manifest.permission.CAMERA; PermissionRequest.RESOURCE_AUDIO_CAPTURE -> Manifest.permission.RECORD_AUDIO; else -> null } }
            val missing = need.filter { checkSelfPermission(it) != PackageManager.PERMISSION_GRANTED }
            if (missing.isEmpty()) request.grant(request.resources) else { pendingPerm = request; requestPermissions(missing.toTypedArray(), 21) }
        }
        override fun onShowCustomView(view: View, callback: CustomViewCallback) {
            if (fullView != null) { callback.onCustomViewHidden(); return }
            fullView = view; fullCb = callback
            root.addView(view, FrameLayout.LayoutParams(-1, -1)); root.setPadding(0, 0, 0, 0); updateVisibility()
            WindowInsetsControllerCompat(window, root).apply { hide(WindowInsetsCompat.Type.systemBars()); systemBarsBehavior = WindowInsetsControllerCompat.BEHAVIOR_SHOW_TRANSIENT_BARS_BY_SWIPE }
        }
        override fun onHideCustomView() {
            fullView?.let { root.removeView(it) }; fullView = null
            fullCb?.onCustomViewHidden(); fullCb = null
            WindowInsetsControllerCompat(window, root).show(WindowInsetsCompat.Type.systemBars())
            ViewCompat.requestApplyInsets(root); updateVisibility()
        }
        override fun onShowFileChooser(view: WebView, cb: ValueCallback<Array<Uri>>, params: FileChooserParams): Boolean {
            fileCb?.onReceiveValue(null); fileCb = cb
            return try { startActivityForResult(params.createIntent(), 31); true } catch (e: ActivityNotFoundException) { fileCb = null; false }
        }
    }

    @Deprecated("file chooser result")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        if (requestCode == 31) { fileCb?.onReceiveValue(WebChromeClient.FileChooserParams.parseResult(resultCode, data)); fileCb = null }
        @Suppress("DEPRECATION") super.onActivityResult(requestCode, resultCode, data)
    }

    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        val r = pendingPerm ?: return; pendingPerm = null
        if (grantResults.isNotEmpty() && grantResults.all { it == PackageManager.PERMISSION_GRANTED }) r.grant(r.resources) else r.deny()
    }

    private fun closeTab(t: Tab) {
        val i = tabs.indexOf(t); if (i < 0) return
        if (!isStart(tabUrl(t))) { closed += JSONObject().put("u", tabUrl(t)).put("t", tabTitle(t)); while (closed.size > 25) closed.removeAt(0) }
        t.gone = true; tabs.removeAt(i)
        t.view?.let { content.removeView(it); it.destroy() }; t.view = null
        if (t == active) { active = null; if (tabs.isNotEmpty()) activate(tabs[minOf(i, tabs.size - 1)]) }
        if (tabs.isEmpty()) newTab("", true)
        pushTabs(); scheduleSave()
    }

    private fun reopenClosed() { if (closed.isEmpty()) return; val r = closed.removeAt(closed.size - 1); newTab(r.optString("u"), true).title = r.optString("t") }

    private fun moveTab(id: Int, to: Int) {
        val i = tabs.indexOfFirst { it.id == id }; if (i < 0 || to !in tabs.indices || to == i) return
        val t = tabs.removeAt(i); tabs.add(to, t); pushTabs(); scheduleSave()
    }

    // ---------------------------------------------------------------- history + session

    private fun addHistory(u: String, title: String) {
        val last = history.lastOrNull()
        if (last != null && last.optString("u") == u) { last.put("at", now()); if (title.isNotEmpty()) last.put("t", title) }
        else history += JSONObject().put("u", u).put("t", title).put("at", now())
        while (history.size > 5000) history.removeAt(0)
    }

    private fun sendHistory(q: String) {
        val ql = q.lowercase().trim()
        val items = JSONArray()
        for (h in history.asReversed()) {
            if (items.length() >= 400) break
            if (ql.isEmpty() || h.optString("t").lowercase().contains(ql) || h.optString("u").lowercase().contains(ql)) items.put(h)
        }
        post(JSONObject().put("t", "history").put("items", items).put("persist", keepData()))
    }

    private fun scheduleSave() {
        saveTask?.let { main.removeCallbacks(it) }
        saveTask = Runnable { saveNow() }.also { main.postDelayed(it, 1500) }
    }

    private fun saveNow() {
        if (picker || !restored || !keepData()) return
        val a = JSONArray()
        for (t in tabs) a.put(JSONObject().put("u", if (isStart(tabUrl(t))) "" else tabUrl(t)).put("t", tabTitle(t)))
        val s = JSONObject().put("tabs", a).put("active", tabs.indexOf(active).coerceAtLeast(0)).put("closed", JSONArray(closed)).toString()
        val h = JSONArray(history).toString()
        val id = profId
        bg.execute { vault.write("p/$id/session.bin", s); vault.write("p/$id/history.bin", h) }
    }

    // ---------------------------------------------------------------- translation (shared Go translator)

    private fun afterLoad(t: Tab) {
        val v = t.view ?: return; val seq = t.trSeq
        v.evaluateJavascript(scripts.optString("detect")) { r ->
            val d = try { JSONObject(org.json.JSONTokener(r).nextValue() as String) } catch (_: Throwable) { return@evaluateJavascript }
            if (seq != t.trSeq) return@evaluateJavascript
            val l = d.optString("l")
            if (l.isNotEmpty()) { t.pageLang = l; decideTranslate(t); return@evaluateJavascript }
            val sample = d.optString("s"); if (sample.length < 40) return@evaluateJavascript
            bg.execute {
                val det = helper.call("detect", JSONObject().put("sample", sample).put("port", if (proxyOn) xray.port else 0)).optString("lang")
                main.post { if (seq == t.trSeq && det.isNotEmpty()) { t.pageLang = det; decideTranslate(t) } }
            }
        }
    }

    private fun decideTranslate(t: Tab) {
        val p = prof()
        when {
            t.pageLang.isEmpty() || t.pageLang.substringBefore('-').equals(lang().substringBefore('-'), true) -> if (t.trState == "offer") t.trState = ""
            t.trState in listOf("done", "doneHidden", "working") -> {}
            has(p.optJSONArray("neverLangs"), t.pageLang) -> t.trState = ""
            p.optBoolean("transAuto") || has(p.optJSONArray("alwaysLangs"), t.pageLang) -> { translate(t, false); return }
            p.optBoolean("noTransOffer") -> t.trState = ""
            else -> t.trState = "offer"
        }
        pushTabs()
    }

    private fun translate(t: Tab, more: Boolean) {
        val v = t.view ?: return; val seq = t.trSeq
        if (!more) { t.trState = "working"; t.trMsg = ""; pushTabs() }
        v.evaluateJavascript(scripts.optString("collect")) { r ->
            if (seq != t.trSeq || t.gone) return@evaluateJavascript
            val c = try { JSONObject(org.json.JSONTokener(r).nextValue() as String) } catch (_: Throwable) {
                if (!more) { t.trState = "error"; t.trMsg = "This page cannot be translated in place."; pushTabs() }; return@evaluateJavascript
            }
            val texts = c.optJSONArray("texts") ?: JSONArray()
            if (texts.length() == 0) { if (!more) { t.trState = "done"; pushTabs(); follow(t, seq, 0) }; return@evaluateJavascript }
            bg.execute {
                val res = helper.call("translate", JSONObject().put("texts", texts).put("to", lang()).put("port", if (proxyOn) xray.port else 0), 120)
                main.post {
                    if (seq != t.trSeq || t.trState == "original") return@post
                    val out = res.optJSONArray("out")
                    if (out == null) { if (!more) { t.trState = "error"; t.trMsg = "The translation service could not be reached."; pushTabs() }; return@post }
                    t.view?.evaluateJavascript("window.__ckA&&window.__ckA(${c.optInt("base")},$out)", null)
                    if (t.pageLang.isEmpty()) t.pageLang = res.optString("detected")
                    if (!more) { t.trState = "done"; pushTabs(); follow(t, seq, 0) }
                }
            }
        }
    }

    private fun follow(t: Tab, seq: Int, n: Int) {
        if (n >= 40) return
        main.postDelayed({
            if (seq != t.trSeq || t.gone || (t.trState != "done" && t.trState != "doneHidden")) return@postDelayed
            if (t == active) translate(t, true)
            follow(t, seq, n + 1)
        }, 3000)
    }

    private fun onTranslateOp(op: String) {
        val t = active ?: return; val v = t.view ?: return
        when (op) {
            "translate", "retry" -> { t.trState = ""; translate(t, false) }
            "original" -> { t.trState = "original"; v.evaluateJavascript("window.__ckR&&window.__ckR()", null); pushTabs() }
            "always" -> {
                if (t.pageLang.isNotEmpty()) { val p = prof(); p.put("alwaysLangs", without(p.optJSONArray("alwaysLangs"), t.pageLang).put(t.pageLang.substringBefore('-'))); p.put("neverLangs", without(p.optJSONArray("neverLangs"), t.pageLang)); saveConfig(); sendState() }
                if (t.trState !in listOf("done", "doneHidden", "working")) translate(t, false)
            }
            "never" -> {
                if (t.pageLang.isNotEmpty()) { val p = prof(); p.put("neverLangs", without(p.optJSONArray("neverLangs"), t.pageLang).put(t.pageLang.substringBefore('-'))); p.put("alwaysLangs", without(p.optJSONArray("alwaysLangs"), t.pageLang)); saveConfig(); sendState() }
                t.trState = "dismissed"; pushTabs()
            }
            "dismiss" -> { t.trState = if (t.trState == "done") "doneHidden" else "dismissed"; pushTabs() }
            "google" -> { t.trState = ""; v.loadUrl("https://translate.google.com/translate?sl=auto&tl=${lang().substringBefore('-')}&u=" + Uri.encode(t.url)) }
        }
    }

    // ---------------------------------------------------------------- profiles / proxies

    private fun deleteProfile(id: String) {
        if (id == profId) return
        val a = JSONArray(); for (p in list(profiles())) if (p.optString("id") != id) a.put(p)
        cfg.put("profiles", a); saveConfig()
        if (multiProfile) try { ProfileStore.getInstance().deleteProfile("ck-$id") } catch (_: Throwable) {}
        vault.delete("p/$id")
        sendState(); toast("Profile deleted")
    }

    private fun addProxy(name: String, link: String) {
        bg.execute {
            val r = helper.call("parse", JSONObject().put("link", link.trim()))
            main.post {
                if (r.has("error")) { post(JSONObject().put("t", "proxyAdded").put("error", r.optString("error"))); return@post }
                val px = JSONObject().put("id", newId()).put("name", name.trim().ifEmpty { r.optString("name").ifEmpty { r.optString("kind") } }.take(40))
                    .put("link", link.trim()).put("kind", r.optString("kind")).put("added", now())
                proxies().put(px); if (cfg.optString("default").isEmpty()) cfg.put("default", px.optString("id"))
                saveConfig(); sendState()
                post(JSONObject().put("t", "proxyAdded").put("id", px.optString("id")))
                testProxy(px.optString("id"))
            }
        }
    }

    /** Tests a proxy with its own short-lived engine (does not touch the browsing tunnel). */
    private fun testProxy(id: String) {
        val px = proxyById(id) ?: return
        post(JSONObject().put("t", "proxyTesting").put("id", id))
        bg.execute {
            val x = Xray(this, helper)
            val err = x.start(px.optString("link"))
            val test = if (err != null) JSONObject().put("ok", false).put("error", err) else {
                val r = helper.call("tunnel", JSONObject().put("port", x.port)); x.stop()
                JSONObject().put("ok", r.optBoolean("ok")).put("ms", r.optInt("ms")).put("country", r.optString("country")).put("hidden", true).put("error", r.optString("error"))
            }
            test.put("at", now())
            main.post { px.put("test", test); saveConfig(); post(JSONObject().put("t", "proxyTested").put("id", id).put("test", test)); sendState() }
        }
    }

    private fun deleteProxy(id: String) {
        val inUse = proxyOn && chosenProxy()?.optString("id") == id
        val a = JSONArray(); for (p in list(proxies())) if (p.optString("id") != id) a.put(p)
        cfg.put("proxies", a)
        if (cfg.optString("default") == id) cfg.put("default", if (a.length() > 0) a.getJSONObject(0).optString("id") else "")
        for (p in list(profiles())) if (p.optString("proxy") == id) p.put("proxy", "")
        saveConfig(); sendState()
        if (inUse) restartTunnel()
    }

    /** Android changes the proxy live (no restart): tabs are hidden until the checks pass again. */
    private fun applyProxy(on: Boolean, id: String, bypass: String) {
        val p = prof()
        p.put("bypass", bypass.trim()); p.put("proxy", if (on && proxyById(id) != null) id else "")
        saveConfig(); sendState(); restartTunnel()
        toast(if (on) "Applying proxy…" else "Proxy off")
    }

    private fun restartTunnel() {
        xray.stop()
        for (t in tabs) { t.view?.let { content.removeView(it); it.destroy() }; t.view = null }
        restored = true
        begin()
    }

    private fun resetIdentity() {
        checkSeq++
        for (t in tabs) t.view?.let { content.removeView(it); it.destroy() }
        tabs.clear(); active = null; closed.clear(); history.clear()
        vault.delete("p/$profId")
        if (multiProfile) try { ProfileStore.getInstance().deleteProfile(profileName()) } catch (_: Throwable) {}
        else { CookieManager.getInstance().removeAllCookies(null); WebStorage.getInstance().deleteAllData() }
        WebView(this).apply { clearCache(true); destroy() }
        restored = false
        toast("Identity reset")
        begin()
    }

    // ---------------------------------------------------------------- downloads (through the tunnel)

    private fun download(url: String, ua: String, cd: String?, mime: String?) {
        if (!url.startsWith("http")) { toast("This download type is not supported", true); return }
        val name = URLUtil.guessFileName(url, cd, mime)
        toast("Downloading $name…")
        val port = if (proxyOn) xray.port else 0
        val cookie = CookieManager.getInstance().getCookie(url)
        bg.execute {
            try {
                val c = (if (port > 0) URL(url).openConnection(Proxy(Proxy.Type.HTTP, InetSocketAddress("127.0.0.1", port + 1))) else URL(url).openConnection()) as HttpURLConnection
                c.setRequestProperty("User-Agent", ua); cookie?.let { c.setRequestProperty("Cookie", it) }
                c.connectTimeout = 15000; c.readTimeout = 30000
                val uri = if (Build.VERSION.SDK_INT >= 29) {
                    contentResolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, ContentValues().apply {
                        put(MediaStore.MediaColumns.DISPLAY_NAME, name); put(MediaStore.MediaColumns.MIME_TYPE, mime ?: "application/octet-stream")
                        put(MediaStore.MediaColumns.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS)
                    })!!
                } else Uri.fromFile(java.io.File(getExternalFilesDir(Environment.DIRECTORY_DOWNLOADS), name))
                c.inputStream.use { i -> contentResolver.openOutputStream(uri)!!.use { o -> i.copyTo(o) } }
                main.post { toast("Saved to Downloads: $name") }
            } catch (e: Throwable) { main.post { toast("Download failed: ${e.message ?: "error"}", true) } }
        }
    }

    companion object {
        const val HOST = "appassets.androidplatform.net"
        const val BASE = "https://$HOST/ck/"
    }
}
