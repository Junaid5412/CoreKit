package com.corekit.app

import android.app.KeyguardManager
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.admin.DevicePolicyManager
import android.app.job.JobInfo
import android.app.job.JobParameters
import android.app.job.JobScheduler
import android.app.job.JobService
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import android.provider.Settings
import android.provider.Telephony
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder
import java.security.MessageDigest
import java.text.SimpleDateFormat
import java.util.Locale

/**
 * Security module on Android: checks every app (where it came from, what it can do, whether it
 * hides) and the phone's own protection. Produces the same JSON as the Windows scan
 * (docs/ARCHITECTURE.md), so ui/security.html works unchanged.
 */
object SecurityScanner {
    private const val PREFS = "corekit-security"
    @Volatile var last: JSONObject? = null

    // app stores; anything else (browser, file manager, chat app, "Package installer") is a sideload
    private val STORES = mapOf(
        "com.android.vending" to "Google Play", "com.amazon.venezia" to "Amazon Appstore",
        "com.sec.android.app.samsungapps" to "Galaxy Store", "com.huawei.appmarket" to "Huawei AppGallery",
        "com.xiaomi.mipicks" to "Xiaomi GetApps", "com.xiaomi.market" to "Xiaomi GetApps", "com.heytap.market" to "OPPO App Market",
        "com.oppo.market" to "OPPO App Market", "com.bbk.appstore" to "vivo App Store", "com.vivo.appstore" to "vivo App Store",
        "com.oneplus.market" to "OnePlus Store", "org.fdroid.fdroid" to "F-Droid", "com.aurora.store" to "Aurora Store",
        "com.google.android.feedback" to "Google Play", "com.transsion.phoenix" to "Palm Store", "com.hihonor.appmarket" to "HONOR App Market"
    )
    private val SIDELOADERS = mapOf(
        "com.google.android.packageinstaller" to "a file you opened", "com.android.packageinstaller" to "a file you opened",
        "com.samsung.android.packageinstaller" to "a file you opened", "com.android.chrome" to "Chrome (downloaded file)",
        "org.telegram.messenger" to "Telegram", "com.whatsapp" to "WhatsApp", "com.android.shell" to "a computer (adb)",
        "com.google.android.apps.nbu.files" to "Files by Google", "com.mi.android.globalFileexplorer" to "a file manager",
        "com.sec.android.app.myfiles" to "My Files", "com.facebook.orca" to "Messenger", "com.discord" to "Discord"
    )
    // names that malware likes to pretend to be
    private val FAKE_NAMES = Regex("(?i)^(google( play)? services?|play services|system( update| service| ui)?|android( system| update| service)?|settings|security update|software update|wi-?fi( service)?|chrome|google|update|device (care|security)|battery (saver|service)|sim toolkit|smart ?manager)$")

    private fun prefs(c: Context) = c.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    fun trusted(c: Context): MutableSet<String> = HashSet(prefs(c).getStringSet("trusted", emptySet()) ?: emptySet())
    fun setTrusted(c: Context, s: Set<String>) = prefs(c).edit().putStringSet("trusted", s).apply()
    fun apiKey(c: Context): String = Vault(c).read("abusech.key")?.trim() ?: ""
    fun setKey(c: Context, k: String) { if (k.isEmpty()) Vault(c).delete("abusech.key") else Vault(c).write("abusech.key", k) }

    // ---------------------------------------------------------------- facts about one app

    class Ctx(val c: Context) {
        val pm: PackageManager = c.packageManager
        val a11y: String = Settings.Secure.getString(c.contentResolver, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES) ?: ""
        val notif: String = Settings.Secure.getString(c.contentResolver, "enabled_notification_listeners") ?: ""
        val ime: String = Settings.Secure.getString(c.contentResolver, Settings.Secure.DEFAULT_INPUT_METHOD) ?: ""
        val admins: Set<String> = try {
            (c.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager).activeAdmins?.map { it.packageName }?.toSet() ?: emptySet()
        } catch (_: Throwable) { emptySet() }
        val sms: String = try { Telephony.Sms.getDefaultSmsPackage(c) ?: "" } catch (_: Throwable) { "" }
        val launchable: Set<String> = try {
            pm.queryIntentActivities(Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER), 0).map { it.activityInfo.packageName }.toSet()
        } catch (_: Throwable) { emptySet() }
        val ops = c.getSystemService(Context.APP_OPS_SERVICE) as android.app.AppOpsManager
        fun op(op: String, uid: Int, pkg: String): Boolean = try {
            @Suppress("DEPRECATION")
            val m = if (Build.VERSION.SDK_INT >= 29) ops.unsafeCheckOpNoThrow(op, uid, pkg) else ops.checkOpNoThrow(op, uid, pkg)
            m == android.app.AppOpsManager.MODE_ALLOWED
        } catch (_: Throwable) { false }
    }

    private fun installer(x: Ctx, pkg: String): Pair<String, String> = try {
        if (Build.VERSION.SDK_INT >= 30) {
            val s = x.pm.getInstallSourceInfo(pkg)
            (s.installingPackageName ?: s.initiatingPackageName ?: "") to (s.initiatingPackageName ?: "")
        } else {
            @Suppress("DEPRECATION")
            (x.pm.getInstallerPackageName(pkg) ?: "") to ""
        }
    } catch (_: Throwable) { "" to "" }

    private fun label(x: Ctx, ai: ApplicationInfo): String = try { x.pm.getApplicationLabel(ai).toString() } catch (_: Throwable) { ai.packageName }

    private fun sha256(f: File): String = try {
        if (f.length() > 400L shl 20) "" else {
            val md = MessageDigest.getInstance("SHA-256")
            f.inputStream().use { i -> val b = ByteArray(1 shl 16); while (true) { val n = i.read(b); if (n < 0) break; md.update(b, 0, n) } }
            md.digest().joinToString("") { "%02x".format(it) }
        }
    } catch (_: Throwable) { "" }

    @Suppress("DEPRECATION")
    private fun signer(pi: PackageInfo): String = try {
        val sigs = if (Build.VERSION.SDK_INT >= 28) pi.signingInfo?.apkContentsSigners else pi.signatures
        val cert = java.security.cert.CertificateFactory.getInstance("X.509")
            .generateCertificate(sigs!![0].toByteArray().inputStream()) as java.security.cert.X509Certificate
        cert.subjectX500Principal.name.let { n -> Regex("CN=([^,]+)").find(n)?.groupValues?.get(1) ?: n }
    } catch (_: Throwable) { "" }

    private fun granted(pi: PackageInfo, perm: String): Boolean {
        val r = pi.requestedPermissions ?: return false
        val f = pi.requestedPermissionsFlags ?: return false
        val i = r.indexOf(perm)
        return i >= 0 && (f[i] and PackageInfo.REQUESTED_PERMISSION_GRANTED) != 0
    }

    private fun requested(pi: PackageInfo, perm: String) = pi.requestedPermissions?.contains(perm) == true

    private fun reason(t: String, w: Int) = JSONObject().put("t", t).put("w", w)

    /** One app -> a finding (or null when there is nothing to say). */
    fun appFinding(x: Ctx, pi: PackageInfo, intel: Map<String, JSONObject>, trusted: Set<String>, hash: Boolean): JSONObject? {
        val ai = pi.applicationInfo ?: return null
        val pkg = pi.packageName
        if (pkg == x.c.packageName) return null
        val system = (ai.flags and ApplicationInfo.FLAG_SYSTEM) != 0
        val updatedSystem = (ai.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0
        if (system && !updatedSystem) return null
        val name = label(x, ai)
        val (inst, init) = installer(x, pkg)
        val store = STORES[inst]
        val side = store == null && !system
        val rs = JSONArray()
        val mitre = JSONArray()
        val actions = JSONArray()
        var sha = ""
        if (side) {
            val via = SIDELOADERS[inst] ?: SIDELOADERS[init] ?: if (inst.isEmpty()) "an unknown source" else inst
            rs.put(reason("Installed from outside an app store (via $via)", 15))
        } else if (store != null) rs.put(reason("Installed from $store", -10))
        val a11y = x.a11y.contains("$pkg/")
        val notif = x.notif.contains("$pkg/")
        val admin = pkg in x.admins
        val hidden = pkg !in x.launchable
        val overlay = x.op("android:system_alert_window", ai.uid, pkg)
        val installs = x.op("android:request_install_packages", ai.uid, pkg)
        val smsRead = granted(pi, "android.permission.READ_SMS") || granted(pi, "android.permission.RECEIVE_SMS")
        val calls = granted(pi, "android.permission.READ_CALL_LOG") || granted(pi, "android.permission.PROCESS_OUTGOING_CALLS")
        val mic = granted(pi, "android.permission.RECORD_AUDIO")
        val bgLoc = granted(pi, "android.permission.ACCESS_BACKGROUND_LOCATION")
        val contacts = granted(pi, "android.permission.READ_CONTACTS")
        if (a11y) {
            rs.put(reason("Can see and control everything on screen (Accessibility)", if (side) 45 else 15)); mitre.put("T1517")
            actions.put(JSONObject().put("id", "settings:a11y").put("label", "Turn off its Accessibility"))
        }
        if (admin) {
            rs.put(reason("Is a device administrator (can lock or wipe the phone and resist uninstall)", if (side) 40 else 20)); mitre.put("T1626.001")
            actions.put(JSONObject().put("id", "settings:admin").put("label", "Remove admin rights"))
        }
        if (notif) {
            rs.put(reason("Reads all your notifications (messages, one-time codes)", if (side) 30 else 10)); mitre.put("T1517")
            actions.put(JSONObject().put("id", "settings:notif").put("label", "Turn off notification access"))
        }
        if (x.sms == pkg && !pkg.startsWith("com.google.") && !pkg.startsWith("com.samsung.") && !pkg.startsWith("com.android.")) rs.put(reason("Is your default SMS app", 20))
        if (smsRead && side) { rs.put(reason("Can read your SMS (including bank and login codes)", 30)); mitre.put("T1636.004") }
        if (overlay && (a11y || smsRead)) { rs.put(reason("Can draw over other apps (fake login screens)", 20)); mitre.put("T1417.002") }
        if (installs && side) rs.put(reason("Can install other apps", 15))
        if (side && (calls || mic || bgLoc) && (a11y || notif || hidden)) { rs.put(reason("Can record, track or read calls while hiding (spyware pattern)", 30)); mitre.put("T1429") }
        if (contacts && smsRead && side) rs.put(reason("Has your contacts and SMS together (used to spread by SMS)", 15))
        if (hidden && !system) { rs.put(reason("Has no icon on the home screen (hides itself)", if (side) 30 else 8)); mitre.put("T1628.001") }
        if (FAKE_NAMES.matches(name.trim()) && side) { rs.put(reason("Pretends to be a system app (\"$name\")", 45)); mitre.put("T1655.001") }
        if (pi.applicationInfo?.targetSdkVersion ?: 99 < 23 && side) rs.put(reason("Built for very old Android to skip permission prompts", 25))
        val sg = signer(pi)
        if (sg.contains("Android Debug", true)) rs.put(reason("Signed with a developer test key", 10))
        if (x.ime.substringBefore('/') == pkg && side) rs.put(reason("Is your keyboard (sees everything you type)", 30))
        val now = System.currentTimeMillis() / 1000
        val first = pi.firstInstallTime / 1000
        if (side && now - first < 3 * 86400) rs.put(reason("Installed recently", 5))
        if (side && hash) sha = sha256(File(ai.sourceDir))
        intel[sha]?.let { if (it.optString("verdict") == "malicious") { rs.put(reason("Known malware: ${it.optString("family").ifEmpty { "a known malware sample" }} (MalwareBazaar)", 100)) } }
        if (pkg in trusted || (sha.isNotEmpty() && sha in trusted)) rs.put(reason("You marked it as trusted", -200))
        var score = 0
        for (i in 0 until rs.length()) score += rs.getJSONObject(i).getInt("w")
        score = score.coerceIn(0, 100)
        val sev = when { score >= 70 -> "high"; score >= 40 -> "med"; score >= 20 -> "low"; else -> "info" }
        if (sev == "info") return null
        val all = JSONArray().put(JSONObject().put("id", "uninstall").put("label", "Uninstall").put("main", true))
        for (i in 0 until actions.length()) all.put(actions.get(i))
        all.put(JSONObject().put("id", "appinfo").put("label", "App settings"))
        all.put(JSONObject().put("id", "trust").put("label", "Trust it"))
        val persist = JSONArray()
        if (a11y) persist.put(JSONObject().put("kind", "a11y").put("where", "Accessibility").put("value", "Turned on for $name"))
        if (admin) persist.put(JSONObject().put("kind", "admin").put("where", "Device administrator").put("value", "Active"))
        if (notif) persist.put(JSONObject().put("kind", "notif").put("where", "Notification access").put("value", "Allowed"))
        val sorted = (0 until rs.length()).map { rs.getJSONObject(it) }.sortedByDescending { it.getInt("w") }
        val f = JSONObject().put("kind", "app").put("sev", sev).put("score", score).put("title", name).put("sub", pkg)
            .put("pkg", pkg).put("reasons", JSONArray(sorted)).put("actions", all).put("mitre", mitre)
            .put("summary", sorted.filter { it.getInt("w") > 0 }.take(2).joinToString(" · ") { it.getString("t") })
            .put("first", first).put("last", pi.lastUpdateTime / 1000).put("signer", sg).put("signed", if (sg.isNotEmpty()) "valid" else "unknown")
            .put("path", ai.sourceDir).put("size", File(ai.sourceDir).length()).put("persist", persist)
        if (sha.isNotEmpty()) f.put("sha256", sha)
        if (side) f.put("origin", JSONObject().put("zone", 3).put("text", "Installed via " + (SIDELOADERS[inst] ?: SIDELOADERS[init] ?: inst.ifEmpty { "an unknown source" })).put("via", inst.ifEmpty { init }))
        intel[sha]?.let { f.put("intel", JSONArray().put(it)) }
        return f
    }

    // ---------------------------------------------------------------- the phone's own protection

    private fun protection(c: Context, x: Ctx, findings: JSONArray): JSONArray {
        val p = JSONArray()
        fun add(id: String, name: String, state: String, detail: String, fix: String) {
            p.put(JSONObject().put("id", id).put("name", name).put("state", state).put("detail", detail).put("fix", fix))
            if (state == "off") {
                val w = when (id) { "lock" -> 45; "patch" -> 35; "root" -> 40; else -> 25 }
                findings.put(JSONObject().put("kind", "setting").put("title", "$name: needs attention").put("sub", detail).put("score", w)
                    .put("sev", if (w >= 40) "med" else "low").put("reasons", JSONArray().put(reason(detail, w)))
                    .put("summary", detail).put("fix", fix)
                    .put("actions", JSONArray().put(JSONObject().put("id", "settings:$fix").put("label", "Open settings").put("main", true))))
            }
        }
        val secure = (c.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager).isDeviceSecure
        add("lock", "Screen lock", if (secure) "on" else "off", if (secure) "PIN, pattern, password or fingerprint is set" else "Anyone who picks up the phone can open it", "lock")
        val patch = Build.VERSION.SECURITY_PATCH
        val age = try { (System.currentTimeMillis() - SimpleDateFormat("yyyy-MM-dd", Locale.US).parse(patch)!!.time) / 86400000L } catch (_: Throwable) { -1L }
        when {
            age < 0 -> add("patch", "Security updates", "unknown", "Security patch: $patch", "update")
            age > 365 -> add("patch", "Security updates", "off", "Last security update is ${age / 30} months old ($patch)", "update")
            age > 120 -> add("patch", "Security updates", "warn", "Last security update is ${age / 30} months old ($patch)", "update")
            else -> add("patch", "Security updates", "on", "Security patch $patch", "update")
        }
        if (Build.VERSION.SDK_INT < 30) add("android", "Android version", "off", "Android ${Build.VERSION.RELEASE} no longer gets security fixes", "update")
        val adb = Settings.Global.getInt(c.contentResolver, Settings.Global.ADB_ENABLED, 0) == 1
        add("adb", "USB debugging", if (adb) "off" else "on", if (adb) "On: a connected computer can install apps and read data" else "Off", "dev")
        val dev = Settings.Global.getInt(c.contentResolver, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0) == 1
        if (dev && !adb) add("dev", "Developer options", "warn", "Developer options are on", "dev")
        val rooted = listOf("/system/bin/su", "/system/xbin/su", "/sbin/su", "/system/app/Superuser.apk").any { File(it).exists() } ||
            (Build.TAGS ?: "").contains("test-keys") || try { x.pm.getPackageInfo("com.topjohnwu.magisk", 0); true } catch (_: Throwable) { false }
        add("root", "Not rooted", if (rooted) "off" else "on", if (rooted) "This phone is rooted: apps can get full control" else "Android's security model is intact", "dev")
        val enc = try { (c.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager).storageEncryptionStatus } catch (_: Throwable) { 0 }
        val encOn = enc == DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE || enc == DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE_PER_USER
        add("encrypt", "Storage encryption", if (encOn) "on" else "warn", if (encOn) "Your data is encrypted" else "Could not confirm encryption", "lock")
        add("playprotect", "Google Play Protect", "unknown", "Make sure it is on: it scans apps from every source", "playprotect")
        return p
    }

    // ---------------------------------------------------------------- bloatware

    private val BLOAT = listOf(
        Triple("com.facebook.system", "remove", "Facebook App Installer: pre-installed, installs and updates Facebook apps silently"),
        Triple("com.facebook.appmanager", "remove", "Facebook App Manager: pre-installed background updater"),
        Triple("com.facebook.services", "remove", "Facebook Services: pre-installed background service"),
        Triple("com.facebook.katana", "optional", "Pre-installed Facebook"),
        Triple("com.netflix.partner.activation", "remove", "Netflix partner activation: only for the pre-installed offer"),
        Triple("com.netflix.mediaclient", "optional", "Pre-installed Netflix"),
        Triple("com.linkedin.android", "remove", "Pre-installed LinkedIn"),
        Triple("com.booking", "remove", "Pre-installed Booking.com"),
        Triple("com.amazon.mShop.android.shopping", "optional", "Pre-installed Amazon Shopping"),
        Triple("com.amazon.appmanager", "remove", "Amazon app manager"),
        Triple("com.microsoft.skydrive", "optional", "Pre-installed OneDrive"),
        Triple("com.spotify.music", "optional", "Pre-installed Spotify"),
        Triple("com.miui.analytics", "remove", "Xiaomi analytics: collects usage data"),
        Triple("com.miui.msa.global", "remove", "Xiaomi MSA: shows ads in system apps"),
        Triple("com.miui.daemon", "remove", "Xiaomi diagnostics daemon"),
        Triple("com.xiaomi.mipicks", "optional", "Xiaomi GetApps store"),
        Triple("com.mi.globalbrowser", "optional", "Mi Browser: shows ads"),
        Triple("com.miui.videoplayer", "optional", "Mi Video"),
        Triple("com.samsung.android.app.spage", "remove", "Samsung Free / Bixby Home"),
        Triple("com.samsung.android.bixby.agent", "optional", "Bixby voice assistant"),
        Triple("com.samsung.android.arzone", "remove", "AR Zone"),
        Triple("com.samsung.android.ardrawing", "remove", "AR Doodle"),
        Triple("com.samsung.android.game.gamehome", "optional", "Game Launcher"),
        Triple("com.samsung.android.app.tips", "remove", "Samsung Tips"),
        Triple("com.heytap.market", "optional", "OPPO/realme App Market: shows suggestions"),
        Triple("com.heytap.browser", "optional", "OPPO/realme Browser: shows ads"),
        Triple("com.coloros.gamespace", "optional", "Game Space"),
        Triple("com.transsion.aivoiceassistant", "optional", "Tecno/Infinix voice assistant"),
        Triple("com.transsion.magazineservice", "remove", "Lock-screen magazine with ads"),
        Triple("com.hihonor.search", "optional", "HONOR search with suggestions"),
        Triple("com.google.android.videos", "remove", "Google TV / Play Movies"),
        Triple("com.google.android.apps.podcasts", "remove", "Google Podcasts (retired)"),
        Triple("com.google.android.apps.youtube.music", "optional", "YouTube Music"),
        Triple("com.google.android.apps.tachyon", "optional", "Google Meet"),
        Triple("com.google.android.apps.subscriptions.red", "optional", "Google One"),
        Triple("com.google.android.apps.magazines", "remove", "Google News"),
        Triple("com.google.android.apps.books", "optional", "Google Play Books")
    )

    private fun bloat(x: Ctx): JSONArray {
        val out = JSONArray()
        var n = 0
        for ((pkg, rating, why) in BLOAT) {
            val ai = try { x.pm.getApplicationInfo(pkg, 0) } catch (_: Throwable) { continue }
            out.put(JSONObject().put("id", "b${++n}").put("name", label(x, ai)).put("publisher", pkg).put("kind", "system").put("rating", rating)
                .put("why", why).put("action", "appinfo").put("on", ai.enabled).put("pkg", pkg))
        }
        return out
    }

    // ---------------------------------------------------------------- MalwareBazaar

    fun lookup(key: String, hashes: List<String>): Pair<Map<String, JSONObject>, String> {
        val out = HashMap<String, JSONObject>()
        if (key.isEmpty() || hashes.isEmpty()) return out to "off"
        var err = ""
        for (h in hashes.distinct().take(60)) {
            try {
                val c = URL("https://mb-api.abuse.ch/api/v1/").openConnection() as HttpURLConnection
                c.requestMethod = "POST"; c.doOutput = true; c.connectTimeout = 8000; c.readTimeout = 10000
                c.setRequestProperty("Auth-Key", key)
                c.setRequestProperty("Content-Type", "application/x-www-form-urlencoded")
                c.outputStream.use { it.write("query=get_info&hash=${URLEncoder.encode(h, "UTF-8")}".toByteArray()) }
                val j = JSONObject(c.inputStream.bufferedReader().readText())
                when (j.optString("query_status")) {
                    "ok" -> {
                        val d = j.optJSONArray("data")?.optJSONObject(0)
                        if (d != null) out[h] = JSONObject().put("source", "MalwareBazaar").put("verdict", "malicious").put("family", d.optString("signature"))
                            .put("first", d.optString("first_seen")).put("link", "https://bazaar.abuse.ch/sample/$h/").put("tags", d.optJSONArray("tags") ?: JSONArray())
                    }
                    "unknown_auth_key", "user_blacklisted" -> { err = "the abuse.ch key was refused"; break }
                }
            } catch (e: Throwable) { if (err.isEmpty()) err = e.message ?: "network error" }
        }
        return out to if (err.isEmpty()) "on" else "error: $err"
    }

    // ---------------------------------------------------------------- full scan

    @Suppress("DEPRECATION")
    private fun packages(pm: PackageManager): List<PackageInfo> {
        val flags = PackageManager.GET_PERMISSIONS or if (Build.VERSION.SDK_INT >= 28) PackageManager.GET_SIGNING_CERTIFICATES else PackageManager.GET_SIGNATURES
        return pm.getInstalledPackages(flags)
    }

    fun scan(c: Context, progress: (Int, String) -> Unit): JSONObject {
        val t0 = System.currentTimeMillis()
        progress(3, "Reading installed apps")
        val x = Ctx(c)
        val all = packages(x.pm)
        val trusted = trusted(c)
        val key = apiKey(c)
        progress(15, "Checking ${all.size} apps")
        // first pass without hashes, to know which apps deserve a fingerprint
        val first = ArrayList<Pair<PackageInfo, JSONObject?>>()
        all.forEachIndexed { i, pi ->
            if (i % 20 == 0) progress(15 + 45 * i / all.size.coerceAtLeast(1), "Checking apps (${i + 1}/${all.size})")
            first.add(pi to appFinding(x, pi, emptyMap(), trusted, false))
        }
        var intelState = "off"
        var intel: Map<String, JSONObject> = emptyMap()
        val toHash = all.filter { pi ->
            val ai = pi.applicationInfo ?: return@filter false
            (ai.flags and ApplicationInfo.FLAG_SYSTEM) == 0 && STORES[installer(x, pi.packageName).first] == null
        }.take(60)
        if (key.isNotEmpty() && toHash.isNotEmpty()) {
            progress(62, "Fingerprinting ${toHash.size} apps from outside app stores")
            val hs = toHash.mapNotNull { pi -> pi.applicationInfo?.sourceDir?.let { sha256(File(it)) } }.filter { it.isNotEmpty() }
            progress(72, "Checking against known malware")
            val (m, st) = lookup(key, hs)
            intel = m; intelState = st
        }
        progress(82, "Scoring")
        val findings = JSONArray()
        val hashed = toHash.map { it.packageName }.toSet()
        for ((pi, f0) in first) {
            val f = if (pi.packageName in hashed) appFinding(x, pi, intel, trusted, true) else f0
            if (f != null) findings.put(f)
        }
        progress(90, "Checking phone protection")
        val prot = protection(c, x, findings)
        val list = (0 until findings.length()).map { findings.getJSONObject(it) }.sortedByDescending { it.getInt("score") }
        val counts = JSONObject().put("high", 0).put("med", 0).put("low", 0).put("info", 0)
        list.forEachIndexed { i, f -> f.put("id", "a${i + 1}"); counts.put(f.getString("sev"), counts.getInt(f.getString("sev")) + 1) }
        var score = 100 - counts.getInt("high") * 25 - counts.getInt("med") * 8 - counts.getInt("low") * 2
        for (i in 0 until prot.length()) if (prot.getJSONObject(i).getString("state") == "off") score -= 4
        score = score.coerceIn(0, 100)
        val verdict = when { counts.getInt("high") > 0 -> "danger"; counts.getInt("med") > 0 || score < 80 -> "attention"; else -> "clean" }
        val notes = JSONArray()
        if (Build.VERSION.SDK_INT >= 30 && all.size < 25) notes.put("CoreKit can only see some apps. Allow it to see all apps for a complete scan.")
        progress(100, "Done")
        val res = JSONObject().put("platform", "android").put("t", System.currentTimeMillis() / 1000)
            .put("host", "${Build.MANUFACTURER.replaceFirstChar { it.uppercase() }} ${Build.MODEL}").put("os", "Android ${Build.VERSION.RELEASE}")
            .put("admin", true).put("score", score).put("verdict", verdict).put("counts", counts)
            .put("scanned", JSONObject().put("apps", all.size).put("files", toHash.size).put("lookups", intel.size).put("processes", 0).put("autoruns", 0).put("connections", 0))
            .put("protection", prot).put("findings", JSONArray(list)).put("bloat", bloat(x)).put("notes", notes)
            .put("intel", intelState).put("ms", System.currentTimeMillis() - t0)
        last = res
        val p = prefs(c)
        p.edit().putInt("checked", p.getInt("checked", 0) + all.size).apply()
        return res
    }

    // ---------------------------------------------------------------- history

    private fun histFile(c: Context) = File(c.filesDir, "security-history.json")

    fun history(c: Context): JSONArray = try { JSONArray(histFile(c).readText()) } catch (_: Throwable) { JSONArray() }

    fun addRecord(c: Context, r: JSONObject) = synchronized(this) {
        val h = history(c)
        r.put("id", "r" + java.util.UUID.randomUUID().toString().take(10)).put("t", r.optLong("t", System.currentTimeMillis() / 1000))
        h.put(r)
        val trimmed = if (h.length() > 300) JSONArray((h.length() - 300 until h.length()).map { h.get(it) }) else h
        histFile(c).writeText(trimmed.toString())
        r
    }

    fun recordOf(f: JSONObject, action: String, done: String) = JSONObject().put("source", "scan").put("title", f.optString("title")).put("sub", f.optString("sub"))
        .put("path", f.optString("path")).put("sev", f.optString("sev")).put("score", f.optInt("score")).put("reasons", f.optJSONArray("reasons"))
        .put("origin", f.optJSONObject("origin")).put("mitre", f.optJSONArray("mitre")).put("action", action).put("done", JSONArray().put(done)).put("canUndo", false)

    // ---------------------------------------------------------------- Live Shield (new and updated apps)

    const val JOB_ID = 4711
    private const val CH = "security"

    fun shieldOn(c: Context) = prefs(c).getBoolean("shield", false)

    fun setShield(c: Context, on: Boolean) {
        val js = c.getSystemService(Context.JOB_SCHEDULER_SERVICE) as JobScheduler
        prefs(c).edit().putBoolean("shield", on).apply()
        if (!on) { js.cancel(JOB_ID); return }
        if (Build.VERSION.SDK_INT >= 26) prefs(c).edit().putInt("seq", c.packageManager.getChangedPackages(0)?.sequenceNumber ?: 0).putLong("since", System.currentTimeMillis() / 1000).apply()
        js.schedule(JobInfo.Builder(JOB_ID, ComponentName(c, SecurityJob::class.java))
            .setPeriodic(15 * 60 * 1000L).setPersisted(true).build())
    }

    fun shieldStatus(c: Context): JSONObject {
        val p = prefs(c)
        return JSONObject().put("platform", "android").put("on", shieldOn(c)).put("installed", shieldOn(c)).put("running", shieldOn(c))
            .put("checked", p.getInt("shieldChecked", 0)).put("blocked", p.getInt("alerts", 0)).put("since", p.getLong("since", 0))
    }

    /** Checks apps installed or updated since the last check; alerts about dangerous ones. */
    fun checkChanged(c: Context) {
        if (Build.VERSION.SDK_INT < 26) return
        val p = prefs(c)
        val seq = p.getInt("seq", 0)
        val ch = c.packageManager.getChangedPackages(seq) ?: return
        p.edit().putInt("seq", ch.sequenceNumber).apply()
        val x = Ctx(c)
        val trusted = trusted(c)
        val key = apiKey(c)
        for (pkg in ch.packageNames) {
            val pi = try {
                @Suppress("DEPRECATION")
                x.pm.getPackageInfo(pkg, PackageManager.GET_PERMISSIONS or if (Build.VERSION.SDK_INT >= 28) PackageManager.GET_SIGNING_CERTIFICATES else PackageManager.GET_SIGNATURES)
            } catch (_: Throwable) { continue }
            p.edit().putInt("shieldChecked", p.getInt("shieldChecked", 0) + 1).apply()
            var f = appFinding(x, pi, emptyMap(), trusted, false) ?: continue
            if (key.isNotEmpty() && f.has("origin")) {
                val sha = sha256(File(pi.applicationInfo!!.sourceDir))
                if (sha.isNotEmpty()) f = appFinding(x, pi, lookup(key, listOf(sha)).first, trusted, true) ?: continue
            }
            if (f.optInt("score") < 55) continue
            p.edit().putInt("alerts", p.getInt("alerts", 0) + 1).apply()
            addRecord(c, JSONObject().put("source", "shield").put("title", f.optString("title")).put("sub", pkg).put("path", f.optString("path"))
                .put("sev", f.optString("sev")).put("score", f.optInt("score")).put("reasons", f.optJSONArray("reasons")).put("origin", f.optJSONObject("origin"))
                .put("mitre", f.optJSONArray("mitre")).put("action", "alert").put("done", JSONArray().put("You were alerted")).put("canUndo", false))
            notify(c, f)
        }
    }

    private fun notify(c: Context, f: JSONObject) {
        val nm = c.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        if (Build.VERSION.SDK_INT >= 26 && nm.getNotificationChannel(CH) == null)
            nm.createNotificationChannel(NotificationChannel(CH, "Security alerts", NotificationManager.IMPORTANCE_HIGH).apply { description = "Dangerous apps found by Live Shield" })
        val open = PendingIntent.getActivity(c, 7, Intent(c, MainActivity::class.java).setAction(MainActivity.ACTION_OPEN_SECURITY).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK), PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        val del = PendingIntent.getActivity(c, 8, Intent(Intent.ACTION_DELETE, android.net.Uri.parse("package:" + f.optString("pkg"))).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK), PendingIntent.FLAG_IMMUTABLE)
        val why = f.optString("summary")
        @Suppress("DEPRECATION")
        val b = if (Build.VERSION.SDK_INT >= 26) Notification.Builder(c, CH) else Notification.Builder(c)
        b.setSmallIcon(android.R.drawable.ic_dialog_alert).setContentTitle("Dangerous app: " + f.optString("title"))
            .setContentText(why).setStyle(Notification.BigTextStyle().bigText(why)).setContentIntent(open).setAutoCancel(true)
            .addAction(Notification.Action.Builder(null, "Uninstall", del).build())
            .addAction(Notification.Action.Builder(null, "Details", open).build())
        try { nm.notify(f.optString("pkg").hashCode(), b.build()) } catch (_: Throwable) {}
    }
}

/** Runs Live Shield's check about every 15 minutes (Android does not let apps watch installs live). */
class SecurityJob : JobService() {
    override fun onStartJob(params: JobParameters): Boolean {
        Thread {
            try { SecurityScanner.checkChanged(this) } catch (_: Throwable) {}
            jobFinished(params, false)
        }.start()
        return true
    }

    override fun onStopJob(params: JobParameters) = true
}
