package com.corekit.app

import android.app.AppOpsManager
import android.app.usage.StorageStatsManager
import android.app.usage.UsageStatsManager
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import android.os.Environment
import android.os.Process
import android.os.StatFs
import android.os.storage.StorageManager
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/**
 * Storage & Performance for Android: where space is going, every app (with its size, where it came
 * from and whether it's bloat), the junk that can be cleared, and plain recommendations. It only
 * reads; removing apps or files is done by the user through the system's own confirmations.
 *
 * The JSON it returns matches the Windows result exactly so the one storage.html page fits both.
 */
object StorageScanner {

    fun scan(ctx: Context, progress: (Int, String) -> Unit): JSONObject {
        progress(5, "Reading storage")
        val pm = ctx.packageManager
        val res = JSONObject()
        res.put("platform", "android")
        val usageOk = hasUsageAccess(ctx)
        val ssm = if (Build.VERSION.SDK_INT >= 26) ctx.getSystemService(Context.STORAGE_STATS_SERVICE) as? StorageStatsManager else null
        val exact = ssm != null && usageOk
        val needs = JSONArray()
        if (!exact) needs.put("usage")
        res.put("needs", needs)

        // ---- totals (the size on the box, as Settings shows it) ----
        val st = StatFs(Environment.getDataDirectory().path)
        var total = st.totalBytes
        var free = st.availableBytes
        if (ssm != null) try {
            total = ssm.getTotalBytes(StorageManager.UUID_DEFAULT)
            free = ssm.getFreeBytes(StorageManager.UUID_DEFAULT)
        } catch (_: Throwable) {}
        val used = (total - free).coerceAtLeast(0)

        // ---- apps ----
        progress(20, "Listing apps")
        val usage = lastUsedMap(ctx)
        val apps = JSONArray()
        var cacheAll = 0L
        var appsBytes = 0L
        for (ai in pm.getInstalledApplications(0)) {
            if (ai.packageName == ctx.packageName) continue
            val system = ai.flags and ApplicationInfo.FLAG_SYSTEM != 0
            val updatedSystem = ai.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP != 0
            var size = 0L
            var approx = false
            if (exact && ssm != null) {
                try {
                    val q = ssm.queryStatsForPackage(StorageManager.UUID_DEFAULT, ai.packageName, Process.myUserHandle())
                    size = q.appBytes + q.dataBytes
                    cacheAll += q.cacheBytes
                } catch (_: Throwable) {}
            }
            if (size == 0L) { size = apkBytes(ai); approx = true } // only the installed package size is known
            else appsBytes += size
            val pi = try { pm.getPackageInfo(ai.packageName, 0) } catch (_: Throwable) { null }
            val name = label(pm, ai)
            val (bloat, why) = bloatOf(ai.packageName, name, system)
            val o = JSONObject()
                .put("id", ai.packageName)
                .put("name", name)
                .put("pub", ai.packageName)
                .put("ver", pi?.versionName ?: "")
                .put("size", size)
                .put("installed", (pi?.firstInstallTime ?: 0L) / 1000)
                .put("lastUsed", usage[ai.packageName] ?: 0L)
                .put("loc", ai.packageName)
                .put("drive", "Internal storage")
                .put("source", sourceOf(pm, ai.packageName, system, updatedSystem))
                .put("kind", "apk")
                .put("system", system && !updatedSystem)
                .put("bloat", bloat)
                .put("bloatWhy", why)
                .put("removable", !system || updatedSystem)
            if (approx) o.put("approx", true)
            apps.put(o)
        }
        res.put("apps", apps)
        res.put("appCount", apps.length())

        // ---- where the space went ----
        progress(50, "Measuring photos, videos and audio")
        var img = 0L; var vid = 0L; var aud = 0L
        if (exact && ssm != null) try {
            val e = ssm.queryExternalStatsForUser(StorageManager.UUID_DEFAULT, Process.myUserHandle())
            img = e.imageBytes; vid = e.videoBytes; aud = e.audioBytes
        } catch (_: Throwable) {}
        val parts = JSONArray()
        fun part(n: String, b: Long, c: String) { if (b > 0) parts.put(JSONObject().put("name", n).put("bytes", b).put("color", c)) }
        if (exact) {
            part("Apps & app data", appsBytes, "#38bdf8")
            part("Photos", img, "#34d399")
            part("Videos", vid, "#a78bfa")
            part("Audio", aud, "#fbbf24")
            part("Other files & system", (used - appsBytes - img - vid - aud).coerceAtLeast(0), "#64748b")
        } else part("Used", used, "#38bdf8")
        val drives = JSONArray()
        drives.put(JSONObject().put("name", "Internal storage").put("label", "").put("total", total).put("free", free)
            .put("used", used).put("kind", "system").put("parts", parts))
        // SD card / USB storage, if any
        try {
            for (d in ctx.getExternalFilesDirs(null).drop(1)) {
                if (d == null) continue
                val s2 = StatFs(d.path)
                val rem = try { Environment.isExternalStorageRemovable(d) } catch (_: Throwable) { true }
                val u2 = (s2.totalBytes - s2.availableBytes).coerceAtLeast(0)
                drives.put(JSONObject().put("name", if (rem) "SD card" else "Extra storage").put("label", "")
                    .put("total", s2.totalBytes).put("free", s2.availableBytes).put("used", u2)
                    .put("kind", if (rem) "removable" else "fixed")
                    .put("parts", JSONArray().put(JSONObject().put("name", "Used").put("bytes", u2).put("color", "#38bdf8"))))
            }
        } catch (_: Throwable) {}
        res.put("drives", drives)

        // ---- cleanables ----
        progress(75, "Checking caches and downloads")
        val clean = JSONArray()
        val ownCache = dirSize(ctx.cacheDir) + dirSize(ctx.codeCacheDir) + (ctx.externalCacheDir?.let { dirSize(it) } ?: 0)
        if (ownCache > 0) clean.put(JSONObject().put("id", "owncache").put("name", "CoreKit cache").put("desc", "CoreKit's own temporary files — safe to clear.").put("bytes", ownCache).put("safe", true).put("group", "Apps"))
        if (cacheAll > 0) clean.put(JSONObject().put("id", "allcache").put("name", "Cache of all your apps").put("desc", "Temporary files across your apps. Android clears these from its own Free-up-space screen.").put("bytes", cacheAll).put("safe", true).put("group", "Apps"))
        val dl = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
        val (dlBytes, dlCount) = downloadsInfo(dl)
        if (dlBytes > 0) clean.put(JSONObject().put("id", "downloads").put("name", "Downloads folder").put("desc", "$dlCount item(s) in your Downloads folder. Open it and choose what to delete.").put("bytes", dlBytes).put("count", dlCount).put("safe", false).put("path", dl.absolutePath).put("group", "Your files"))
        res.put("clean", clean)

        // Android does not let an app list other files, so the biggest things we can show are apps
        val bigList = ArrayList<JSONObject>()
        for (i in 0 until apps.length()) {
            val a = apps.getJSONObject(i)
            if (a.optLong("size") >= 50L * 1024 * 1024)
                bigList.add(JSONObject().put("path", a.optString("id")).put("name", a.optString("name")).put("bytes", a.optLong("size")).put("kind", "app").put("drive", "Internal storage"))
        }
        bigList.sortByDescending { it.optLong("bytes") }
        val big = JSONArray()
        bigList.take(30).forEach { big.put(it) }
        res.put("big", big)

        progress(92, "Working out recommendations")
        res.put("total", total).put("free", free).put("used", used)
        val recList = ArrayList<JSONObject>()
        var reclaim = 0L
        for (i in 0 until clean.length()) {
            val c = clean.getJSONObject(i)
            if (c.optBoolean("safe") && c.optString("id") != "allcache") reclaim += c.optLong("bytes")
            if (c.optString("id") == "owncache") recList.add(JSONObject().put("id", "c-owncache").put("title", "Clear CoreKit cache").put("why", c.optString("desc")).put("bytes", c.optLong("bytes")).put("kind", "clean").put("target", "owncache").put("safe", true))
        }
        val now = System.currentTimeMillis() / 1000
        for (i in 0 until apps.length()) {
            val a = apps.getJSONObject(i)
            if (a.optBoolean("bloat") && a.optBoolean("removable")) {
                recList.add(JSONObject().put("id", "b-" + a.optString("id")).put("title", "Remove " + a.optString("name")).put("why", a.optString("bloatWhy")).put("bytes", a.optLong("size")).put("kind", "app-unused").put("target", a.optString("id")).put("safe", false))
            } else if (a.optBoolean("removable") && !a.optBoolean("system") && a.optLong("lastUsed") > 0 && a.optLong("size") > 50L * 1024 * 1024) {
                val days = (now - a.optLong("lastUsed")) / 86400
                if (days >= 60) recList.add(JSONObject().put("id", "a-" + a.optString("id")).put("title", "Uninstall " + a.optString("name")).put("why", "Not opened in $days days and using " + human(a.optLong("size")) + ".").put("bytes", a.optLong("size")).put("kind", "app-unused").put("target", a.optString("id")).put("safe", false))
            }
        }
        recList.sortWith(compareBy<JSONObject>({ if (it.optString("kind") == "clean") 0 else 1 }, { -it.optLong("bytes") }))
        val recs = JSONArray()
        recList.take(120).forEach { recs.put(it) }
        res.put("recs", recs)
        res.put("reclaim", reclaim)
        return res
    }

    // ---------------------------------------------------------------- actions

    /** clean: clears what Android actually allows an app to clear (its own cache); the rest points
     *  the user at Android's own tools. Returns {freed, freedText, log}. */
    fun clean(ctx: Context, ids: List<String>, pick: Map<String, List<String>>): JSONObject {
        var freed = 0L
        val log = JSONArray()
        for (id in ids) when (id) {
            "owncache" -> {
                val before = dirSize(ctx.cacheDir) + dirSize(ctx.codeCacheDir) + (ctx.externalCacheDir?.let { dirSize(it) } ?: 0)
                runCatching { ctx.cacheDir.deleteRecursively(); ctx.codeCacheDir.deleteRecursively(); ctx.externalCacheDir?.deleteRecursively() }
                freed += before
                log.put("Cleared CoreKit cache (" + human(before) + ")")
            }
            "allcache" -> log.put("Open Android Settings › Storage › Free up space to clear other apps' caches (Android doesn't let an app clear them directly).")
            "downloads" -> {
                var n = 0; var b = 0L
                val root = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS).canonicalFile
                for (p in pick["downloads"].orEmpty()) {
                    val f = runCatching { File(p).canonicalFile }.getOrNull() ?: continue
                    if (f == root || !f.path.startsWith(root.path + File.separator)) continue // only inside Downloads
                    val len = dirSize(f)
                    if (runCatching { if (f.isDirectory) f.deleteRecursively() else f.delete() }.getOrDefault(false)) { n++; b += len }
                }
                freed += b
                log.put("Deleted $n item(s) from Downloads (" + human(b) + ")")
            }
        }
        return JSONObject().put("freed", freed).put("freedText", human(freed)).put("log", log)
    }

    fun drill(ctx: Context, path: String): JSONObject {
        val dir = File(path)
        if (!dir.isDirectory) return JSONObject().put("error", "That folder isn't available.")
        val items = JSONArray()
        (dir.listFiles() ?: emptyArray()).map { it to (if (it.isDirectory) dirSize(it) else it.length()) }
            .sortedByDescending { it.second }.take(300).forEach { (f, sz) ->
                items.put(JSONObject().put("name", f.name).put("path", f.absolutePath).put("bytes", sz).put("mod", f.lastModified() / 1000).put("kind", if (f.isDirectory) "folder" else "file"))
            }
        return JSONObject().put("items", items).put("path", path)
    }

    // ---------------------------------------------------------------- helpers

    private fun label(pm: PackageManager, ai: ApplicationInfo) = try { pm.getApplicationLabel(ai).toString() } catch (_: Throwable) { ai.packageName }
    private fun verOf(pm: PackageManager, pkg: String) = try { pm.getPackageInfo(pkg, 0).versionName ?: "" } catch (_: Throwable) { "" }

    private fun sourceOf(pm: PackageManager, pkg: String, system: Boolean, updatedSystem: Boolean): String {
        if (system && !updatedSystem) return "system"
        val inst = try {
            if (Build.VERSION.SDK_INT >= 30) pm.getInstallSourceInfo(pkg).installingPackageName
            else @Suppress("DEPRECATION") pm.getInstallerPackageName(pkg)
        } catch (_: Throwable) { null }
        return when (inst) {
            "com.android.vending" -> "store"
            null, "" -> if (updatedSystem) "preinstalled" else "sideloaded"
            else -> "sideloaded"
        }
    }

    private fun lastUsedMap(ctx: Context): Map<String, Long> {
        if (!hasUsageAccess(ctx)) return emptyMap()
        return try {
            val usm = ctx.getSystemService(Context.USAGE_STATS_SERVICE) as UsageStatsManager
            val end = System.currentTimeMillis()
            val stats = usm.queryUsageStats(UsageStatsManager.INTERVAL_YEARLY, end - 365L * 86400_000, end)
            val m = HashMap<String, Long>()
            for (u in stats) if (u.lastTimeUsed > 0) m[u.packageName] = maxOf(m[u.packageName] ?: 0, u.lastTimeUsed / 1000)
            m
        } catch (_: Throwable) { emptyMap() }
    }

    private fun hasUsageAccess(ctx: Context): Boolean = try {
        val ops = ctx.getSystemService(Context.APP_OPS_SERVICE) as AppOpsManager
        val mode = if (Build.VERSION.SDK_INT >= 29)
            ops.unsafeCheckOpNoThrow(AppOpsManager.OPSTR_GET_USAGE_STATS, Process.myUid(), ctx.packageName)
        else @Suppress("DEPRECATION") ops.checkOpNoThrow(AppOpsManager.OPSTR_GET_USAGE_STATS, Process.myUid(), ctx.packageName)
        mode == AppOpsManager.MODE_ALLOWED
    } catch (_: Throwable) { false }

    private fun dirSize(f: File?): Long {
        if (f == null || !f.exists()) return 0
        if (f.isFile) return f.length()
        var t = 0L
        (f.listFiles() ?: return 0).forEach { t += if (it.isDirectory) dirSize(it) else it.length() }
        return t
    }

    private fun human(b: Long): String = when {
        b >= 1L shl 30 -> String.format("%.1f GB", b / 1073741824.0)
        b >= 1L shl 20 -> String.format("%.0f MB", b / 1048576.0)
        b >= 1L shl 10 -> "${b / 1024} KB"
        else -> "$b B"
    }

    // A small, conservative list of common junk/preinstalled apps worth flagging.
    private val BLOAT = mapOf(
        "com.facebook.appmanager" to "Facebook background installer, often pre-installed.",
        "com.facebook.services" to "Facebook background service, often pre-installed.",
        "com.facebook.system" to "Facebook system stub, often pre-installed.",
        "com.facebook.katana" to "Pre-installed Facebook; remove if you don't use it.",
        "com.amazon.appmanager" to "Amazon pre-installed assistant.",
        "com.netflix.partner.activation" to "Netflix pre-install stub.",
        "com.microsoft.skydrive" to "Pre-installed OneDrive; keep only if you use it.",
        "com.linkedin.android" to "Pre-installed LinkedIn; remove if unused.",
        "com.booking" to "Pre-installed Booking.com promo.",
        "com.agoda.mobile.consumer" to "Pre-installed Agoda promo."
    )

    private fun bloatOf(pkg: String, name: String, system: Boolean): Pair<Boolean, String> {
        BLOAT[pkg]?.let { return true to it }
        val n = name.lowercase()
        if (system && (n.contains("facebook") || n.contains("booking.com") || n.contains("agoda") || n.contains("linkedin")))
            return true to "A pre-installed promotional app."
        return false to ""
    }
}
