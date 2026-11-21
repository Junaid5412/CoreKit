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
import android.provider.MediaStore
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

        // ---- drive (internal storage) with a category breakdown ----
        val dataDir = Environment.getDataDirectory()
        val st = StatFs(dataDir.path)
        val total = st.totalBytes
        val free = st.availableBytes
        val used = total - free

        progress(25, "Measuring photos, videos and files")
        val media = mediaSizes(ctx)
        val appsBytes = appBytesTotal(ctx)
        val known = media.values.sum() + appsBytes
        val other = (used - known).coerceAtLeast(0)
        val parts = JSONArray()
        fun part(n: String, b: Long, c: String) { if (b > 0) parts.put(JSONObject().put("name", n).put("bytes", b).put("color", c)) }
        part("Apps", appsBytes, "#38bdf8")
        part("Photos", media["images"] ?: 0, "#34d399")
        part("Videos", media["video"] ?: 0, "#a78bfa")
        part("Audio", media["audio"] ?: 0, "#fbbf24")
        part("Downloads", media["downloads"] ?: 0, "#f87171")
        part("Other", other, "#64748b")
        val drive = JSONObject().put("name", "Internal storage").put("label", "")
            .put("total", total).put("free", free).put("used", used).put("kind", "system").put("parts", parts)
        res.put("drives", JSONArray().put(drive))

        // ---- apps ----
        progress(50, "Listing apps")
        val usage = lastUsedMap(ctx)
        val ssm = if (Build.VERSION.SDK_INT >= 26) ctx.getSystemService(Context.STORAGE_STATS_SERVICE) as? StorageStatsManager else null
        val uuid = if (Build.VERSION.SDK_INT >= 26) StorageManager.UUID_DEFAULT else null
        val apps = JSONArray()
        var cacheAll = 0L
        for (ai in pm.getInstalledApplications(0)) {
            if (ai.packageName == ctx.packageName) continue
            val system = ai.flags and ApplicationInfo.FLAG_SYSTEM != 0
            val updatedSystem = ai.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP != 0
            var size = 0L
            var cache = 0L
            if (ssm != null && uuid != null) {
                try {
                    val s = ssm.queryStatsForPackage(uuid, ai.packageName, Process.myUserHandle())
                    size = s.appBytes + s.dataBytes
                    cache = s.cacheBytes
                    cacheAll += cache
                } catch (_: Throwable) {}
            }
            if (size == 0L) size = File(ai.sourceDir ?: "").length() // floor when usage access isn't granted
            val src = sourceOf(pm, ai.packageName, system, updatedSystem)
            val removable = !system || updatedSystem
            val (bloat, why) = bloatOf(ai.packageName, label(pm, ai), system)
            apps.put(JSONObject()
                .put("id", ai.packageName)
                .put("name", label(pm, ai))
                .put("pub", "")
                .put("ver", verOf(pm, ai.packageName))
                .put("size", size)
                .put("installed", 0)
                .put("lastUsed", usage[ai.packageName] ?: 0L)
                .put("loc", ai.packageName)
                .put("drive", "Internal storage")
                .put("source", src)
                .put("kind", "apk")
                .put("system", system && !updatedSystem)
                .put("bloat", bloat)
                .put("bloatWhy", why)
                .put("removable", removable))
        }
        res.put("apps", apps)
        res.put("appCount", apps.length())

        // ---- cleanables ----
        progress(75, "Checking caches and downloads")
        val clean = JSONArray()
        val ownCache = dirSize(ctx.cacheDir) + dirSize(ctx.codeCacheDir) + (ctx.externalCacheDir?.let { dirSize(it) } ?: 0)
        if (ownCache > 0) clean.put(JSONObject().put("id", "owncache").put("name", "CoreKit cache").put("desc", "CoreKit's own temporary files — safe to clear.").put("bytes", ownCache).put("safe", true))
        if (cacheAll > 0) clean.put(JSONObject().put("id", "allcache").put("name", "App caches").put("desc", "Temporary files across your apps. Android clears these from its own Free-up-space screen.").put("bytes", cacheAll).put("safe", true))
        val dl = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
        val (dlBytes, dlCount) = oldDownloads(dl)
        if (dlBytes > 0) clean.put(JSONObject().put("id", "downloads").put("name", "Old downloads").put("desc", "$dlCount file(s) over two weeks old in Downloads. Review before deleting.").put("bytes", dlBytes).put("safe", false).put("path", dl.absolutePath))
        res.put("clean", clean)

        // biggest folders aren't walked on Android (scoped storage); leave empty
        res.put("big", JSONArray())

        progress(92, "Working out recommendations")
        res.put("total", total).put("free", free).put("used", used)
        // recommendations: bloat, big unused apps, old downloads
        val recs = JSONArray()
        var reclaim = 0L
        for (i in 0 until clean.length()) {
            val c = clean.getJSONObject(i)
            if (c.optBoolean("safe") && c.optString("id") != "allcache") { reclaim += c.optLong("bytes") }
            if (c.optString("id") == "owncache") recs.put(JSONObject().put("id", "c-owncache").put("title", "Clear CoreKit cache").put("why", c.optString("desc")).put("bytes", c.optLong("bytes")).put("kind", "clean").put("target", "owncache").put("safe", true))
        }
        val now = System.currentTimeMillis() / 1000
        for (i in 0 until apps.length()) {
            val a = apps.getJSONObject(i)
            if (a.optBoolean("bloat") && a.optBoolean("removable")) {
                recs.put(JSONObject().put("id", "b-" + a.optString("id")).put("title", "Remove " + a.optString("name")).put("why", a.optString("bloatWhy")).put("bytes", a.optLong("size")).put("kind", "app-unused").put("target", a.optString("id")).put("safe", false))
            } else if (a.optBoolean("removable") && !a.optBoolean("system") && a.optLong("lastUsed") > 0 && a.optLong("size") > 50L * 1024 * 1024) {
                val days = (now - a.optLong("lastUsed")) / 86400
                if (days >= 60) recs.put(JSONObject().put("id", "a-" + a.optString("id")).put("title", "Uninstall " + a.optString("name")).put("why", "Not opened in $days days and using " + human(a.optLong("size")) + ".").put("bytes", a.optLong("size")).put("kind", "app-unused").put("target", a.optString("id")).put("safe", false))
            }
        }
        res.put("recs", recs)
        res.put("reclaim", reclaim)
        if (ssm == null || !hasUsageAccess(ctx)) res.put("note", "Grant Usage access for exact app sizes")
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
                for (p in pick["downloads"].orEmpty()) {
                    val f = File(p)
                    val len = f.length()
                    if (runCatching { f.delete() }.getOrDefault(false)) { n++; b += len }
                }
                freed += b
                log.put("Deleted $n old download(s) (" + human(b) + ")")
            }
        }
        return JSONObject().put("freed", freed).put("freedText", human(freed)).put("log", log)
    }

    fun drill(ctx: Context, path: String): JSONObject {
        val dir = File(path)
        if (!dir.isDirectory) return JSONObject().put("error", "That folder isn't available.")
        val items = JSONArray()
        (dir.listFiles() ?: emptyArray()).sortedByDescending { if (it.isDirectory) 0L else it.length() }.take(60).forEach {
            items.put(JSONObject().put("name", it.name).put("path", it.absolutePath).put("bytes", if (it.isDirectory) 0L else it.length()).put("kind", if (it.isDirectory) "folder" else "file"))
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

    private fun appBytesTotal(ctx: Context): Long {
        if (Build.VERSION.SDK_INT < 26 || !hasUsageAccess(ctx)) return 0
        val ssm = ctx.getSystemService(Context.STORAGE_STATS_SERVICE) as StorageStatsManager
        var total = 0L
        for (ai in ctx.packageManager.getInstalledApplications(0)) {
            try { val s = ssm.queryStatsForPackage(StorageManager.UUID_DEFAULT, ai.packageName, Process.myUserHandle()); total += s.appBytes + s.dataBytes } catch (_: Throwable) {}
        }
        return total
    }

    private fun mediaSizes(ctx: Context): Map<String, Long> {
        val out = HashMap<String, Long>()
        val cr = ctx.contentResolver
        fun sum(uri: android.net.Uri): Long {
            var t = 0L
            try {
                cr.query(uri, arrayOf(MediaStore.MediaColumns.SIZE), null, null, null)?.use { c ->
                    val idx = c.getColumnIndex(MediaStore.MediaColumns.SIZE)
                    if (idx >= 0) while (c.moveToNext()) t += c.getLong(idx)
                }
            } catch (_: Throwable) {}
            return t
        }
        out["images"] = sum(MediaStore.Images.Media.EXTERNAL_CONTENT_URI)
        out["video"] = sum(MediaStore.Video.Media.EXTERNAL_CONTENT_URI)
        out["audio"] = sum(MediaStore.Audio.Media.EXTERNAL_CONTENT_URI)
        out["downloads"] = if (Build.VERSION.SDK_INT >= 29) sum(MediaStore.Downloads.EXTERNAL_CONTENT_URI) else dirSize(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS))
        return out
    }

    private fun oldDownloads(dir: File): Pair<Long, Int> {
        if (!dir.isDirectory) return 0L to 0
        val cut = System.currentTimeMillis() - 14L * 86400_000
        var b = 0L; var n = 0
        (dir.listFiles() ?: emptyArray()).forEach {
            val ext = it.extension.lowercase()
            if (it.isFile && it.lastModified() < cut && ext in setOf("apk", "zip", "rar", "7z", "iso", "exe", "dmg")) { b += it.length(); n++ }
        }
        return b to n
    }

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
