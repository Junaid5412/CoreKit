package com.corekit.app

import android.app.ActivityManager
import android.app.KeyguardManager
import android.app.admin.DevicePolicyManager
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.hardware.Sensor
import android.hardware.SensorManager
import android.hardware.camera2.CameraCharacteristics
import android.hardware.camera2.CameraManager
import android.hardware.display.DisplayManager
import android.os.BatteryManager
import android.os.Build
import android.os.Environment
import android.os.StatFs
import android.os.SystemClock
import android.provider.Settings
import android.view.Display
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.FileOutputStream
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import kotlin.math.max
import kotlin.math.min
import kotlin.math.roundToInt

/** Builds the same report JSON as desktop/scripts/collector.ps1, from Android's own APIs. */
class HealthCollector(private val ctx: Context) {

    private class Section(val title: String, val kind: String, val weight: Int) {
        var score: Int? = null
        val rows = JSONArray()
        val notes = JSONArray()
        fun row(l: String, v: String, s: String = "info") = rows.put(JSONObject().put("L", l).put("V", v).put("S", s))
        fun head(l: String, v: String) = row(l, v, "head")
        fun note(t: String, s: String) = notes.put(JSONObject().put("T", t).put("S", s))
        fun json(): JSONObject = JSONObject().put("Title", title).put("Kind", kind).put("Weight", weight)
            .put("Score", score ?: JSONObject.NULL).put("Rows", rows).put("Notes", notes)
    }

    private val quick = JSONObject()
    private val model = "${Build.MANUFACTURER.replaceFirstChar { it.uppercase() }} ${Build.MODEL}"

    fun collect(progress: (Int, String) -> Unit): JSONObject {
        val sections = mutableListOf<Section>()
        val steps: List<Pair<String, () -> Section>> = listOf(
            "Reading device information" to ::overview,
            "Testing the processor" to ::cpu,
            "Checking memory" to ::memory,
            "Checking storage health" to ::storage,
            "Measuring storage speed" to ::storageSpeed,
            "Reading battery health" to ::battery,
            "Checking the display" to ::display,
            "Checking sensors and cameras" to ::hardware,
            "Checking security" to ::security,
        )
        steps.forEachIndexed { i, (label, fn) ->
            progress(5 + i * 90 / steps.size, label)
            try { sections += fn() } catch (e: Throwable) {
                sections += Section(label, "Info", 0).apply { row("Error", e.message ?: "unavailable", "warn") }
            }
        }
        progress(98, "Building report")
        quick.put("Display", displaySummary)
        val arr = JSONArray()
        sections.forEach { arr.put(it.json()) }
        return JSONObject()
            .put("version", "android-1").put("platform", "android").put("admin", true)
            .put("host", model)
            .put("time", SimpleDateFormat("dd MMM yyyy, HH:mm", Locale.ENGLISH).format(Date()))
            .put("quick", quick).put("sections", arr)
    }

    // ---------------------------------------------------------------- sections

    private fun overview() = Section("Device Overview", "Info", 0).apply {
        row("Manufacturer", Build.MANUFACTURER.replaceFirstChar { it.uppercase() })
        row("Model", "${Build.MODEL} (${Build.DEVICE})")
        row("Android", "Android ${Build.VERSION.RELEASE}  (API ${Build.VERSION.SDK_INT})")
        row("Build", Build.DISPLAY)
        row("Kernel", System.getProperty("os.version") ?: "—")
        val up = SystemClock.elapsedRealtime() / 1000
        row("Uptime", "%dd %dh %dm".format(up / 86400, up % 86400 / 3600, up % 3600 / 60))
        quick.put("Model", model)
        quick.put("Android", "Android ${Build.VERSION.RELEASE}")
    }

    private fun cpu() = Section("Processor (CPU)", "Performance", 30).apply {
        val cores = Runtime.getRuntime().availableProcessors()
        val freqs = (0 until cores).mapNotNull { readLong("/sys/devices/system/cpu/cpu$it/cpufreq/cpuinfo_max_freq") }
            .map { it / 1_000_000.0 }
        val soc = if (Build.VERSION.SDK_INT >= 31 && Build.SOC_MODEL != Build.UNKNOWN) "${Build.SOC_MANUFACTURER} ${Build.SOC_MODEL}"
        else (cpuInfoHardware() ?: Build.HARDWARE)
        row("Chip", soc)
        row("Cores", "$cores cores")
        if (freqs.isNotEmpty()) {
            val clusters = freqs.groupingBy { "%.2f".format(it) }.eachCount().entries.sortedByDescending { it.key.toDouble() }
            row("Clusters", clusters.joinToString(" + ") { "${it.value}× ${it.key} GHz" })
        }
        row("Architecture", Build.SUPPORTED_ABIS.firstOrNull() ?: "—")
        val bench = benchmark()
        row("Speed test", "%,d points".format(bench), "ok")
        temperature("cpu", "soc", "tsens")?.let { row("Temperature", "$it °C", if (it >= 80) "warn" else "ok") }
        val sum = if (freqs.isNotEmpty()) freqs.sum() else cores * 1.8
        val byFreq = (sum / 20.0 * 100).roundToInt()
        val byBench = (bench / 4_000.0).roundToInt()
        score = clamp(max(byFreq, byBench))
        quick.put("Processor", "$soc ($cores cores)")
    }

    private fun memory() = Section("Memory (RAM)", "Performance", 20).apply {
        val am = ctx.getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
        val mi = ActivityManager.MemoryInfo().also { am.getMemoryInfo(it) }
        val gb = mi.totalMem / 1e9
        val nominal = listOf(1, 2, 3, 4, 6, 8, 12, 16, 18, 24, 32).firstOrNull { it >= gb - 0.4 } ?: gb.roundToInt()
        row("Installed", "$nominal GB", "ok")
        row("Available now", "%.1f GB (%d%% free)".format(mi.availMem / 1e9, (mi.availMem * 100 / mi.totalMem)),
            if (mi.lowMemory) "warn" else "ok")
        row("Low-memory state", if (mi.lowMemory) "Yes" else "No", if (mi.lowMemory) "warn" else "ok")
        score = when {
            nominal >= 12 -> 100; nominal >= 8 -> 92; nominal >= 6 -> 80; nominal >= 4 -> 62; nominal >= 3 -> 45; else -> 28
        }
        if (nominal <= 3) note("$nominal GB of memory is low for today's apps; expect reloads when switching apps.", "warn")
        quick.put("Memory", "$nominal GB RAM")
    }

    private var storageTotalGb = 0.0

    private fun storage() = Section("Storage Health", "Health", 25).apply {
        val st = StatFs(Environment.getDataDirectory().path)
        val total = st.totalBytes / 1e9
        val free = st.availableBytes / 1e9
        storageTotalGb = total
        val nominal = listOf(16, 32, 64, 128, 256, 512, 1024, 2048).firstOrNull { it >= total } ?: total.roundToInt()
        val freePct = (free / total * 100).roundToInt()
        row("Capacity", "$nominal GB")
        row("Free space", "%.1f GB (%d%%)".format(free, freePct), if (freePct < 10) "bad" else if (freePct < 20) "warn" else "ok")
        val enc = (ctx.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager).storageEncryptionStatus
        row("Encryption", if (enc >= DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE) "On" else "Off",
            if (enc >= DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE) "ok" else "warn")
        score = when { freePct < 5 -> 45; freePct < 10 -> 65; freePct < 20 -> 85; else -> 100 }
        if (freePct < 10) note("Storage is almost full. Phones slow down and updates fail when less than 10% is free.", "warn")
        quick.put("Storage", "$nominal GB · $freePct% free")
    }

    private fun storageSpeed() = Section("Storage Speed", "Performance", 20).apply {
        val f = File(ctx.cacheDir, "ck-speed.bin")
        val buf = ByteArray(1 shl 20) { (it * 31).toByte() }
        val mb = 64
        try {
            val t0 = System.nanoTime()
            FileOutputStream(f).use { o -> repeat(mb) { o.write(buf) }; o.fd.sync() }
            val w = mb / ((System.nanoTime() - t0) / 1e9)
            val t1 = System.nanoTime()
            f.inputStream().use { i -> while (i.read(buf) > 0) Unit }
            val r = mb / ((System.nanoTime() - t1) / 1e9)
            row("Write", "%.0f MB/s".format(w), if (w < 40) "warn" else "ok")
            row("Read", "%.0f MB/s".format(r), "ok")
            row("Test size", "$mb MB")
            score = clamp((w / 250.0 * 100).roundToInt())
            if (w < 40) note("Storage is slow. Apps will open and install slowly.", "warn")
        } finally { f.delete() }
    }

    private fun battery() = Section("Battery", "Health", 30).apply {
        val bi = ctx.registerReceiver(null, IntentFilter(Intent.ACTION_BATTERY_CHANGED)) ?: error("battery unavailable")
        val level = bi.getIntExtra(BatteryManager.EXTRA_LEVEL, -1) * 100 / max(1, bi.getIntExtra(BatteryManager.EXTRA_SCALE, 100))
        val h = bi.getIntExtra(BatteryManager.EXTRA_HEALTH, 0)
        val temp = bi.getIntExtra(BatteryManager.EXTRA_TEMPERATURE, 0) / 10.0
        val volt = bi.getIntExtra(BatteryManager.EXTRA_VOLTAGE, 0)
        val plugged = bi.getIntExtra(BatteryManager.EXTRA_PLUGGED, 0)
        val cycles = if (Build.VERSION.SDK_INT >= 34) bi.getIntExtra(BatteryManager.EXTRA_CYCLE_COUNT, -1) else -1
        val bm = ctx.getSystemService(Context.BATTERY_SERVICE) as BatteryManager
        val counter = bm.getIntProperty(BatteryManager.BATTERY_PROPERTY_CHARGE_COUNTER) // µAh
        val design = designCapacity()
        // full capacity now: kernel value if readable, else estimated from the charge counter
        var full = readLong("/sys/class/power_supply/battery/charge_full")?.let { it / 1000.0 }
            ?.takeIf { it in 500.0..30000.0 }
        if (full == null && counter > 0 && level >= 15) full = counter / 1000.0 / (level / 100.0)
        val healthPct = if (full != null && design != null && design > 500) min(100.0, full / design * 100) else null

        val hName = mapOf(2 to "Good", 3 to "Overheating", 4 to "Dead", 5 to "Over voltage", 6 to "Failure", 7 to "Cold")[h] ?: "Unknown"
        head("Battery health", healthPct?.let { "%.0f%%".format(it) } ?: hName)
        healthPct?.let { row("Wear level", "%.0f%%".format(100 - it), if (it < 70) "bad" else if (it < 80) "warn" else "ok") }
        design?.let { row("Design capacity", "%.0f mAh".format(it)) }
        full?.let { row("Full charge now", "≈%.0f mAh".format(it)) }
        if (cycles >= 0) row("Charge cycles", "$cycles", if (cycles > 800) "warn" else "ok")
        row("Condition", hName, if (h == 2) "ok" else if (h in listOf(3, 5, 6, 4)) "bad" else "info")
        row("Charge", "$level%" + if (plugged != 0) "  (charging)" else "")
        row("Temperature", "%.1f °C".format(temp), if (temp >= 45) "warn" else "ok")
        row("Voltage", "%.2f V".format(volt / 1000.0))
        row("Technology", bi.getStringExtra(BatteryManager.EXTRA_TECHNOLOGY) ?: "—")
        var s = healthPct?.roundToInt() ?: when (h) { 2 -> 90; 3, 7 -> 55; 5 -> 40; 4, 6 -> 15; else -> 70 }
        if (h != 2 && h != 0) s = min(s, 50)
        if (cycles > 800) s = min(s, 75)
        score = clamp(s)
        when {
            healthPct != null && healthPct < 80 -> note("Battery has noticeable wear (%.0f%% health). Expect shorter battery life; a replacement may be needed.".format(healthPct), "warn")
            h != 2 && h != 0 -> note("Android reports the battery as \"$hName\".", "bad")
        }
        if (healthPct == null) note("This phone does not report its design capacity, so wear is estimated from Android's battery status.", "info")
        quick.put("Battery", healthPct?.let { "%.0f%% health".format(it) } ?: hName)
    }

    private var displaySummary = "—"

    private fun display() = Section("Display", "Info", 0).apply {
        val dm = ctx.getSystemService(Context.DISPLAY_SERVICE) as DisplayManager
        val d = dm.getDisplay(Display.DEFAULT_DISPLAY)
        val mode = d.mode
        val m = ctx.resources.displayMetrics
        val rates = d.supportedModes.map { it.refreshRate.roundToInt() }.distinct().sorted()
        head("Resolution", "${mode.physicalWidth} × ${mode.physicalHeight}")
        row("Refresh rate", rates.joinToString(" / ") { "$it Hz" })
        row("Density", "${m.densityDpi} dpi")
        val inch = Math.hypot(mode.physicalWidth / m.xdpi.toDouble(), mode.physicalHeight / m.ydpi.toDouble())
        row("Size", "≈%.1f inch".format(inch))
        val hdr = d.hdrCapabilities?.supportedHdrTypes?.isNotEmpty() == true
        row("HDR", if (hdr) "Supported" else "No")
        displaySummary = "${mode.physicalWidth}×${mode.physicalHeight} · ${rates.maxOrNull() ?: 60} Hz"
    }

    private fun hardware() = Section("Sensors & Hardware", "Health", 10).apply {
        val sm = ctx.getSystemService(Context.SENSOR_SERVICE) as SensorManager
        val pm = ctx.packageManager
        val checks = listOf(
            Triple("Accelerometer", sm.getDefaultSensor(Sensor.TYPE_ACCELEROMETER) != null, true),
            Triple("Gyroscope", sm.getDefaultSensor(Sensor.TYPE_GYROSCOPE) != null, false),
            Triple("Compass", sm.getDefaultSensor(Sensor.TYPE_MAGNETIC_FIELD) != null, false),
            Triple("Proximity", sm.getDefaultSensor(Sensor.TYPE_PROXIMITY) != null, true),
            Triple("Light sensor", sm.getDefaultSensor(Sensor.TYPE_LIGHT) != null, true),
            Triple("Fingerprint", pm.hasSystemFeature(PackageManager.FEATURE_FINGERPRINT), false),
            Triple("NFC", pm.hasSystemFeature(PackageManager.FEATURE_NFC), false),
            Triple("Bluetooth", pm.hasSystemFeature(PackageManager.FEATURE_BLUETOOTH), true),
            Triple("GPS", pm.hasSystemFeature(PackageManager.FEATURE_LOCATION_GPS), true),
        )
        var missing = 0
        for ((n, ok, essential) in checks) {
            row(n, if (ok) "Present" else "Not found", if (ok) "ok" else if (essential) "warn" else "info")
            if (!ok && essential) missing++
        }
        val cm = ctx.getSystemService(Context.CAMERA_SERVICE) as CameraManager
        val cams = try { cm.cameraIdList.toList() } catch (_: Throwable) { emptyList() }
        val back = cams.count { cm.getCameraCharacteristics(it).get(CameraCharacteristics.LENS_FACING) == CameraCharacteristics.LENS_FACING_BACK }
        val front = cams.count { cm.getCameraCharacteristics(it).get(CameraCharacteristics.LENS_FACING) == CameraCharacteristics.LENS_FACING_FRONT }
        row("Cameras", "$back back · $front front", if (cams.isEmpty()) "warn" else "ok")
        row("Total sensors", "${sm.getSensorList(Sensor.TYPE_ALL).size}")
        score = clamp(100 - missing * 20)
        if (missing > 0) note("$missing basic sensor(s) not detected. On a used phone this can mean a replaced or faulty part.", "warn")
    }

    private fun security() = Section("Security & Ownership", "Health", 15).apply {
        val km = ctx.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
        var s = 100
        val lock = km.isDeviceSecure
        row("Screen lock", if (lock) "On" else "Off", if (lock) "ok" else "warn"); if (!lock) s -= 20
        val patch = Build.VERSION.SECURITY_PATCH
        val age = monthsSince(patch)
        row("Security patch", "$patch" + (age?.let { " ($it months old)" } ?: ""), if ((age ?: 0) > 12) "warn" else "ok")
        if ((age ?: 0) > 12) { s -= 15; note("Security updates are over a year old. The phone may no longer receive updates.", "warn") }
        val root = isRooted()
        row("Rooted", if (root) "Yes" else "No", if (root) "warn" else "ok"); if (root) { s -= 25; note("The phone appears to be rooted. Banking apps may refuse to run and security is weaker.", "warn") }
        val dev = Settings.Global.getInt(ctx.contentResolver, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0) == 1
        val adb = Settings.Global.getInt(ctx.contentResolver, Settings.Global.ADB_ENABLED, 0) == 1
        row("Developer options", if (dev) "On" else "Off", if (dev) "warn" else "ok")
        row("USB debugging", if (adb) "On" else "Off", if (adb) "warn" else "ok"); if (adb) s -= 10
        val tags = Build.TAGS ?: ""
        row("Firmware", if (tags.contains("release-keys")) "Official (release keys)" else tags.ifBlank { "Unknown" },
            if (tags.contains("test-keys")) "warn" else "ok")
        if (tags.contains("test-keys")) { s -= 15; note("The firmware is signed with test keys (custom or unofficial ROM).", "warn") }
        score = clamp(s)
    }

    // ---------------------------------------------------------------- helpers

    private fun clamp(v: Int) = v.coerceIn(0, 100)

    private fun readLong(path: String): Long? = try { File(path).readText().trim().toLong() } catch (_: Throwable) { null }

    private fun cpuInfoHardware(): String? = try {
        File("/proc/cpuinfo").readLines().firstOrNull { it.startsWith("Hardware") }?.substringAfter(":")?.trim()
    } catch (_: Throwable) { null }

    private fun temperature(vararg kinds: String): Int? {
        val dirs = File("/sys/class/thermal").listFiles { f -> f.name.startsWith("thermal_zone") } ?: return null
        for (d in dirs) {
            val type = try { File(d, "type").readText().trim().lowercase() } catch (_: Throwable) { continue }
            if (kinds.none { type.contains(it) }) continue
            val t = readLong(File(d, "temp").path) ?: continue
            val c = if (t > 1000) (t / 1000).toInt() else t.toInt()
            if (c in 15..120) return c
        }
        return null
    }

    /** Short multi-core integer benchmark (about one second). */
    private fun benchmark(): Int {
        val n = Runtime.getRuntime().availableProcessors()
        val counts = LongArray(n)
        val end = System.nanoTime() + 900_000_000L
        val threads = (0 until n).map { t ->
            Thread {
                var x = 88172645463325252L + t
                var c = 0L
                while (System.nanoTime() < end) {
                    for (i in 0 until 20_000) { x = x xor (x shl 13); x = x xor (x ushr 7); x = x xor (x shl 17) }
                    c++
                }
                counts[t] = c + (x and 1)
            }.also { it.start() }
        }
        threads.forEach { it.join() }
        return counts.sum().toInt()
    }

    private fun designCapacity(): Double? = try {
        val cls = Class.forName("com.android.internal.os.PowerProfile")
        val pp = cls.getConstructor(Context::class.java).newInstance(ctx)
        (cls.getMethod("getBatteryCapacity").invoke(pp) as Double).takeIf { it > 500 }
    } catch (_: Throwable) {
        readLong("/sys/class/power_supply/battery/charge_full_design")?.let { it / 1000.0 }?.takeIf { it in 500.0..30000.0 }
    }

    private fun isRooted(): Boolean {
        val paths = listOf("/system/bin/su", "/system/xbin/su", "/sbin/su", "/su/bin/su", "/data/local/xbin/su", "/data/local/bin/su", "/system/app/Superuser.apk")
        return paths.any { File(it).exists() }
    }

    private fun monthsSince(date: String): Int? = try {
        val d = SimpleDateFormat("yyyy-MM-dd", Locale.US).parse(date) ?: return null
        ((System.currentTimeMillis() - d.time) / (1000L * 60 * 60 * 24 * 30)).toInt()
    } catch (_: Throwable) { null }
}
