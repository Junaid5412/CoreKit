package com.corekit.app

import android.content.Context
import android.os.Build
import android.provider.Settings
import org.json.JSONObject
import java.io.File
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.URL
import java.security.SecureRandom
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/**
 * The Remote Access engine is the shared Go code (libcorekit.so --remote): pairing,
 * encryption, discovery and the session. It listens on a random loopback port and
 * only answers requests that carry our random token. The page talks to it through
 * Host (events) and the bridge (commands); RemoteService feeds it screen frames and
 * takes input events from it.
 */
object RemoteEngine {
    @Volatile private var proc: Process? = null
    @Volatile var port = 0; private set
    @Volatile var lastError = ""; private set
    val token: String = ByteArray(24).also { SecureRandom().nextBytes(it) }.joinToString("") { "%02x".format(it) }
    private val io = Executors.newSingleThreadExecutor()

    @Synchronized
    fun ensure(ctx: Context): Boolean {
        proc?.let { if (it.isAlive && port > 0) return true }
        port = 0
        val exe = File(ctx.applicationInfo.nativeLibraryDir, "libcorekit.so").path
        val pb = ProcessBuilder(exe, "--remote").redirectErrorStream(true)
        pb.environment()["CK_TOKEN"] = token
        pb.environment()["CK_NAME"] = deviceName(ctx)
        // Android has no /etc/resolv.conf: hand the network's DNS servers to the engine
        try {
            val cm = ctx.getSystemService(Context.CONNECTIVITY_SERVICE) as android.net.ConnectivityManager
            cm.getLinkProperties(cm.activeNetwork)?.dnsServers?.mapNotNull { it.hostAddress?.substringBefore('%') }
                ?.takeIf { it.isNotEmpty() }?.let { pb.environment()["CK_DNS"] = it.joinToString(",") }
        } catch (_: Throwable) {}
        // root certificates for HTTPS downloads (Android 14 keeps the current ones in an APEX)
        listOf("/apex/com.android.conscrypt/cacerts", "/system/etc/security/cacerts").filter { File(it).isDirectory }
            .takeIf { it.isNotEmpty() }?.let { pb.environment()["SSL_CERT_DIR"] = it.joinToString(":") }
        val p = try { pb.start() } catch (e: Throwable) { lastError = "could not run the engine (${e.message})"; return false }
        val early = StringBuilder()
        proc = p
        val reader = p.inputStream.bufferedReader()
        val ready = java.util.concurrent.CountDownLatch(1)
        Thread {
            try {
                reader.forEachLine { line ->
                    if (port == 0 && line.startsWith("READY ")) { port = line.removePrefix("READY ").trim().toIntOrNull() ?: 0; ready.countDown() }
                    else if (port == 0 && early.length < 400) early.append(line.trim()).append(' ')
                    // keep reading: the engine's log lines must not fill the pipe
                }
            } catch (_: Throwable) {}
            ready.countDown()
        }.apply { isDaemon = true }.start()
        ready.await(6, TimeUnit.SECONDS)
        if (port == 0) {
            lastError = early.toString().trim().ifEmpty { if (p.isAlive) "the engine did not answer in time" else "the engine stopped (exit ${try { p.exitValue() } catch (_: Throwable) { -1 }})" }
            try { p.destroy() } catch (_: Throwable) {}; proc = null; return false
        }
        lastError = ""
        // tell the engine whether tapping/typing is possible right now
        cmd(ctx, JSONObject().put("t", "glue").put("a11y", RemoteControlService.isOn(ctx)).toString())
        return true
    }

    /** Stops the engine process (Exit). It starts again on the next command. */
    fun stop() {
        io.execute {
            try { proc?.destroy() } catch (_: Throwable) {}
            proc = null; port = 0
        }
    }

    fun deviceName(ctx: Context): String = try {
        Settings.Global.getString(ctx.contentResolver, Settings.Global.DEVICE_NAME)?.takeIf { it.isNotBlank() }
    } catch (_: Throwable) { null } ?: "${Build.MANUFACTURER.replaceFirstChar { it.uppercase() }} ${Build.MODEL}"

    private fun open(path: String, method: String = "GET"): HttpURLConnection {
        val c = URL("http://127.0.0.1:$port/$path").openConnection() as HttpURLConnection
        c.requestMethod = method
        c.setRequestProperty("X-CK", token)
        c.connectTimeout = 3000
        return c
    }

    /** Sends one command (JSON) to the engine, off the calling thread. */
    fun cmd(ctx: Context, json: String) {
        io.execute {
            if (!ensure(ctx)) return@execute
            try {
                val c = open("cmd", "POST")
                c.doOutput = true; c.readTimeout = 5000
                c.setRequestProperty("Content-Type", "application/json")
                c.outputStream.use { it.write(json.toByteArray()) }
                c.responseCode; c.disconnect()
            } catch (_: Throwable) {}
        }
    }

    /** Event stream for the page (glue = false) or for RemoteService (glue = true).
     *  lite: screen frames come as a small notice; the picture is fetched with [lastFrame]. */
    fun events(ctx: Context, glue: Boolean, lite: Boolean = false): InputStream? {
        if (!ensure(ctx)) return null
        return try {
            val c = open(if (glue) "glue" else if (lite) "events?lite=1" else "events")
            c.readTimeout = 0
            c.inputStream
        } catch (_: Throwable) { null }
    }

    /** The newest picture received from the other device (JPEG), or null. */
    fun lastFrame(): ByteArray? {
        if (port == 0) return null
        return try {
            val c = open("lastframe"); c.readTimeout = 4000
            val b = if (c.responseCode == 200) c.inputStream.use { it.readBytes() } else null
            c.disconnect(); b
        } catch (_: Throwable) { null }
    }

    /** Current engine state (JSON), or "" if the engine isn't running yet. Never starts it. */
    fun state(): String {
        if (port == 0 || proc?.isAlive != true) return ""
        return try {
            val c = open("state"); c.readTimeout = 2000
            val s = c.inputStream.bufferedReader().readText(); c.disconnect(); s
        } catch (_: Throwable) { "" }
    }

    /** One captured screen frame (JPEG). Called on the capture thread. */
    fun frame(jpeg: ByteArray, w: Int, h: Int) {
        if (port == 0) return
        try {
            val c = open("frame", "POST")
            c.doOutput = true; c.readTimeout = 3000
            c.setFixedLengthStreamingMode(jpeg.size)
            c.setRequestProperty("X-W", w.toString()); c.setRequestProperty("X-H", h.toString())
            c.outputStream.use { it.write(jpeg) }
            c.responseCode; c.disconnect()
        } catch (_: Throwable) {}
    }
}
