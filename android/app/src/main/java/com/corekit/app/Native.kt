package com.corekit.app

import android.content.Context
import android.net.ConnectivityManager
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import org.json.JSONObject
import java.io.File
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import kotlin.random.Random

/** Runs the shared Go code (desktop/helper.go) shipped as libcorekit.so. */
class Helper(private val ctx: Context) {
    private val exe = File(ctx.applicationInfo.nativeLibraryDir, "libcorekit.so").path

    fun call(cmd: String, req: JSONObject = JSONObject(), timeoutSec: Long = 60): JSONObject {
        val pb = ProcessBuilder(exe, "--helper", cmd).redirectErrorStream(false)
        dnsServer()?.let { pb.environment()["CK_DNS"] = it }
        val p = pb.start()
        p.outputStream.use { it.write(req.toString().toByteArray()) }
        val out = p.inputStream.bufferedReader().readText()
        if (!p.waitFor(timeoutSec, java.util.concurrent.TimeUnit.SECONDS)) p.destroyForcibly()
        return try { JSONObject(out.trim().ifEmpty { "{}" }) } catch (e: Exception) { JSONObject().put("error", "helper: ${out.take(200)}") }
    }

    /** Raw output (used for the Xray configuration). */
    fun raw(cmd: String, req: JSONObject): String {
        val p = ProcessBuilder(exe, "--helper", cmd).start()
        p.outputStream.use { it.write(req.toString().toByteArray()) }
        val out = p.inputStream.bufferedReader().readText()
        p.waitFor()
        return out
    }

    private fun dnsServer(): String? = try {
        val cm = ctx.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        cm.getLinkProperties(cm.activeNetwork)?.dnsServers?.firstOrNull { it is java.net.Inet4Address }?.hostAddress
    } catch (_: Throwable) { null }
}

/** Encrypted storage: AES-GCM with a key kept in the Android Keystore (never leaves the phone). */
class Vault(ctx: Context) {
    private val dir = File(ctx.filesDir, "browser").apply { mkdirs() }

    private fun key(): SecretKey {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (ks.getEntry(ALIAS, null) as? KeyStore.SecretKeyEntry)?.let { return it.secretKey }
        val kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        kg.init(KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256).build())
        return kg.generateKey()
    }

    fun file(name: String) = File(dir, name)

    fun write(name: String, text: String) {
        synchronized(LOCK) {
            val c = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, key()) }
            val enc = c.iv + c.doFinal(text.toByteArray())
            val f = file(name); f.parentFile?.mkdirs()
            val tmp = File(f.path + ".tmp"); tmp.writeBytes(enc); tmp.renameTo(f)
        }
    }

    fun read(name: String): String? = try {
        val b = file(name).readBytes()
        val c = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, b, 0, 12)) }
        String(c.doFinal(b, 12, b.size - 12))
    } catch (_: Throwable) { null }

    fun delete(name: String) { file(name).deleteRecursively() }

    companion object { private const val ALIAS = "corekit-vault"; private val LOCK = Any() }
}

/** The bundled Xray engine (official build, libxray.so): SOCKS on port, HTTP on port+1. */
class Xray(private val ctx: Context, private val helper: Helper) {
    private var proc: Process? = null
    var port = 0; private set

    fun start(link: String): String? {
        stop()
        port = freePortPair()
        val cfg = helper.raw("xray-config", JSONObject().put("link", link).put("port", port))
        if (!cfg.trimStart().startsWith("{") || cfg.contains("\"error\"")) return try { JSONObject(cfg).optString("error", "invalid proxy link") } catch (_: Throwable) { "invalid proxy link" }
        val f = File(ctx.filesDir, "run-${port}.json")
        f.writeText(cfg)
        try {
            val exe = File(ctx.applicationInfo.nativeLibraryDir, "libxray.so").path
            proc = ProcessBuilder(exe, "run", "-c", f.path).redirectErrorStream(true).directory(ctx.filesDir).start()
            val err = StringBuilder()
            Thread { try { proc?.inputStream?.bufferedReader()?.forEachLine { if (err.length < 4000) err.append(it).append('\n') } } catch (_: Throwable) {} }.start()
            val deadline = System.currentTimeMillis() + 8000
            while (System.currentTimeMillis() < deadline) {
                if (proc?.isAlive != true) return "proxy engine stopped: " + err.toString().takeLast(300)
                try { Socket().use { it.connect(InetSocketAddress("127.0.0.1", port), 200) }; return null } catch (_: Throwable) {}
                Thread.sleep(120)
            }
            stop()
            return "proxy engine did not start"
        } finally { f.delete() }
    }

    fun alive() = proc?.isAlive == true
    fun stop() { proc?.destroy(); proc = null }

    private fun freePortPair(): Int {
        repeat(200) {
            val p = 20000 + Random.nextInt(9500) * 2
            if (free(p) && free(p + 1)) return p
        }
        return 39321
    }
    private fun free(p: Int) = try { ServerSocket(p, 1, java.net.InetAddress.getByName("127.0.0.1")).close(); true } catch (_: Throwable) { false }
}
