package com.corekit.app

import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.atomic.AtomicLong
import kotlin.math.abs
import kotlin.math.roundToInt

/** Cloudflare speed test (same servers and result fields as the Windows app). */
object SpeedTest {
    private const val BASE = "https://speed.cloudflare.com"

    fun run(progress: (phase: String, pct: Int, mbps: Double) -> Unit): JSONObject {
        val o = JSONObject().put("server", "Cloudflare")
        try {
            progress("Measuring latency", 80, 0.0)
            val lat = (0 until 8).mapNotNull { timeOnce() }
            if (lat.isEmpty()) return o.put("ok", false).put("error", "speed server unreachable")
            val ping = lat.sorted()[lat.size / 2]
            val jitter = if (lat.size > 1) lat.zipWithNext { a, b -> abs(a - b) }.average() else 0.0
            val down = transfer(true, 6, 8000) { m -> progress("Download", 84, m) }
            val up = transfer(false, 4, 7000) { m -> progress("Upload", 92, m) }
            return o.put("ok", true).put("down", r1(down)).put("up", r1(up)).put("ping", r1(ping)).put("jitter", r1(jitter))
        } catch (e: Throwable) {
            return o.put("ok", false).put("error", e.message ?: "failed")
        }
    }

    private fun timeOnce(): Double? = try {
        val t0 = System.nanoTime()
        val c = URL("$BASE/__down?bytes=0").openConnection() as HttpURLConnection
        c.connectTimeout = 3000; c.readTimeout = 3000
        c.inputStream.use { it.readBytes() }
        c.disconnect()
        (System.nanoTime() - t0) / 1e6
    } catch (_: Throwable) { null }

    private fun transfer(download: Boolean, streams: Int, ms: Long, report: (Double) -> Unit): Double {
        val bytes = AtomicLong()
        val end = System.currentTimeMillis() + ms
        val start = System.currentTimeMillis()
        val threads = (0 until streams).map {
            Thread {
                val chunk = ByteArray(64 * 1024)
                val payload = ByteArray(2 * 1024 * 1024)
                while (System.currentTimeMillis() < end) {
                    try {
                        if (download) {
                            val c = URL("$BASE/__down?bytes=25000000").openConnection() as HttpURLConnection
                            c.connectTimeout = 4000; c.readTimeout = 4000
                            c.inputStream.use { i ->
                                while (System.currentTimeMillis() < end) {
                                    val n = i.read(chunk); if (n < 0) break; bytes.addAndGet(n.toLong())
                                }
                            }
                            c.disconnect()
                        } else {
                            val c = URL("$BASE/__up").openConnection() as HttpURLConnection
                            c.doOutput = true; c.requestMethod = "POST"; c.connectTimeout = 4000; c.readTimeout = 6000
                            c.setFixedLengthStreamingMode(payload.size)
                            c.outputStream.use { o ->
                                var off = 0
                                while (off < payload.size) { val n = minOf(chunk.size, payload.size - off); o.write(payload, off, n); off += n; bytes.addAndGet(n.toLong()) }
                            }
                            c.responseCode; c.disconnect()
                        }
                    } catch (_: Throwable) { Thread.sleep(150) }
                }
            }.also { it.start() }
        }
        while (System.currentTimeMillis() < end) {
            Thread.sleep(500)
            val secs = (System.currentTimeMillis() - start) / 1000.0
            if (secs > 0) report(bytes.get() * 8 / secs / 1e6)
        }
        threads.forEach { it.join(3000) }
        val secs = (System.currentTimeMillis() - start) / 1000.0
        return bytes.get() * 8 / secs / 1e6
    }

    private fun r1(v: Double) = (v * 10).roundToInt() / 10.0
}
