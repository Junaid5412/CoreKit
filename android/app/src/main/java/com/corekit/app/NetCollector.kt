package com.corekit.app

import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.NetworkCapabilities
import android.net.wifi.WifiManager
import android.os.Build
import android.provider.Settings
import org.json.JSONArray
import org.json.JSONObject
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.HttpURLConnection
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URL
import java.security.cert.X509Certificate
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory
import kotlin.math.abs
import kotlin.math.roundToInt
import kotlin.random.Random

/** Internet diagnosis for Android — returns the same JSON as desktop/scripts/net.ps1 (scan mode). */
class NetCollector(private val ctx: Context) {
    private val cm = ctx.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
    private val issues = JSONArray()

    private fun issue(id: String, sev: String, layer: String, title: String, detail: String, vararg fixes: String) {
        issues.put(JSONObject().put("id", id).put("sev", sev).put("layer", layer).put("title", title)
            .put("detail", detail).put("fixes", JSONArray(fixes.toList())))
    }

    fun scan(sitesRaw: String, progress: (Int, String) -> Unit): JSONObject {
        val out = JSONObject().put("version", "android-1").put("platform", "android")
            .put("time", SimpleDateFormat("dd MMM yyyy, HH:mm", Locale.ENGLISH).format(Date()))
            .put("host", "${Build.MANUFACTURER.replaceFirstChar { it.uppercase() }} ${Build.MODEL}")

        progress(4, "Reading network connection")
        val net = cm.activeNetwork
        val caps = net?.let { cm.getNetworkCapabilities(it) }
        val lp = net?.let { cm.getLinkProperties(it) }
        val kind = when {
            caps == null -> "None"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "Wi-Fi"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "Mobile data"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "Ethernet"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) -> "VPN"
            else -> "Other"
        }
        val vpnOn = cm.allNetworks.any { cm.getNetworkCapabilities(it)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true }
        val ipv4 = lp?.linkAddresses?.firstOrNull { it.address is Inet4Address }
        val ipv6 = lp?.linkAddresses?.firstOrNull { it.address is Inet6Address && !it.address.isLinkLocalAddress }
        val gateway = lp?.routes?.firstOrNull { it.isDefaultRoute && it.gateway is Inet4Address }?.gateway?.hostAddress
        val dns = lp?.dnsServers?.filterIsInstance<Inet4Address>()?.map { it.hostAddress ?: "" } ?: emptyList()
        val dns6 = lp?.dnsServers?.filterIsInstance<Inet6Address>()?.map { it.hostAddress ?: "" } ?: emptyList()
        val privDns = if (Build.VERSION.SDK_INT >= 28 && lp != null) lp.isPrivateDnsActive else false
        val privName = if (Build.VERSION.SDK_INT >= 28) lp?.privateDnsServerName else null

        // Wi-Fi
        val wifi = JSONObject()
        var signal = 0
        if (kind == "Wi-Fi") {
            @Suppress("DEPRECATION")
            val wi = (ctx.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager).connectionInfo
            signal = ((wi.rssi + 100) * 2).coerceIn(0, 100)
            val freq = wi.frequency
            val band = when { freq >= 5925 -> "6 GHz"; freq >= 4900 -> "5 GHz"; freq > 0 -> "2.4 GHz"; else -> "" }
            val ch = when { freq in 2412..2484 -> if (freq == 2484) 14 else (freq - 2407) / 5; freq in 5170..5895 -> (freq - 5000) / 5; freq >= 5955 -> (freq - 5950) / 5; else -> 0 }
            val std = if (Build.VERSION.SDK_INT >= 30) when (wi.wifiStandard) { 4 -> "802.11n (Wi-Fi 4)"; 5 -> "802.11ac (Wi-Fi 5)"; 6 -> "802.11ax (Wi-Fi 6)"; 7 -> "802.11ad"; 8 -> "802.11be (Wi-Fi 7)"; else -> "802.11a/b/g" } else ""
            val ssid = wi.ssid?.trim('"')?.takeIf { it.isNotBlank() && it != "<unknown ssid>" } ?: "Hidden (allow location to show)"
            wifi.put("state", "connected").put("ssid", ssid).put("signal", signal).put("radio", std).put("band", band)
                .put("channel", if (ch > 0) "$ch" else "").put("rssi", wi.rssi)
                .put("rx", if (Build.VERSION.SDK_INT >= 29) "${wi.rxLinkSpeedMbps}" else "${wi.linkSpeed}")
                .put("tx", if (Build.VERSION.SDK_INT >= 29) "${wi.txLinkSpeedMbps}" else "${wi.linkSpeed}")
                .put("auth", "").put("cipher", "").put("radioOff", false)
            if (signal < 35) issue("wifi-weak", "warning", "adapter", "Weak Wi-Fi signal ($signal%)",
                "Move closer to the router or remove obstacles. Weak signal causes slow pages and drop-outs.", "open:wifi")
        } else {
            val wm = ctx.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
            wifi.put("state", if (wm.isWifiEnabled) "disconnected" else "off").put("radioOff", !wm.isWifiEnabled)
        }
        out.put("wifi", wifi)

        val active = JSONObject().put("name", kind).put("desc", kind).put("kind", kind)
            .put("ipv4", ipv4?.address?.hostAddress ?: JSONObject.NULL).put("prefix", ipv4?.prefixLength ?: 0)
            .put("gateway", gateway ?: JSONObject.NULL).put("dns", JSONArray(dns)).put("dns6", JSONArray(dns6))
            .put("dnsProvider", when { privDns -> "Private DNS" + (privName?.let { " ($it)" } ?: " (automatic)"); else -> providerName(dns) })
            .put("dhcp", true).put("speed", wifi.optString("rx").takeIf { it.isNotBlank() }?.let { "$it Mbps" } ?: "")
            .put("mac", "").put("connectivity", if (caps?.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED) == true) "Internet" else "No internet")
            .put("network", wifi.optString("ssid", kind)).put("ipv6", ipv6?.address?.hostAddress ?: JSONObject.NULL)
        out.put("active", if (net == null) JSONObject.NULL else active)
        out.put("adapters", JSONArray().put(JSONObject().put("name", kind).put("desc", kind).put("status", if (net != null) "Up" else "Down")
            .put("kind", kind).put("speed", active.optString("speed")).put("mac", "").put("driver", "").put("disabled", false)))
        if (net == null) issue("no-connection", "critical", "adapter", "No network connection",
            "Turn on Wi-Fi or mobile data and connect to a network.", "open:wifi", "open:mobile")

        // Reachability
        progress(14, "Testing the router")
        val pGw = gateway?.let { ping(it) } ?: JSONObject().put("ok", false).put("target", JSONObject.NULL)
        progress(22, "Testing the internet")
        val pCf = ping("1.1.1.1")
        val pGg = ping("8.8.8.8")
        out.put("pingGateway", pGw).put("pingCloudflare", pCf).put("pingGoogle", pGg)
        out.put("ipv6", if (ipv6 != null) tcpTime("2606:4700:4700::1111", 443)?.let { JSONObject().put("ok", true).put("avg", it) } ?: JSONObject().put("ok", false) else JSONObject().put("ok", false))

        progress(30, "Checking for a login page (captive portal)")
        val ncsi = captiveCheck()
        out.put("ncsi", ncsi)
        val portal = ncsi.optBoolean("portal") || caps?.hasCapability(NetworkCapabilities.NET_CAPABILITY_CAPTIVE_PORTAL) == true
        if (portal) issue("portal", "critical", "internet", "This network needs a login",
            "Open the Wi-Fi login page and sign in (hotel, airport, office Wi-Fi).", "open:portal")

        // DNS
        progress(40, "Benchmarking DNS servers")
        val bench = dnsBench(dns.firstOrNull())
        out.put("dnsBench", bench)
        val current = (0 until bench.length()).map { bench.getJSONObject(it) }.firstOrNull { it.optBoolean("current") }
        val best = (0 until bench.length()).map { bench.getJSONObject(it) }.filter { !it.optBoolean("current") && it.optInt("fail") < it.optInt("total") }
            .minByOrNull { it.optInt("ms", 9999) }
        out.put("fastestDns", best?.optString("key") ?: JSONObject.NULL)
        progress(52, "Checking DNS for redirection")
        val hijack = dns.firstOrNull()?.let { dnsHijack(it) } ?: false
        out.put("dnsHijack", hijack)
        out.put("doh", if (privDns) JSONArray().put(privName ?: "automatic") else JSONArray())
        out.put("dohSupported", Build.VERSION.SDK_INT >= 28)
        if (current != null && current.optInt("fail") >= current.optInt("total") && net != null)
            issue("dns-fail", "critical", "dns", "DNS is not answering",
                "Websites cannot be found by name. Use Private DNS (Cloudflare) to fix it.", "dns:cloudflare", "open:privatedns")
        else if (current != null && best != null && current.optInt("ms") > 80 && current.optInt("ms") > best.optInt("ms") * 3)
            issue("dns-slow", "warning", "dns", "Slow DNS (${current.optInt("ms")} ms)",
                "${best.optString("name")} answers in ${best.optInt("ms")} ms. A faster DNS makes every website open quicker.", "dns:${best.optString("key")}")
        if (hijack) issue("dns-hijack", "warning", "dns", "Your DNS redirects unknown websites",
            "Your provider's DNS answers for websites that do not exist (ad redirection). Private DNS fixes this and adds privacy.", "dns:cloudflare")

        // Clock, proxy, VPN
        progress(60, "Checking the clock")
        val clock = clockCheck()
        out.put("clock", clock)
        if (abs(clock.optInt("skew")) > 120) issue("clock", "critical", "web", "Phone clock is wrong by ${fmtSkew(clock.optInt("skew"))}",
            "A wrong clock breaks secure (HTTPS) websites. Turn on automatic date and time.", "open:datetime")
        @Suppress("DEPRECATION")
        val proxyHost = cm.defaultProxy?.host ?: System.getProperty("http.proxyHost")
        out.put("proxy", JSONObject().put("enabled", !proxyHost.isNullOrBlank()).put("server", proxyHost ?: JSONObject.NULL).put("pac", JSONObject.NULL))
        if (!proxyHost.isNullOrBlank()) issue("proxy", "warning", "web", "A proxy is set for this network",
            "Traffic goes through $proxyHost. Remove it in the Wi-Fi network's advanced settings if you didn't set it.", "open:wifi")
        out.put("vpn", if (vpnOn) JSONArray().put("VPN active") else JSONArray())
        out.put("hosts", JSONArray()).put("firewall", JSONArray()).put("av", JSONArray())

        // Websites
        val sites = JSONArray()
        val custom = sitesRaw.split(",").map { it.trim().lowercase() }.filter { it.isNotBlank() }.take(5)
        val all = custom.map { it to true } + listOf("www.google.com", "www.cloudflare.com", "www.microsoft.com").map { it to false }
        all.forEachIndexed { i, (h, isCustom) ->
            progress(66 + i * 30 / all.size, "Testing $h")
            sites.put(siteCheck(h, isCustom))
        }
        out.put("sites", sites)
        for (k in 0 until sites.length()) {
            val s = sites.getJSONObject(k)
            if (s.optString("status") == "fail") issue("site:${s.optString("host")}", if (s.optBoolean("custom")) "critical" else "warning", "web",
                "${s.optString("host")} is not working", s.optString("cause"), *jsonList(s.optJSONArray("fixes")).toTypedArray())
        }

        val online = pCf.optBoolean("ok") || pGg.optBoolean("ok") || (0 until sites.length()).any { sites.getJSONObject(it).optString("status") == "ok" }
        out.put("online", online)
        if (net != null && !online && !portal) issue("offline", "critical", "internet", "Connected, but no internet",
            "The ${kind.lowercase()} network has no internet access. Restart the router or switch networks.", "open:wifi")

        out.put("layers", JSONObject()
            .put("adapter", layer(net != null, false, if (kind == "Wi-Fi") "Wi-Fi $signal%" else kind))
            .put("router", layer(pGw.optBoolean("ok") || gateway == null && net != null, false, pGw.optDouble("avg", -1.0).takeIf { it >= 0 }?.let { "%.1f ms".format(it) } ?: "—"))
            .put("internet", layer(online, portal, if (portal) "Login needed" else pCf.optDouble("avg", -1.0).takeIf { it >= 0 }?.let { "%.1f ms".format(it) } ?: if (online) "OK" else "Offline"))
            .put("dns", layer(current?.let { it.optInt("fail") < it.optInt("total") } ?: false, (current?.optInt("ms") ?: 0) > 80 || hijack, current?.let { "${it.optInt("ms")} ms" } ?: "—"))
            .put("web", layer((0 until sites.length()).none { sites.getJSONObject(it).optString("status") == "fail" }, false,
                if ((0 until sites.length()).any { sites.getJSONObject(it).optString("status") == "fail" }) "Problems" else "OK")))
        out.put("issues", issues)
        progress(97, "Done")
        return out
    }

    // ---------------------------------------------------------------- probes

    private fun layer(ok: Boolean, warn: Boolean, text: String) =
        JSONObject().put("status", if (!ok) "fail" else if (warn) "warn" else "ok").put("text", text)

    private fun providerName(dns: List<String>): String {
        val known = mapOf("1.1.1.1" to "Cloudflare", "1.0.0.1" to "Cloudflare", "8.8.8.8" to "Google", "8.8.4.4" to "Google",
            "9.9.9.9" to "Quad9", "208.67.222.222" to "OpenDNS")
        val names = dns.mapNotNull { known[it] }.distinct()
        return if (names.isNotEmpty()) names.joinToString(" + ") else "Automatic (router / provider)"
    }

    /** ICMP ping through the system ping tool; TCP timing if ping is unavailable. */
    private fun ping(target: String): JSONObject {
        val o = JSONObject().put("target", target)
        val times = mutableListOf<Double>()
        var sent = 4
        try {
            val p = ProcessBuilder("/system/bin/ping", "-c", "4", "-i", "0.25", "-W", "1", target).redirectErrorStream(true).start()
            p.inputStream.bufferedReader().forEachLine { l -> Regex("time=([0-9.]+)").find(l)?.let { times += it.groupValues[1].toDouble() } }
            p.waitFor()
        } catch (_: Throwable) {
            sent = 3
            repeat(3) { tcpTime(target, 53)?.let { times += it } ?: tcpTime(target, 443)?.let { times += it } }
        }
        if (times.isEmpty()) return o.put("ok", false).put("loss", 100)
        val avg = times.average()
        val jitter = if (times.size > 1) times.zipWithNext { a, b -> abs(a - b) }.average() else 0.0
        return o.put("ok", true).put("avg", r1(avg)).put("min", r1(times.min())).put("jitter", r1(jitter))
            .put("loss", ((sent - times.size).coerceAtLeast(0) * 100 / sent))
    }

    private fun tcpTime(host: String, port: Int, timeout: Int = 1500): Double? = try {
        Socket().use { s ->
            val t0 = System.nanoTime()
            s.connect(InetSocketAddress(host, port), timeout)
            (System.nanoTime() - t0) / 1e6
        }
    } catch (_: Throwable) { null }

    private fun captiveCheck(): JSONObject = try {
        val c = URL("http://connectivitycheck.gstatic.com/generate_204").openConnection() as HttpURLConnection
        c.instanceFollowRedirects = false; c.connectTimeout = 4000; c.readTimeout = 4000; c.useCaches = false
        val code = c.responseCode
        val loc = c.getHeaderField("Location")
        c.disconnect()
        JSONObject().put("ok", code == 204).put("portal", code != 204 && code in 200..399).put("status", code)
            .put("final", loc ?: "http://connectivitycheck.gstatic.com/generate_204").put("error", JSONObject.NULL)
    } catch (e: Throwable) {
        JSONObject().put("ok", false).put("portal", false).put("status", 0).put("final", JSONObject.NULL).put("error", e.message ?: "failed")
    }

    /** Minimal DNS A-record query over UDP. Returns (answered, rcode, ms) or null on timeout. */
    private fun dnsQuery(server: String, name: String, timeout: Int = 1500): Triple<Int, Int, Double>? = try {
        DatagramSocket().use { sock ->
            sock.soTimeout = timeout
            val id = Random.nextInt(0, 65535)
            val q = java.io.ByteArrayOutputStream()
            q.write(byteArrayOf((id shr 8).toByte(), id.toByte(), 1, 0, 0, 1, 0, 0, 0, 0, 0, 0))
            for (label in name.trimEnd('.').split(".")) { q.write(label.length); q.write(label.toByteArray()) }
            q.write(byteArrayOf(0, 0, 1, 0, 1))
            val data = q.toByteArray()
            val t0 = System.nanoTime()
            sock.send(DatagramPacket(data, data.size, InetAddress.getByName(server), 53))
            val buf = ByteArray(1500)
            val pk = DatagramPacket(buf, buf.size)
            while (true) {
                sock.receive(pk)
                if (((buf[0].toInt() and 255) shl 8 or (buf[1].toInt() and 255)) == id) break
            }
            val ms = (System.nanoTime() - t0) / 1e6
            Triple((buf[6].toInt() and 255) shl 8 or (buf[7].toInt() and 255), buf[3].toInt() and 15, ms)
        }
    } catch (_: Throwable) { null }

    private fun dnsBench(current: String?): JSONArray {
        val list = mutableListOf<Triple<String, String, String>>()
        if (current != null) list += Triple("current", "Current", current)
        list += listOf(Triple("cloudflare", "Cloudflare", "1.1.1.1"), Triple("google", "Google", "8.8.8.8"),
            Triple("quad9", "Quad9", "9.9.9.9"), Triple("opendns", "OpenDNS", "208.67.222.222"))
        val names = listOf("example.com", "wikipedia.org", "github.com")
        val arr = JSONArray()
        for ((key, name, ip) in list) {
            val times = mutableListOf<Double>()
            var fail = 0
            for (round in 0 until 2) for (n in names) {
                val r = dnsQuery(ip, if (round == 0) n else "www.$n")
                if (r == null || r.second != 0) fail++ else times += r.third
            }
            arr.put(JSONObject().put("key", key).put("name", name).put("ip", ip).put("current", key == "current")
                .put("ms", if (times.isEmpty()) 0 else times.sorted()[times.size / 2].roundToInt()).put("fail", fail).put("total", 6))
        }
        return arr
    }

    private fun dnsHijack(server: String): Boolean {
        val r = dnsQuery(server, "ck${Random.nextLong(1_000_000_000L, 9_999_999_999L)}.nonexistent-check.invalid") ?: return false
        return r.second == 0 && r.first > 0
    }

    private fun clockCheck(): JSONObject {
        val o = JSONObject()
        val tz = TimeZone.getDefault()
        o.put("tz", tz.id).put("local", SimpleDateFormat("dd MMM yyyy HH:mm:ss", Locale.ENGLISH).format(Date()))
        val auto = Settings.Global.getInt(ctx.contentResolver, Settings.Global.AUTO_TIME, 1) == 1
        o.put("service", if (auto) "Automatic" else "Manual").put("startup", if (auto) "Automatic" else "Manual")
        var skew = 0
        try {
            val c = URL("https://www.google.com/generate_204").openConnection() as HttpsURLConnection
            c.requestMethod = "HEAD"; c.connectTimeout = 4000; c.readTimeout = 4000
            val t0 = System.currentTimeMillis()
            c.responseCode
            val server = c.date
            c.disconnect()
            if (server > 0) skew = ((t0 - server) / 1000).toInt()
        } catch (_: Throwable) {}
        return o.put("skew", skew)
    }

    /** DNS + TCP + TLS (certificate) + HTTP for one website, like the Windows check. */
    private fun siteCheck(host: String, custom: Boolean): JSONObject {
        val o = JSONObject().put("host", host).put("custom", custom).put("hostsOverride", JSONObject.NULL)
        val fixes = JSONArray()
        // DNS (system and public)
        val t0 = System.nanoTime()
        val sysIps = try { InetAddress.getAllByName(host).map { it.hostAddress ?: "" } } catch (_: Throwable) { emptyList() }
        val sysMs = ((System.nanoTime() - t0) / 1e6).roundToInt()
        o.put("dnsSys", JSONObject().put("ok", sysIps.isNotEmpty()).put("ms", sysMs).put("ips", JSONArray(sysIps.filter { !it.contains(":") }))
            .put("ip6", JSONArray(sysIps.filter { it.contains(":") })).put("err", if (sysIps.isEmpty()) "not found" else JSONObject.NULL))
        val pub = dnsQuery("1.1.1.1", host)
        o.put("dnsPub", JSONObject().put("ok", pub != null && pub.second == 0 && pub.first > 0).put("ms", pub?.third?.roundToInt() ?: 0)
            .put("ips", JSONArray()).put("nx", pub?.second == 3).put("err", if (pub == null) "timeout" else JSONObject.NULL))
        if (sysIps.isEmpty()) {
            val cause = if (pub != null && pub.first > 0) "Your DNS cannot find this website, but public DNS can. Your DNS is blocking or broken."
            else "This website name does not exist or cannot be found."
            if (pub != null && pub.first > 0) fixes.put("dns:cloudflare")
            return o.put("status", "fail").put("cause", cause).put("fixes", fixes).put("ip", JSONObject.NULL).put("tls", JSONObject.NULL).put("http", JSONObject.NULL)
        }
        o.put("ip", sysIps.first())
        // TCP + TLS with certificate details
        val tls = JSONObject()
        var tlsOk = false
        var cause = ""
        try {
            val t1 = System.nanoTime()
            val raw = Socket()
            raw.connect(InetSocketAddress(sysIps.first(), 443), 5000)
            val tcpMs = ((System.nanoTime() - t1) / 1e6).roundToInt()
            tls.put("tcpOk", true).put("tcpMs", tcpMs)
            val t2 = System.nanoTime()
            val s = (SSLSocketFactory.getDefault() as SSLSocketFactory).createSocket(raw, host, 443, true) as SSLSocket
            s.soTimeout = 6000
            val params = s.sslParameters; params.endpointIdentificationAlgorithm = "HTTPS"; s.sslParameters = params
            s.startHandshake()
            tls.put("tlsMs", ((System.nanoTime() - t2) / 1e6).roundToInt())
            val ses = s.session
            val cert = ses.peerCertificates.firstOrNull() as? X509Certificate
            val fmt = SimpleDateFormat("dd MMM yyyy", Locale.ENGLISH)
            tls.put("protocol", ses.protocol.replace("TLSv", "TLS ")).put("ok", true)
            cert?.let {
                tls.put("subject", cn(it.subjectX500Principal.name)).put("issuer", cn(it.issuerX500Principal.name))
                    .put("issuerOrg", org(it.issuerX500Principal.name)).put("validFrom", fmt.format(it.notBefore))
                    .put("validTo", fmt.format(it.notAfter)).put("daysLeft", ((it.notAfter.time - System.currentTimeMillis()) / 86_400_000L).toInt())
            }
            tls.put("errors", "None").put("chain", JSONArray()).put("chainNames", JSONArray()).put("root", "").put("error", JSONObject.NULL).put("revocation", JSONObject.NULL)
            s.close()
            tlsOk = true
        } catch (e: javax.net.ssl.SSLHandshakeException) {
            val m = (e.cause?.message ?: e.message ?: "").lowercase()
            cause = when {
                "expired" in m || "not yet valid" in m -> { fixes.put("open:datetime"); "The site's certificate is expired or the phone's date is wrong." }
                "trust anchor" in m || "certpath" in m -> "This phone does not trust the site's certificate. Something may be intercepting secure connections (or the site is misconfigured)."
                "hostname" in m -> "The certificate belongs to a different website. The connection may be redirected."
                else -> "Secure connection failed: ${e.message ?: "handshake error"}"
            }
            tls.put("ok", false).put("tcpOk", true).put("errors", e.message ?: "handshake failed").put("error", e.message ?: "")
        } catch (e: javax.net.ssl.SSLPeerUnverifiedException) {
            cause = "The certificate belongs to a different website. The connection may be redirected."
            tls.put("ok", false).put("tcpOk", true).put("errors", "Name mismatch").put("error", e.message ?: "")
        } catch (e: Throwable) {
            cause = if (!tls.has("tcpOk")) "The website could not be reached (connection blocked or timed out)." else "Secure connection failed: ${e.message ?: "error"}"
            tls.put("ok", false).put("tcpOk", tls.optBoolean("tcpOk", false)).put("error", e.message ?: "")
            if (!tls.has("tcpOk")) tls.put("tcpOk", false)
        }
        o.put("tls", tls)
        // HTTP
        var httpOk = false
        if (tlsOk) {
            val h = JSONObject()
            try {
                val t3 = System.nanoTime()
                val c = URL("https://$host/").openConnection() as HttpsURLConnection
                c.connectTimeout = 6000; c.readTimeout = 6000; c.instanceFollowRedirects = true
                c.setRequestProperty("User-Agent", "Mozilla/5.0 (Linux; Android) CoreKit")
                val code = c.responseCode
                h.put("ok", code in 200..499).put("status", code).put("ms", ((System.nanoTime() - t3) / 1e6).roundToInt())
                    .put("final", c.url.toString()).put("server", c.getHeaderField("Server") ?: JSONObject.NULL)
                    .put("date", JSONObject.NULL).put("body", JSONObject.NULL).put("error", JSONObject.NULL).put("webStatus", JSONObject.NULL)
                c.disconnect()
                httpOk = code in 200..499
                if (!httpOk) cause = "The website answered with an error (HTTP $code). The problem is on the website's side."
            } catch (e: Throwable) {
                h.put("ok", false).put("error", e.message ?: "failed"); cause = "The website did not answer: ${e.message ?: "timeout"}"
            }
            o.put("http", h)
        } else o.put("http", JSONObject.NULL)
        return o.put("status", if (tlsOk && httpOk) "ok" else "fail").put("cause", if (tlsOk && httpOk) JSONObject.NULL else cause).put("fixes", fixes)
    }

    private fun cn(dn: String) = Regex("CN=([^,]+)").find(dn)?.groupValues?.get(1) ?: dn
    private fun org(dn: String) = Regex("O=([^,]+)").find(dn)?.groupValues?.get(1) ?: ""
    private fun r1(v: Double) = (v * 10).roundToInt() / 10.0
    private fun fmtSkew(s: Int) = if (abs(s) >= 3600) "${abs(s) / 3600} h ${abs(s) % 3600 / 60} min" else "${abs(s) / 60} min"
    private fun jsonList(a: JSONArray?): List<String> = if (a == null) emptyList() else (0 until a.length()).map { a.getString(it) }
}
