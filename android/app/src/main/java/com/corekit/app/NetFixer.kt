package com.corekit.app

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import org.json.JSONArray
import org.json.JSONObject

/**
 * Android repairs. Android does not let apps change system network settings, so a repair
 * opens the exact settings screen (and copies values to paste, e.g. the Private DNS name).
 */
class NetFixer(private val act: MainActivity) {
    companion object {
        private val ALLOWED = Regex("^(dns:(cloudflare|google|quad9|opendns|auto)|open:(wifi|privatedns|datetime|portal|network|mobile|vpn)|flushdns)$")
        fun allowed(a: String) = ALLOWED.matches(a)
        private val PRIVATE_DNS = mapOf("cloudflare" to "one.one.one.one", "google" to "dns.google", "quad9" to "dns.quad9.net", "opendns" to "dns.opendns.com")
    }

    fun run(actions: List<String>, emit: (type: String, kind: String, text: String, pct: Int) -> Unit): JSONObject {
        val res = JSONArray()
        actions.forEachIndexed { i, a ->
            val pct = (i + 1) * 100 / actions.size
            emit("progress", "", label(a), pct)
            val (ok, msg) = apply(a)
            emit("log", if (ok) "+" else "!", msg, pct)
            res.put(JSONObject().put("id", a).put("ok", ok).put("msg", msg))
            Thread.sleep(400)
        }
        return JSONObject().put("results", res).put("reboot", false)
    }

    private fun label(a: String) = when {
        a.startsWith("dns:") -> "Setting up Private DNS"
        a.startsWith("open:") -> "Opening settings"
        else -> "Working"
    }

    private fun apply(a: String): Pair<Boolean, String> {
        return when {
            a == "dns:auto" -> { open("privatedns"); true to "Private DNS settings opened: choose Automatic." }
            a.startsWith("dns:") -> {
                val name = PRIVATE_DNS[a.removePrefix("dns:")] ?: "one.one.one.one"
                act.runOnUiThread {
                    (act.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager)
                        .setPrimaryClip(ClipData.newPlainText("Private DNS", name))
                }
                open("privatedns")
                true to "Copied \"$name\". In Private DNS choose \"Private DNS provider hostname\" and paste it."
            }
            a.startsWith("open:") -> { open(a.removePrefix("open:")); true to "Settings opened." }
            a == "flushdns" -> true to "Android refreshes its DNS cache automatically."
            else -> false to "Not available on Android."
        }
    }

    private fun open(what: String) = act.runOnUiThread { HostSettings.open(act, what) }
}
