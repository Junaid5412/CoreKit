package com.corekit.app

import android.accessibilityservice.AccessibilityService
import android.accessibilityservice.GestureDescription
import android.content.ComponentName
import android.content.Context
import android.graphics.Path
import android.hardware.display.DisplayManager
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.util.DisplayMetrics
import android.view.Display
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityNodeInfo
import org.json.JSONObject
import kotlin.math.abs
import kotlin.math.max
import kotlin.math.min

/**
 * "CoreKit Remote control" (Settings › Accessibility). It only performs taps, swipes,
 * Back/Home/Recents and typing that arrive from an approved Remote Access session
 * (RemoteService forwards them). It reads nothing on its own and does nothing while
 * no session is running.
 */
class RemoteControlService : AccessibilityService() {

    companion object {
        @Volatile var instance: RemoteControlService? = null; private set

        fun isOn(ctx: Context): Boolean {
            if (instance != null) return true
            val want = ComponentName(ctx, RemoteControlService::class.java).flattenToString()
            val list = Settings.Secure.getString(ctx.contentResolver, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES) ?: return false
            return list.split(':').any { it.equals(want, ignoreCase = true) }
        }
    }

    override fun onServiceConnected() {
        instance = this
        RemoteEngine.cmd(this, JSONObject().put("t", "glue").put("a11y", true).toString())
    }

    override fun onUnbind(intent: android.content.Intent?): Boolean {
        instance = null
        RemoteEngine.cmd(this, JSONObject().put("t", "glue").put("a11y", false).toString())
        return super.onUnbind(intent)
    }

    override fun onDestroy() { instance = null; super.onDestroy() }
    override fun onAccessibilityEvent(event: AccessibilityEvent?) {}
    override fun onInterrupt() {}

    private fun screen(): Pair<Int, Int> {
        val dm = DisplayMetrics()
        val d = (getSystemService(Context.DISPLAY_SERVICE) as DisplayManager).getDisplay(Display.DEFAULT_DISPLAY)
        @Suppress("DEPRECATION") d.getRealMetrics(dm)
        return dm.widthPixels to dm.heightPixels
    }

    /** Performs one input event from the viewer (x, y are 0..1 of the screen). */
    fun perform(ev: JSONObject) {
        val (w, h) = screen()
        fun px(k: String) = (ev.optDouble(k, 0.5).coerceIn(0.0, 1.0) * w).toFloat()
        fun py(k: String) = (ev.optDouble(k, 0.5).coerceIn(0.0, 1.0) * h).toFloat()
        when (ev.optString("k")) {
            "tap" -> tap(px("x"), py("y"), 40)
            "click" -> if (ev.optInt("b") == 2) tap(px("x"), py("y"), 650) else tap(px("x"), py("y"), 40)
            "long" -> tap(px("x"), py("y"), 650)
            "dbl" -> { tap(px("x"), py("y"), 40); android.os.Handler(mainLooper).postDelayed({ tap(px("x"), py("y"), 40) }, 120) }
            "swipe" -> swipe(px("x"), py("y"), px("x2"), py("y2"), ev.optLong("ms", 300).coerceIn(80, 1500))
            "scroll", "wheel" -> {
                val dy = ev.optDouble("dy", 0.0)
                if (abs(dy) < 1) return
                val x = px("x"); val y = py("y").coerceIn(h * 0.2f, h * 0.8f)
                val dist = min(h * 0.55f, max(90f, abs(dy).toFloat() * 2.2f))
                val y2 = if (dy > 0) max(h * 0.08f, y - dist) else min(h * 0.92f, y + dist)
                swipe(x, y, x, y2, 260)
            }
            "nav" -> performGlobalAction(when (ev.optString("a")) {
                "home" -> GLOBAL_ACTION_HOME
                "recents" -> GLOBAL_ACTION_RECENTS
                "notifications" -> GLOBAL_ACTION_NOTIFICATIONS
                else -> GLOBAL_ACTION_BACK
            })
            "text" -> typeText(ev.optString("s"))
            "key" -> when (ev.optString("key")) {
                "Backspace" -> backspace()
                "Enter" -> enter()
                "Escape" -> performGlobalAction(GLOBAL_ACTION_BACK)
            }
        }
    }

    private fun tap(x: Float, y: Float, ms: Long) {
        val p = Path().apply { moveTo(x, y) }
        dispatchGesture(GestureDescription.Builder().addStroke(GestureDescription.StrokeDescription(p, 0, ms)).build(), null, null)
    }

    private fun swipe(x: Float, y: Float, x2: Float, y2: Float, ms: Long) {
        val p = Path().apply { moveTo(x, y); lineTo(x2, y2) }
        dispatchGesture(GestureDescription.Builder().addStroke(GestureDescription.StrokeDescription(p, 0, ms)).build(), null, null)
    }

    private fun focused(): AccessibilityNodeInfo? = try { rootInActiveWindow?.findFocus(AccessibilityNodeInfo.FOCUS_INPUT) } catch (_: Throwable) { null }

    private fun currentText(n: AccessibilityNodeInfo): String {
        if (Build.VERSION.SDK_INT >= 26 && n.isShowingHintText) return ""
        return n.text?.toString() ?: ""
    }

    private fun setText(n: AccessibilityNodeInfo, s: String) {
        val args = Bundle().apply { putCharSequence(AccessibilityNodeInfo.ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE, s) }
        n.performAction(AccessibilityNodeInfo.ACTION_SET_TEXT, args)
        val sel = Bundle().apply { putInt(AccessibilityNodeInfo.ACTION_ARGUMENT_SELECTION_START_INT, s.length); putInt(AccessibilityNodeInfo.ACTION_ARGUMENT_SELECTION_END_INT, s.length) }
        n.performAction(AccessibilityNodeInfo.ACTION_SET_SELECTION, sel)
    }

    private fun typeText(s: String) {
        if (s.isEmpty() || s.length > 2000) return
        val n = focused() ?: return
        if (!n.isEditable) return
        setText(n, currentText(n) + s)
    }

    private fun backspace() {
        val n = focused() ?: return
        val t = currentText(n)
        if (t.isNotEmpty()) setText(n, t.substring(0, t.offsetByCodePoints(t.length, -1)))
    }

    private fun enter() {
        val n = focused() ?: return
        if (Build.VERSION.SDK_INT >= 30) n.performAction(AccessibilityNodeInfo.AccessibilityAction.ACTION_IME_ENTER.id)
        else if (n.isMultiLine) setText(n, currentText(n) + "\n")
    }
}
