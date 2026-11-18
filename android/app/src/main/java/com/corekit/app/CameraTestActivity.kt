package com.corekit.app

import android.Manifest
import android.annotation.SuppressLint
import android.app.Activity
import android.app.AlertDialog
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.Color
import android.graphics.Matrix
import android.graphics.SurfaceTexture
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.hardware.camera2.CameraCaptureSession
import android.hardware.camera2.CameraCharacteristics
import android.hardware.camera2.CameraDevice
import android.hardware.camera2.CameraManager
import android.hardware.camera2.CaptureRequest
import android.hardware.camera2.TotalCaptureResult
import android.hardware.camera2.params.OutputConfiguration
import android.hardware.camera2.params.SessionConfiguration
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.HandlerThread
import android.os.Looper
import android.provider.MediaStore
import android.util.Base64
import android.util.Size
import android.util.TypedValue
import android.view.Gravity
import android.view.Surface
import android.view.TextureView
import android.view.View
import android.view.WindowManager
import android.widget.FrameLayout
import android.widget.GridLayout
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.core.view.ViewCompat
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.util.Locale
import java.util.concurrent.Executor
import kotlin.math.abs
import kotlin.math.roundToInt
import kotlin.math.sqrt

/**
 * Camera test for every lens. The web camera API only offers a phone's main front and back
 * cameras; the extra lenses (ultra-wide, telephoto, macro) are reached here through Camera2:
 * listed cameras, the physical lenses behind a "logical" multi-camera, and ids the phone
 * answers for without listing them. Each lens gets a tile with a real picture; tapping a
 * tile shows it live so the user can mark it. Nothing closes until Done.
 * Result (JSON, to the health page): {lenses:[{name, spec, state, mark, img}]}
 * state: ok | black | fail | off (not available to apps) | depth | wait (not checked)
 */
class CameraTestActivity : Activity() {
    private class Lens(
        val id: String, val parent: String?, val facing: Int, val mp: Double, val focal35: Double,
        val aperture: Float, val depthOnly: Boolean, val listed: Boolean, val orientation: Int, val sig: String,
        val openId: String = id, val zoom: Float = 1f, val manual: Boolean = false, val kind: String = "",
    ) {
        var name = ""; var spec = ""; var state = "wait"; var note = ""; var mark = 0
        var snap: Bitmap? = null
        lateinit var tile: LinearLayout; lateinit var img: ImageView; lateinit var status: TextView; lateinit var markV: TextView
    }

    private val main = Handler(Looper.getMainLooper())
    private val camThread = HandlerThread("cam").apply { start() }
    private val camH = Handler(camThread.looper)
    private val exec = Executor { camH.post(it) }
    private val cm by lazy { getSystemService(CameraManager::class.java) }

    private lateinit var viewer: TextureView
    private lateinit var viewName: TextView
    private lateinit var caption: TextView
    private lateinit var sub: TextView
    private lateinit var btnBad: TextView
    private lateinit var btnGood: TextView
    private lateinit var grid: GridLayout
    private lateinit var still: ImageView
    private lateinit var panel: LinearLayout
    private var plusTile: View? = null
    private var extra = 0
    private var autoIdx = 0
    private var resumeAuto = false

    private var lenses = listOf<Lens>()
    @Volatile private var device: CameraDevice? = null
    @Volatile private var session: CameraCaptureSession? = null
    @Volatile private var closedHook: (() -> Unit)? = null
    private var surface: Surface? = null
    private var openSeq = 0
    private var live: Lens? = null
    private var auto = false
    private var started = false
    private var surfaceReady = false
    private var permitted = false
    private var finished = false

    private fun dp(v: Float) = TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, v, resources.displayMetrics)
    private fun dpi(v: Float) = dp(v).roundToInt()

    // ---------------------------------------------------------------- screen

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        routeBack { done() }
        if (Prefs(this).captureShield) window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        WindowCompat.setDecorFitsSystemWindows(window, false)
        val root = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setBackgroundColor(MainActivity.BG) }
        ViewCompat.setOnApplyWindowInsetsListener(root) { v, ins ->
            val b = ins.getInsets(WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.displayCutout())
            v.setPadding(b.left, b.top, b.right, b.bottom); WindowInsetsCompat.CONSUMED
        }

        // top bar
        val bar = LinearLayout(this).apply { gravity = Gravity.CENTER_VERTICAL; setPadding(dpi(6f), dpi(6f), dpi(16f), dpi(6f)) }
        bar.addView(text("‹", 30f, WHITE).apply { setPadding(dpi(12f), 0, dpi(12f), dpi(4f)); setOnClickListener { done() } })
        val tt = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        tt.addView(text("Camera test", 18f, WHITE, true))
        sub = text("Looking for lenses…", 12.5f, MUTED); tt.addView(sub)
        bar.addView(tt, LinearLayout.LayoutParams(0, -2, 1f))
        bar.addView(text("Done", 14f, 0xFF04201C.toInt(), true).apply {
            background = round(ACC, ACC, 18f); setPadding(dpi(18f), dpi(8f), dpi(18f), dpi(8f)); setOnClickListener { done() }
        })
        root.addView(bar)

        // live viewer (portrait 3:4)
        val dm = resources.displayMetrics
        val vh = (dm.heightPixels * 0.40f).roundToInt()
        val vw = minOf((vh * 3f / 4f).roundToInt(), dm.widthPixels - dpi(32f))
        val box = FrameLayout(this).apply { background = round(0xFF05080B.toInt(), LINE, 14f); clipToOutline = true }
        viewer = TextureView(this)
        box.addView(viewer, FrameLayout.LayoutParams(-1, -1))
        still = ImageView(this).apply { scaleType = ImageView.ScaleType.CENTER_CROP; setBackgroundColor(0xFF05080B.toInt()); visibility = View.GONE }
        box.addView(still, FrameLayout.LayoutParams(-1, -1))
        panel = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL; setBackgroundColor(0xE6080C11.toInt()); setPadding(dpi(12f), dpi(12f), dpi(12f), dpi(12f)); visibility = View.GONE
            addView(text("Your phone keeps this lens for its own camera app. Tap Take photo, switch to this lens there (for example 0.5x, macro or 2x), take the photo, then mark it below.", 12.5f, WHITE))
            addView(text("Take photo", 14f, 0xFF04201C.toInt(), true).apply {
                gravity = Gravity.CENTER; background = round(ACC, ACC, 10f); setOnClickListener { takePhoto() }
            }, LinearLayout.LayoutParams(-1, dpi(40f)).apply { topMargin = dpi(10f) })
            addView(text("Open camera app", 13f, WHITE, true).apply {
                gravity = Gravity.CENTER; background = round(PANEL, LINE2, 10f); setOnClickListener { openCameraApp() }
            }, LinearLayout.LayoutParams(-1, dpi(38f)).apply { topMargin = dpi(8f) })
        }
        box.addView(panel, FrameLayout.LayoutParams(-1, -2, Gravity.BOTTOM))
        viewName = text("", 12f, Color.WHITE, true).apply {
            background = round(0xB3000000.toInt(), 0, 10f); setPadding(dpi(9f), dpi(4f), dpi(9f), dpi(4f)); visibility = View.GONE
        }
        box.addView(viewName, FrameLayout.LayoutParams(-2, -2, Gravity.TOP or Gravity.START).apply { setMargins(dpi(10f), dpi(10f), 0, 0) })
        root.addView(box, LinearLayout.LayoutParams(vw, (vw * 4f / 3f).roundToInt()).apply { gravity = Gravity.CENTER_HORIZONTAL; topMargin = dpi(4f) })

        caption = text("", 12.5f, MUTED).apply { gravity = Gravity.CENTER; setPadding(dpi(16f), dpi(8f), dpi(16f), dpi(6f)) }
        root.addView(caption)

        // mark the lens on screen
        val marks = LinearLayout(this).apply { setPadding(dpi(16f), 0, dpi(16f), dpi(8f)) }
        btnBad = text("✗  Problem", 14f, BAD, true).apply { gravity = Gravity.CENTER; setOnClickListener { markLive(-1) } }
        btnGood = text("✓  Looks good", 14f, ACC, true).apply { gravity = Gravity.CENTER; setOnClickListener { markLive(1) } }
        marks.addView(btnBad, LinearLayout.LayoutParams(0, dpi(42f), 1f).apply { marginEnd = dpi(8f) })
        marks.addView(btnGood, LinearLayout.LayoutParams(0, dpi(42f), 1f))
        root.addView(marks)
        paintMarks()

        // every lens
        grid = GridLayout(this).apply { columnCount = 3; setPadding(dpi(10f), 0, dpi(10f), dpi(12f)) }
        root.addView(ScrollView(this).apply { addView(grid) }, LinearLayout.LayoutParams(-1, 0, 1f))
        setContentView(root)

        viewer.surfaceTextureListener = object : TextureView.SurfaceTextureListener {
            override fun onSurfaceTextureAvailable(st: SurfaceTexture, w: Int, h: Int) { surfaceReady = true; maybeStart() }
            override fun onSurfaceTextureSizeChanged(st: SurfaceTexture, w: Int, h: Int) {}
            override fun onSurfaceTextureDestroyed(st: SurfaceTexture): Boolean { surfaceReady = false; return true }
            override fun onSurfaceTextureUpdated(st: SurfaceTexture) {}
        }
        if (checkSelfPermission(Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED) permitted = true
        else requestPermissions(arrayOf(Manifest.permission.CAMERA), REQ_CAMERA)
        maybeStart()
    }

    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode != REQ_CAMERA) return
        if (grantResults.firstOrNull() == PackageManager.PERMISSION_GRANTED) { permitted = true; maybeStart() }
        else finishWith(JSONObject().put("lenses", JSONArray()).put("error", "Camera permission was refused. Allow it in Settings › Apps › CoreKit › Permissions to test the cameras."))
    }

    private fun maybeStart() {
        if (started || !permitted || !surfaceReady) return
        started = true
        camH.post {
            val found = try { discover() } catch (_: Throwable) { emptyList() }
            main.post {
                if (finished) return@post
                if (found.isEmpty()) { finishWith(JSONObject().put("lenses", JSONArray()).put("error", "No camera found.")); return@post }
                lenses = found
                nameAll(found)
                buildTiles()
                sub.text = "${found.size} lens${if (found.size == 1) "" else "es"} found"
                auto = true
                autoCheck(0)
            }
        }
    }

    override fun onPause() {
        super.onPause()
        resumeAuto = auto
        auto = false; openSeq++
        closeCam {}
    }

    override fun onResume() {
        super.onResume()
        if (!started || finished || !surfaceReady) return
        if (resumeAuto) { resumeAuto = false; auto = true; autoCheck(autoIdx) } else live?.let { showLive(it) }
    }

    override fun onDestroy() {
        openSeq++
        closeCam {}
        camThread.quitSafely()
        super.onDestroy()
    }

    @Deprecated("Back returns the result to the health page")
    override fun onBackPressed() = done()

    // ---------------------------------------------------------------- lenses

    private fun discover(): List<Lens> {
        val out = LinkedHashMap<String, Lens>()
        val listed = try { cm.cameraIdList.toList() } catch (_: Throwable) { emptyList() }
        fun add(id: String, parent: String?, isListed: Boolean) {
            if (out.containsKey(id)) return
            val ch = try { cm.getCameraCharacteristics(id) } catch (_: Throwable) { return }
            val caps = ch.get(CameraCharacteristics.REQUEST_AVAILABLE_CAPABILITIES) ?: IntArray(0)
            val px = ch.get(CameraCharacteristics.SENSOR_INFO_PIXEL_ARRAY_SIZE)
            val phys = ch.get(CameraCharacteristics.SENSOR_INFO_PHYSICAL_SIZE)
            val f = ch.get(CameraCharacteristics.LENS_INFO_AVAILABLE_FOCAL_LENGTHS)?.firstOrNull() ?: 0f
            val ap = ch.get(CameraCharacteristics.LENS_INFO_AVAILABLE_APERTURES)?.firstOrNull() ?: 0f
            val mp = if (px != null) px.width * px.height / 1e6 else 0.0
            val diag = if (phys != null) sqrt((phys.width * phys.width + phys.height * phys.height).toDouble()) else 0.0
            val f35 = if (diag > 0 && f > 0) f * 43.27 / diag else 0.0
            val facing = ch.get(CameraCharacteristics.LENS_FACING) ?: CameraCharacteristics.LENS_FACING_BACK
            val depth = CameraCharacteristics.REQUEST_AVAILABLE_CAPABILITIES_DEPTH_OUTPUT in caps &&
                CameraCharacteristics.REQUEST_AVAILABLE_CAPABILITIES_BACKWARD_COMPATIBLE !in caps
            val sig = "$facing|${px?.width}x${px?.height}|$f|${phys?.width}"
            // an unlisted id that is only another way into a sensor we already have
            if (!isListed && out.values.any { it.sig == sig }) return
            out[id] = Lens(id, parent, facing, mp, f35, ap, depth, isListed, ch.get(CameraCharacteristics.SENSOR_ORIENTATION) ?: 90, sig)
            if (Build.VERSION.SDK_INT >= 28 && CameraCharacteristics.REQUEST_AVAILABLE_CAPABILITIES_LOGICAL_MULTI_CAMERA in caps) {
                for (pid in ch.physicalCameraIds) add(pid, id, false)
            }
        }
        for (id in listed) add(id, null, true)
        for (n in 0..63) add(n.toString(), null, false) // ids the phone answers for but does not list
        // Zooming below 1x can only use a separate ultra-wide lens; many phones offer it this way only.
        if (Build.VERSION.SDK_INT >= 30) {
            for (l in out.values.toList()) {
                if (!l.listed || l.depthOnly) continue
                if (out.values.any { it.facing == l.facing && it !== l && (it.kind == "Ultra-wide" || (it.focal35 > 0 && l.focal35 > 0 && it.focal35 < l.focal35 * 0.8)) }) continue
                val r = try { cm.getCameraCharacteristics(l.id).get(CameraCharacteristics.CONTROL_ZOOM_RATIO_RANGE) } catch (_: Throwable) { null } ?: continue
                if (r.lower >= 0.95f) continue
                val id = "${l.id}~uw"
                out[id] = Lens(id, null, l.facing, 0.0, if (l.focal35 > 0) l.focal35 * r.lower else 0.0, 0f, false, false, l.orientation, "zoom:$id",
                    openId = l.id, zoom = r.lower, kind = "Ultra-wide")
            }
        }
        return out.values.sortedBy { if (it.facing == CameraCharacteristics.LENS_FACING_FRONT) 1 else if (it.facing == CameraCharacteristics.LENS_FACING_BACK) 0 else 2 }
    }

    private fun nameAll(ls: List<Lens>) {
        for (face in listOf(CameraCharacteristics.LENS_FACING_BACK, CameraCharacteristics.LENS_FACING_FRONT, CameraCharacteristics.LENS_FACING_EXTERNAL)) {
            val g = ls.filter { it.facing == face }
            if (g.isEmpty()) continue
            val side = when (face) { CameraCharacteristics.LENS_FACING_FRONT -> "Front"; CameraCharacteristics.LENS_FACING_EXTERNAL -> "External"; else -> "Back" }
            val primary = g.filter { !it.depthOnly && it.zoom == 1f && it.kind.isEmpty() }.maxByOrNull { (if (it.focal35 == 0.0 || it.focal35 in 20.0..35.0) 10000.0 else 0.0) + it.mp }
            val mainF = primary?.focal35 ?: 0.0
            for (l in g) {
                val kind = when {
                    l.kind.isNotEmpty() -> l.kind
                    l.depthOnly -> "Depth sensor"
                    l === primary -> if (g.size > 1) "Main" else ""
                    l.focal35 > 0 && l.focal35 < 20 -> "Ultra-wide"
                    mainF > 0 && l.focal35 > mainF * 1.6 -> "Telephoto ${zoom(l.focal35 / mainF)}"
                    l.mp in 0.1..5.5 -> "Macro or depth"
                    else -> "Wide"
                }
                l.name = if (kind.isEmpty()) side else "$side · $kind"
                l.spec = listOfNotNull(
                    if (l.zoom != 1f) String.format(Locale.US, "%.1fx zoom", l.zoom) else null,
                    if (l.mp > 0) (if (l.mp >= 10) "${l.mp.roundToInt()} MP" else String.format(Locale.US, "%.1f MP", l.mp)) else null,
                    if (l.focal35 > 0) "${l.focal35.roundToInt()} mm" else null,
                    if (l.aperture > 0) String.format(Locale.US, "f/%.1f", l.aperture) else null,
                ).joinToString(" · ")
            }
        }
        ls.groupBy { it.name }.filter { it.value.size > 1 }.forEach { (_, v) -> v.forEachIndexed { i, l -> l.name += " ${i + 1}" } }
    }

    private fun zoom(z: Double): String = if (abs(z - z.roundToInt()) < 0.15) "${z.roundToInt()}x" else String.format(Locale.US, "%.1fx", z)

    private val tileW get() = (resources.displayMetrics.widthPixels - dpi(20f) - dpi(12f) * 3) / 3

    private fun buildTiles() {
        grid.removeAllViews()
        for (l in lenses) addTile(l)
        addPlusTile()
    }

    private fun addTile(l: Lens) {
        val tw = tileW
        run {
            val t = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(0, 0, 0, dpi(8f)); clipToOutline = true }
            l.img = ImageView(this).apply { scaleType = ImageView.ScaleType.CENTER_CROP; setBackgroundColor(0xFF05080B.toInt()) }
            t.addView(l.img, LinearLayout.LayoutParams(-1, (tw * 4f / 3f).roundToInt()))
            t.addView(text(l.name, 12f, WHITE, true).apply { setPadding(dpi(8f), dpi(6f), dpi(6f), 0); maxLines = 2 })
            if (l.spec.isNotEmpty()) t.addView(text(l.spec, 10.5f, MUTED).apply { setPadding(dpi(8f), dpi(1f), dpi(6f), 0) })
            l.status = text("Waiting", 10.5f, MUTED).apply { setPadding(dpi(8f), dpi(2f), dpi(6f), 0) }
            t.addView(l.status)
            l.markV = text("", 11f, MUTED, true).apply { setPadding(dpi(8f), dpi(2f), dpi(6f), 0); visibility = View.GONE }
            t.addView(l.markV)
            t.setOnClickListener { if (!l.depthOnly) { auto = false; showLive(l) } }
            l.tile = t
            grid.addView(t, GridLayout.LayoutParams().apply { width = tw; setMargins(dpi(6f), dpi(6f), dpi(6f), dpi(6f)) })
            paintTile(l)
        }
    }

    /** "+ Add a lens": for lenses the phone hides from apps, checked through its own camera app. */
    private fun addPlusTile() {
        val tw = tileW
        val t = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL; gravity = Gravity.CENTER; background = round(PANEL, LINE2, 12f)
            setPadding(dpi(6f), dpi(10f), dpi(6f), dpi(10f))
            addView(text("+", 30f, ACC, true).apply { gravity = Gravity.CENTER })
            addView(text("Add a lens", 12f, WHITE, true).apply { gravity = Gravity.CENTER })
            addView(text("Lens missing? Check it in the camera app", 10.5f, MUTED).apply { gravity = Gravity.CENTER })
            setOnClickListener {
                AlertDialog.Builder(this@CameraTestActivity, android.R.style.Theme_DeviceDefault_Dialog_Alert)
                    .setTitle("Which side is the lens on?")
                    .setItems(arrayOf("Back", "Front")) { _, w -> addManual(if (w == 1) CameraCharacteristics.LENS_FACING_FRONT else CameraCharacteristics.LENS_FACING_BACK) }
                    .show()
            }
        }
        plusTile = t
        grid.addView(t, GridLayout.LayoutParams().apply { width = tw; height = (tw * 4f / 3f).roundToInt() + dpi(50f); setMargins(dpi(6f), dpi(6f), dpi(6f), dpi(6f)) })
    }

    private fun addManual(facing: Int) {
        extra++
        val side = if (facing == CameraCharacteristics.LENS_FACING_FRONT) "Front" else "Back"
        val l = Lens("manual$extra", null, facing, 0.0, 0.0, 0f, false, false, 90, "manual$extra", manual = true)
        l.name = "$side · Extra lens ${lenses.count { it.manual && it.facing == facing } + 1}"
        l.spec = ""; l.state = "manual"
        lenses = lenses + l
        plusTile?.let { grid.removeView(it) }
        addTile(l); addPlusTile()
        sub.text = "${lenses.size} lenses"
        auto = false
        showLive(l)
    }

    private fun takePhoto() {
        try { startActivityForResult(Intent(MediaStore.ACTION_IMAGE_CAPTURE), REQ_PHOTO) }
        catch (_: Throwable) { caption.text = "No camera app was found to take the photo." }
    }

    private fun openCameraApp() {
        try { startActivity(Intent(MediaStore.INTENT_ACTION_STILL_IMAGE_CAMERA)) }
        catch (_: Throwable) { caption.text = "No camera app was found." }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode != REQ_PHOTO || resultCode != RESULT_OK) return
        @Suppress("DEPRECATION")
        val b = data?.extras?.get("data") as? Bitmap ?: return
        val l = live ?: return
        if (!l.manual) return
        l.snap = b
        still.setImageBitmap(b)
        paintTile(l)
        caption.text = "Photo received. Is it clear, in focus and free of spots? Mark it below."
    }

    private fun paintTile(l: Lens) {
        val sel = l === live
        val bad = l.state == "fail" || l.mark == -1 || (l.state == "black" && l.mark != 1)
        val stroke = when { sel -> ACC; bad -> 0xFF5A1F26.toInt(); l.state == "ok" -> 0xFF1F5A52.toInt(); else -> LINE }
        l.tile.background = round(0xFF0B1016.toInt(), stroke, 12f, if (sel) 2f else 1f)
        l.status.text = when (l.state) {
            "ok" -> "Working"; "black" -> "Black picture (covered?)"; "fail" -> "Could not open"
            "off" -> "Not available to apps"; "depth" -> "Depth sensor (no picture)"; "checking" -> "Checking…"
            "manual" -> if (l.snap != null) "Photo from camera app" else "Check in camera app"; else -> "Waiting"
        }
        l.status.setTextColor(when (l.state) { "fail", "black" -> BAD; "ok" -> ACC; else -> MUTED })
        l.markV.visibility = if (l.mark == 0) View.GONE else View.VISIBLE
        l.markV.text = if (l.mark == 1) "✓ Marked good" else "✗ Marked problem"
        l.markV.setTextColor(if (l.mark == 1) ACC else BAD)
        l.snap?.let { l.img.setImageBitmap(it) }
    }

    private fun setState(l: Lens, st: String, note: String = "") { l.state = st; l.note = note; paintTile(l); updateSummary() }

    /** Running result under the title: working, problems, still to mark. */
    private fun updateSummary() {
        val use = lenses.filter { it.state != "off" && it.state != "depth" && !(it.manual && it.mark == 0) }
        val bad = use.count { it.state == "fail" || it.mark == -1 || (it.state == "black" && it.mark != 1) }
        val todo = lenses.count { it.mark == 0 && (it.state == "ok" || it.state == "black" || it.manual) }
        sub.text = "${lenses.size} lenses · ${use.size - bad} OK · $bad problem${if (bad == 1) "" else "s"}" + if (todo > 0) " · $todo to mark" else ""
    }

    // ---------------------------------------------------------------- checking and live view

    /** Goes through every lens once: open it, keep a picture, move on. */
    private fun autoCheck(i: Int) {
        if (!auto || finished) return
        autoIdx = i
        val l = lenses.getOrNull(i)
        if (l == null) { auto = false; afterAuto(); return }
        if (l.manual) { autoCheck(i + 1); return }
        if (l.depthOnly) { setState(l, "depth"); autoCheck(i + 1); return }
        select(l)
        setState(l, "checking")
        caption.text = "Checking ${l.name}… (${i + 1} of ${lenses.size})"
        openLens(l, onFrame = {
            main.postDelayed({
                if (!auto || live !== l) return@postDelayed
                snapshot(l)
                autoCheck(i + 1)
            }, 1300)
        }, onFail = { why ->
            setState(l, if (l.listed) "fail" else "off", why)
            if (auto) autoCheck(i + 1)
        })
    }

    private fun afterAuto() {
        val ok = lenses.count { it.state == "ok" }
        val first = lenses.firstOrNull { it.state == "ok" || it.state == "black" }
        val back = lenses.count { it.facing == CameraCharacteristics.LENS_FACING_BACK && !it.manual }
        caption.text = "$ok of ${lenses.count { !it.depthOnly && !it.manual }} lenses gave a picture. Tap a lens to see it live and mark it. " +
            "This phone lets apps use $back back lens${if (back == 1) "" else "es"}; if it has more, tap + Add a lens."
        if (first != null) showLive(first) else { viewName.visibility = View.GONE }
    }

    /** Shows [l] live in the viewer (after keeping a picture of the lens that was live). */
    private fun showLive(l: Lens) {
        live?.let { if (it !== l && it.state == "ok") snapshot(it) }
        select(l)
        if (l.manual) {
            openSeq++; closeCam {}
            caption.text = if (l.snap == null) "Take a photo with this lens in the camera app, then mark it." else "Is the photo clear, in focus and free of spots? Mark it below."
            return
        }
        if (!auto) caption.text = "Opening ${l.name}…"
        openLens(l, onFrame = {
            if (l.state != "black") setState(l, "ok")
            if (!auto) caption.text = "Is the picture clear, in focus and free of spots? Mark it below."
        }, onFail = { why ->
            setState(l, if (l.listed) "fail" else "off", why)
            if (!auto) caption.text = if (l.listed) "${l.name} could not be opened ($why)." else "${l.name} is not available to apps on this phone (the phone maker keeps it for its own camera app)."
        })
    }

    private fun select(l: Lens) {
        val prev = live
        live = l
        prev?.let { paintTile(it) }
        paintTile(l)
        viewName.text = l.name
        viewName.visibility = View.VISIBLE
        panel.visibility = if (l.manual) View.VISIBLE else View.GONE
        still.visibility = if (l.manual) View.VISIBLE else View.GONE
        still.setImageBitmap(if (l.manual) l.snap else null)
        paintMarks()
    }

    private fun markLive(v: Int) {
        val l = live ?: return
        if (l.state == "off" || l.state == "depth") return
        l.mark = if (l.mark == v) 0 else v
        if (l.state == "ok") snapshot(l)
        paintTile(l); paintMarks()
        updateSummary()
        if (l.mark != 0) {
            // go on to the next lens that still needs a mark
            val next = lenses.firstOrNull { it.mark == 0 && (it.state == "ok" || it.state == "black" || it.manual) }
            if (next != null) main.postDelayed({ if (!finished && live === l) showLive(next) }, 350)
            else caption.text = "All lenses marked. Tap Done to see the result."
        }
    }

    private fun paintMarks() {
        val m = live?.mark ?: 0
        btnBad.background = round(if (m == -1) 0xFF2E0F14.toInt() else PANEL, if (m == -1) 0xFF5A1F26.toInt() else LINE2, 10f)
        btnGood.background = round(if (m == 1) 0xFF0F2E2A.toInt() else PANEL, if (m == 1) 0xFF1F5A52.toInt() else LINE2, 10f)
    }

    private fun snapshot(l: Lens) {
        if (!surfaceReady || live !== l) return
        val b = try { viewer.getBitmap(240, 320) } catch (_: Throwable) { null } ?: return
        l.snap = b
        if (isBlack(b) && l.state != "black") l.state = "black" else if (!isBlack(b) && l.state != "ok") l.state = "ok"
        paintTile(l)
    }

    private fun isBlack(b: Bitmap): Boolean {
        var sum = 0L; var n = 0
        for (y in 0 until b.height step 8) for (x in 0 until b.width step 8) {
            val c = b.getPixel(x, y); sum += (Color.red(c) * 3 + Color.green(c) * 6 + Color.blue(c)) / 10; n++
        }
        return n > 0 && sum / n < 6
    }

    // ---------------------------------------------------------------- Camera2

    /** Closes the open camera and calls [then] once it is really closed (the next lens may need it). */
    private fun closeCam(then: () -> Unit) {
        val d = device
        try { session?.close() } catch (_: Throwable) {}
        session = null; device = null
        if (d == null) { then(); return }
        var fired = false
        val go = { if (!fired) { fired = true; then() } }
        closedHook = { main.post { go() } }
        try { d.close() } catch (_: Throwable) {}
        main.postDelayed({ go() }, 1500)
    }

    @SuppressLint("MissingPermission")
    private fun openLens(l: Lens, onFrame: () -> Unit, onFail: (String) -> Unit) {
        val seq = ++openSeq
        var settled = false
        fun fail(why: String) = main.post {
            if (seq != openSeq || settled) return@post
            settled = true; closeCam {}; onFail(why)
        }
        fun frame() = main.post { if (seq == openSeq && !settled) { settled = true; onFrame() } }
        closeCam {
            if (seq != openSeq || finished) return@closeCam
            val st = viewer.surfaceTexture
            if (st == null) { fail("no picture surface"); return@closeCam }
            val size = previewSize(l)
            st.setDefaultBufferSize(size.width, size.height)
            fitViewer(size, l.orientation)
            surface?.release()
            val sf = Surface(st).also { surface = it }
            main.postDelayed({ fail("no picture"); Unit }, 7000)
            fun start(dev: CameraDevice, physical: String?) {
                val cb = object : CameraCaptureSession.StateCallback() {
                    override fun onConfigured(s: CameraCaptureSession) {
                        if (seq != openSeq) { s.close(); return }
                        session = s
                        try {
                            val req = dev.createCaptureRequest(CameraDevice.TEMPLATE_PREVIEW).apply {
                                addTarget(sf); set(CaptureRequest.CONTROL_MODE, CaptureRequest.CONTROL_MODE_AUTO)
                                if (l.zoom != 1f && Build.VERSION.SDK_INT >= 30) set(CaptureRequest.CONTROL_ZOOM_RATIO, l.zoom)
                            }.build()
                            s.setRepeatingRequest(req, object : CameraCaptureSession.CaptureCallback() {
                                var n = 0
                                override fun onCaptureCompleted(s: CameraCaptureSession, r: CaptureRequest, res: TotalCaptureResult) { if (++n == 3) frame() }
                            }, camH)
                        } catch (e: Throwable) { fail(e.message ?: "error") }
                    }
                    override fun onConfigureFailed(s: CameraCaptureSession) { fail("the phone refused this lens on its own") }
                }
                try {
                    if (physical != null && Build.VERSION.SDK_INT >= 28) {
                        val oc = OutputConfiguration(sf)
                        oc.setPhysicalCameraId(physical)
                        dev.createCaptureSession(SessionConfiguration(SessionConfiguration.SESSION_REGULAR, listOf(oc), exec, cb))
                    } else {
                        @Suppress("DEPRECATION")
                        dev.createCaptureSession(listOf(sf), cb, camH)
                    }
                } catch (e: Throwable) { fail(e.message ?: "error") }
            }
            try {
                cm.openCamera(l.parent ?: l.openId, object : CameraDevice.StateCallback() {
                    override fun onOpened(d: CameraDevice) {
                        if (seq != openSeq) { d.close(); return }
                        device = d
                        start(d, if (l.parent != null) l.id else null)
                    }
                    override fun onDisconnected(d: CameraDevice) { d.close(); fail("in use by another app") }
                    override fun onError(d: CameraDevice, error: Int) { d.close(); fail(if (error == CameraDevice.StateCallback.ERROR_CAMERA_DISABLED) "blocked by the phone" else "camera error $error") }
                    override fun onClosed(d: CameraDevice) { closedHook?.invoke(); closedHook = null }
                }, camH)
            } catch (e: SecurityException) { fail("blocked by the phone") } catch (e: Throwable) { fail(e.message ?: "error") }
        }
    }

    private fun previewSize(l: Lens): Size {
        fun sizes(id: String): Array<Size>? = try {
            cm.getCameraCharacteristics(id).get(CameraCharacteristics.SCALER_STREAM_CONFIGURATION_MAP)?.getOutputSizes(SurfaceTexture::class.java)
        } catch (_: Throwable) { null }
        val all = (sizes(l.openId) ?: l.parent?.let { sizes(it) } ?: emptyArray()).filter { it.width <= 1600 && it.height <= 1200 }
        val four3 = all.filter { abs(it.width * 3 - it.height * 4) < 8 }
        return four3.ifEmpty { all }.maxByOrNull { it.width * it.height } ?: Size(1280, 960)
    }

    /** Fills the 3:4 viewer without stretching (centre crop). */
    private fun fitViewer(s: Size, orient: Int) = main.post {
        val vw = viewer.width.toFloat(); val vh = viewer.height.toFloat()
        if (vw == 0f || vh == 0f) return@post
        val ca = if (orient % 180 == 90) s.height.toFloat() / s.width else s.width.toFloat() / s.height
        val va = vw / vh
        val m = Matrix()
        if (ca > va) m.setScale(ca / va, 1f, vw / 2, vh / 2) else m.setScale(1f, va / ca, vw / 2, vh / 2)
        viewer.setTransform(m)
    }

    // ---------------------------------------------------------------- result

    private fun done() {
        if (finished) return
        live?.let { if (it.state == "ok") snapshot(it) }
        val arr = JSONArray()
        for (l in lenses) {
            val o = JSONObject().put("name", l.name).put("spec", l.spec).put("state", if (l.state == "checking") "wait" else l.state).put("mark", l.mark)
            if (l.note.isNotEmpty()) o.put("note", l.note)
            l.snap?.let { o.put("img", "data:image/jpeg;base64," + jpeg(it)) }
            arr.put(o)
        }
        finishWith(JSONObject().put("lenses", arr))
    }

    private fun finishWith(r: JSONObject) {
        if (finished) return
        finished = true; auto = false; openSeq++
        setResult(RESULT_OK, Intent().putExtra("result", r.toString()))
        finish()
    }

    private fun jpeg(b: Bitmap): String {
        val small = Bitmap.createScaledBitmap(b, 180, 240, true)
        val out = ByteArrayOutputStream()
        small.compress(Bitmap.CompressFormat.JPEG, 72, out)
        return Base64.encodeToString(out.toByteArray(), Base64.NO_WRAP)
    }

    // ---------------------------------------------------------------- small helpers

    private fun text(s: String, sp: Float, color: Int, bold: Boolean = false) = TextView(this).apply {
        text = s; setTextSize(TypedValue.COMPLEX_UNIT_SP, sp); setTextColor(color)
        if (bold) typeface = Typeface.DEFAULT_BOLD
    }

    private fun round(fill: Int, stroke: Int, radius: Float, strokeDp: Float = 1f) = GradientDrawable().apply {
        setColor(fill); cornerRadius = dp(radius)
        if (stroke != 0) setStroke(dp(strokeDp).roundToInt().coerceAtLeast(1), stroke)
    }

    companion object {
        private const val REQ_CAMERA = 21
        private const val REQ_PHOTO = 22
        private const val WHITE = 0xFFF0F6FC.toInt()
        private const val MUTED = 0xFF8B98A5.toInt()
        private const val ACC = 0xFF2DD4BF.toInt()
        private const val BAD = 0xFFFCA5A5.toInt()
        private const val PANEL = 0xFF10161E.toInt()
        private const val LINE = 0xFF1A2431.toInt()
        private const val LINE2 = 0xFF243142.toInt()
    }
}
