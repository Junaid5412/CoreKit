//go:build windows

package main

// Windows side of CoreKit Remote: GDI screen capture (with the mouse pointer drawn in),
// SendInput for mouse and keyboard, and a firewall rule so a phone on the same Wi-Fi
// can reach this PC while it is sharing.

import (
	"bytes"
	"encoding/binary"
	"hash/fnv"
	"image"
	"image/jpeg"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"
)

var (
	rpGetDC              = user32.NewProc("GetDC")
	rpReleaseDC          = user32.NewProc("ReleaseDC")
	rpGetCursorInfo      = user32.NewProc("GetCursorInfo")
	rpGetIconInfo        = user32.NewProc("GetIconInfo")
	rpDrawIconEx         = user32.NewProc("DrawIconEx")
	rpSendInput          = user32.NewProc("SendInput")
	rpVkKeyScanW         = user32.NewProc("VkKeyScanW")
	rpCreateCompatibleDC = gdi32.NewProc("CreateCompatibleDC")
	rpCreateCompatBitmap = gdi32.NewProc("CreateCompatibleBitmap")
	rpSelectObject       = gdi32.NewProc("SelectObject")
	rpStretchBlt         = gdi32.NewProc("StretchBlt")
	rpSetStretchBltMode  = gdi32.NewProc("SetStretchBltMode")
	rpSetBrushOrgEx      = gdi32.NewProc("SetBrushOrgEx")
	rpGetDIBits          = gdi32.NewProc("GetDIBits")
	rpDeleteObject       = gdi32.NewProc("DeleteObject")
	rpDeleteDC           = gdi32.NewProc("DeleteDC")
)

var rDPIOnce sync.Once

func rDeviceName() string {
	if n := os.Getenv("COMPUTERNAME"); n != "" {
		return n
	}
	h, _ := os.Hostname()
	return h
}
func rPlatform() string                    { return "windows" }
func rCanControl(e *rEngine) bool          { return true }
func rQualityChanged(e *rEngine, q string) {}

func rScreenSize(e *rEngine) (int, int) {
	rDPIOnce.Do(setDPIAwareness)
	return screenSize()
}

// rPrepareHost allows CoreKit through the Windows firewall (only this program, and it
// only listens while sharing), so the phone's connection isn't silently dropped.
func rPrepareHost() {
	rDPIOnce.Do(setDPIAwareness)
	if !isAdmin() {
		return
	}
	exe, err := os.Executable()
	if err != nil {
		return
	}
	netsh := os.Getenv("SystemRoot") + `\System32\netsh.exe`
	run := func(args ...string) {
		c := exec.Command(netsh, args...)
		c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
		_ = c.Run()
	}
	run("advfirewall", "firewall", "delete", "rule", "name=CoreKit Remote")
	run("advfirewall", "firewall", "add", "rule", "name=CoreKit Remote", "dir=in", "action=allow", "program="+exe, "enable=yes", "profile=any", "description=CoreKit Remote Access (listens only while you share this PC)")
}

// ---------------------------------------------------------------- capture

type winCap struct {
	memDC, bmp uintptr
	w, h       int
	buf        []byte
	img        *image.RGBA
	last       uint64
	lastAt     time.Time
}

func rNewCapturer(e *rEngine) rCapturer {
	rDPIOnce.Do(setDPIAwareness)
	dc, _, _ := rpCreateCompatibleDC.Call(0)
	return &winCap{memDC: dc}
}

func (c *winCap) close() {
	if c.bmp != 0 {
		rpDeleteObject.Call(c.bmp)
	}
	if c.memDC != 0 {
		rpDeleteDC.Call(c.memDC)
	}
}

func (c *winCap) grab(q rQuality) ([]byte, int, int, error) {
	sw, sh := screenSize()
	if sw <= 0 || sh <= 0 {
		return nil, 0, 0, nil
	}
	tw, th := sw, sh
	if tw > q.maxW {
		tw, th = q.maxW, sh*q.maxW/sw
	}
	tw &^= 1
	th &^= 1
	scr, _, _ := rpGetDC.Call(0)
	if scr == 0 {
		return nil, 0, 0, nil
	}
	defer rpReleaseDC.Call(0, scr)
	if c.bmp == 0 || c.w != tw || c.h != th {
		if c.bmp != 0 {
			rpDeleteObject.Call(c.bmp)
		}
		c.bmp, _, _ = rpCreateCompatBitmap.Call(scr, uintptr(tw), uintptr(th))
		c.w, c.h = tw, th
		c.buf = make([]byte, tw*th*4)
		c.img = image.NewRGBA(image.Rect(0, 0, tw, th))
	}
	old, _, _ := rpSelectObject.Call(c.memDC, c.bmp)
	rpSetStretchBltMode.Call(c.memDC, 4) // HALFTONE: smooth downscale
	rpSetBrushOrgEx.Call(c.memDC, 0, 0, 0)
	rpStretchBlt.Call(c.memDC, 0, 0, uintptr(tw), uintptr(th), scr, 0, 0, uintptr(sw), uintptr(sh), 0x00CC0020|0x40000000) // SRCCOPY|CAPTUREBLT
	c.drawCursor(sw, sh, tw, th)
	rpSelectObject.Call(c.memDC, old)

	// BITMAPINFOHEADER: top-down 32-bit
	var bi [40]byte
	binary.LittleEndian.PutUint32(bi[0:], 40)
	binary.LittleEndian.PutUint32(bi[4:], uint32(int32(tw)))
	binary.LittleEndian.PutUint32(bi[8:], uint32(int32(-th)))
	binary.LittleEndian.PutUint16(bi[12:], 1)
	binary.LittleEndian.PutUint16(bi[14:], 32)
	if r, _, _ := rpGetDIBits.Call(c.memDC, c.bmp, 0, uintptr(th), uintptr(unsafe.Pointer(&c.buf[0])), uintptr(unsafe.Pointer(&bi[0])), 0); r == 0 {
		return nil, 0, 0, nil
	}
	// skip unchanged screens (but refresh every 2 s)
	h := fnv.New64a()
	for i := 0; i < len(c.buf); i += 4 * 61 {
		h.Write(c.buf[i : i+3])
	}
	sum := h.Sum64()
	if sum == c.last && time.Since(c.lastAt) < 2*time.Second {
		return nil, 0, 0, nil
	}
	c.last, c.lastAt = sum, time.Now()
	px := c.img.Pix
	for i := 0; i+3 < len(c.buf); i += 4 { // BGRA → RGBA
		px[i], px[i+1], px[i+2], px[i+3] = c.buf[i+2], c.buf[i+1], c.buf[i], 255
	}
	var out bytes.Buffer
	if err := jpeg.Encode(&out, c.img, &jpeg.Options{Quality: q.jpegQ}); err != nil {
		return nil, 0, 0, err
	}
	return out.Bytes(), tw, th, nil
}

// drawCursor paints the mouse pointer into the frame (screen captures don't include it).
func (c *winCap) drawCursor(sw, sh, tw, th int) {
	var ci [24]byte // CURSORINFO (64-bit layout; 20 bytes on 32-bit)
	size := uint32(24)
	if unsafe.Sizeof(uintptr(0)) == 4 {
		size = 20
	}
	binary.LittleEndian.PutUint32(ci[0:], size)
	if r, _, _ := rpGetCursorInfo.Call(uintptr(unsafe.Pointer(&ci[0]))); r == 0 {
		return
	}
	if binary.LittleEndian.Uint32(ci[4:])&1 == 0 { // CURSOR_SHOWING
		return
	}
	var hcur uintptr
	var px, py int32
	if size == 24 {
		hcur = uintptr(binary.LittleEndian.Uint64(ci[8:]))
		px, py = int32(binary.LittleEndian.Uint32(ci[16:])), int32(binary.LittleEndian.Uint32(ci[20:]))
	} else {
		hcur = uintptr(binary.LittleEndian.Uint32(ci[8:]))
		px, py = int32(binary.LittleEndian.Uint32(ci[12:])), int32(binary.LittleEndian.Uint32(ci[16:]))
	}
	var ii [32]byte // ICONINFO
	hx, hy := int32(0), int32(0)
	if r, _, _ := rpGetIconInfo.Call(hcur, uintptr(unsafe.Pointer(&ii[0]))); r != 0 {
		hx, hy = int32(binary.LittleEndian.Uint32(ii[4:])), int32(binary.LittleEndian.Uint32(ii[8:]))
		var mask, color uintptr
		if unsafe.Sizeof(uintptr(0)) == 8 { // fIcon, xHotspot, yHotspot, pad, hbmMask@16, hbmColor@24
			mask, color = uintptr(binary.LittleEndian.Uint64(ii[16:])), uintptr(binary.LittleEndian.Uint64(ii[24:]))
		} else { // hbmMask@12, hbmColor@16
			mask, color = uintptr(binary.LittleEndian.Uint32(ii[12:])), uintptr(binary.LittleEndian.Uint32(ii[16:]))
		}
		if mask != 0 {
			rpDeleteObject.Call(mask)
		}
		if color != 0 {
			rpDeleteObject.Call(color)
		}
	}
	scale := float64(tw) / float64(sw)
	cs := int(32 * scale * 1.15)
	if cs < 18 {
		cs = 18
	}
	x := int(float64(px-hx) * scale)
	y := int(float64(py-hy) * scale)
	rpDrawIconEx.Call(c.memDC, uintptr(int32(x)), uintptr(int32(y)), hcur, uintptr(cs), uintptr(cs), 0, 0, 3) // DI_NORMAL
}

// ---------------------------------------------------------------- input

const (
	mMove      = 0x0001
	mLeftDown  = 0x0002
	mLeftUp    = 0x0004
	mRightDown = 0x0008
	mRightUp   = 0x0010
	mMidDown   = 0x0020
	mMidUp     = 0x0040
	mWheel     = 0x0800
	mHWheel    = 0x1000
	mAbsolute  = 0x8000
	kExtended  = 0x0001
	kUp        = 0x0002
	kUnicode   = 0x0004
)

func inputSize() (int, int) { // INPUT size, union offset
	if unsafe.Sizeof(uintptr(0)) == 4 {
		return 28, 4
	}
	return 40, 8
}

func sendMouse(flags uint32, x, y float64, data int32) {
	n, o := inputSize()
	in := make([]byte, n)
	binary.LittleEndian.PutUint32(in[0:], 0) // INPUT_MOUSE
	binary.LittleEndian.PutUint32(in[o:], uint32(int32(clamp01(x)*65535+0.5)))
	binary.LittleEndian.PutUint32(in[o+4:], uint32(int32(clamp01(y)*65535+0.5)))
	binary.LittleEndian.PutUint32(in[o+8:], uint32(data))
	binary.LittleEndian.PutUint32(in[o+12:], flags)
	rpSendInput.Call(1, uintptr(unsafe.Pointer(&in[0])), uintptr(n))
}

func sendKey(vk, scan uint16, flags uint32) {
	n, o := inputSize()
	in := make([]byte, n)
	binary.LittleEndian.PutUint32(in[0:], 1) // INPUT_KEYBOARD
	binary.LittleEndian.PutUint16(in[o:], vk)
	binary.LittleEndian.PutUint16(in[o+2:], scan)
	binary.LittleEndian.PutUint32(in[o+4:], flags)
	rpSendInput.Call(1, uintptr(unsafe.Pointer(&in[0])), uintptr(n))
}

func clamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

var vkNames = map[string]uint16{
	"Enter": 0x0D, "Backspace": 0x08, "Tab": 0x09, "Escape": 0x1B, " ": 0x20, "Shift": 0x10, "Control": 0x11, "Alt": 0x12,
	"CapsLock": 0x14, "PrintScreen": 0x2C, "Pause": 0x13,
	"ArrowLeft": 0x25, "ArrowUp": 0x26, "ArrowRight": 0x27, "ArrowDown": 0x28, "Delete": 0x2E, "Insert": 0x2D,
	"Home": 0x24, "End": 0x23, "PageUp": 0x21, "PageDown": 0x22, "Meta": 0x5B, "ContextMenu": 0x5D,
	"F1": 0x70, "F2": 0x71, "F3": 0x72, "F4": 0x73, "F5": 0x74, "F6": 0x75, "F7": 0x76, "F8": 0x77, "F9": 0x78, "F10": 0x79, "F11": 0x7A, "F12": 0x7B,
}
var vkExtended = map[uint16]bool{0x25: true, 0x26: true, 0x27: true, 0x28: true, 0x2E: true, 0x2D: true, 0x24: true, 0x23: true, 0x21: true, 0x22: true, 0x5B: true, 0x5D: true}

func vkFor(key string) uint16 {
	if v, ok := vkNames[key]; ok {
		return v
	}
	r := []rune(key)
	if len(r) == 1 {
		if v, _, _ := rpVkKeyScanW.Call(uintptr(r[0])); int16(v) != -1 {
			return uint16(v) & 0xFF
		}
	}
	return 0
}

func typeText(s string) {
	for _, u := range utf16.Encode([]rune(s)) {
		if u == '\n' {
			sendKey(0x0D, 0, 0)
			sendKey(0x0D, 0, kUp)
			continue
		}
		sendKey(0, u, kUnicode)
		sendKey(0, u, kUnicode|kUp)
	}
}

func f64(m map[string]any, k string) float64 { v, _ := m[k].(float64); return v }

// rInject performs one input event from the viewer (coordinates are 0..1 of the screen).
func rInject(e *rEngine, m map[string]any) {
	k, _ := m["k"].(string)
	x, y := f64(m, "x"), f64(m, "y")
	btn := int(f64(m, "b"))
	down := [3]uint32{mLeftDown, mMidDown, mRightDown}
	up := [3]uint32{mLeftUp, mMidUp, mRightUp}
	if btn < 0 || btn > 2 {
		btn = 0
	}
	switch k {
	case "move":
		sendMouse(mMove|mAbsolute, x, y, 0)
	case "down":
		sendMouse(mMove|mAbsolute|down[btn], x, y, 0)
	case "up":
		sendMouse(mMove|mAbsolute|up[btn], x, y, 0)
	case "click", "tap", "long", "dbl":
		if k == "long" {
			btn = 2
		}
		n := 1
		if k == "dbl" {
			n = 2
		}
		sendMouse(mMove|mAbsolute, x, y, 0)
		for i := 0; i < n; i++ {
			sendMouse(mAbsolute|down[btn], x, y, 0)
			sendMouse(mAbsolute|up[btn], x, y, 0)
		}
	case "swipe":
		x2, y2 := f64(m, "x2"), f64(m, "y2")
		sendMouse(mMove|mAbsolute, x, y, 0)
		sendMouse(mAbsolute|mLeftDown, x, y, 0)
		for i := 1; i <= 8; i++ {
			t := float64(i) / 8
			sendMouse(mMove|mAbsolute, x+(x2-x)*t, y+(y2-y)*t, 0)
			time.Sleep(12 * time.Millisecond)
		}
		sendMouse(mAbsolute|mLeftUp, x2, y2, 0)
	case "wheel", "scroll":
		if dy := f64(m, "dy"); dy != 0 {
			sendMouse(mWheel, x, y, int32(-dy*1.2))
		}
		if dx := f64(m, "dx"); dx != 0 {
			sendMouse(mHWheel, x, y, int32(dx*1.2))
		}
	case "text":
		s, _ := m["s"].(string)
		if len(s) <= 2000 {
			typeText(s)
		}
	case "key":
		key, _ := m["key"].(string)
		vk := vkFor(key)
		if vk == 0 {
			return
		}
		fl := uint32(0)
		if vkExtended[vk] {
			fl |= kExtended
		}
		if d, _ := m["down"].(bool); !d {
			fl |= kUp
		}
		sendKey(vk, 0, fl)
	case "combo": // e.g. "Control+Alt+Tab" from the toolbar
		keys := strings.Split(fmtCombo(m), "+")
		var vks []uint16
		for _, kk := range keys {
			if v := vkFor(kk); v != 0 {
				vks = append(vks, v)
			}
		}
		for _, v := range vks {
			fl := uint32(0)
			if vkExtended[v] {
				fl = kExtended
			}
			sendKey(v, 0, fl)
		}
		for i := len(vks) - 1; i >= 0; i-- {
			fl := uint32(kUp)
			if vkExtended[vks[i]] {
				fl |= kExtended
			}
			sendKey(vks[i], 0, fl)
		}
	}
}

func fmtCombo(m map[string]any) string { s, _ := m["keys"].(string); return s }
