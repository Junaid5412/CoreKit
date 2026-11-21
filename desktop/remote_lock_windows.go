//go:build windows

package main

// Locking the PC from the phone.
//
// Windows blocks a program from sending Win+L (that key combination is reserved by the system),
// which is why sending it as keystrokes did nothing. The real lock is the LockWorkStation API.
//
// "Custom lock" is CoreKit's own full-screen curtain: a black top-most window that covers the
// desktop with a short message, so someone sitting at the PC cannot see what is being done while
// it is managed remotely. It is deliberately safe: it never blocks Ctrl+Alt+Del, it closes itself
// the moment the remote session ends, and it lifts on its own after 30 minutes, so the owner can
// never be locked out of their own machine.

import (
	"runtime"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

var (
	procLockWorkStation = user32.NewProc("LockWorkStation")
	procBeginPaint      = user32.NewProc("BeginPaint")
	procEndPaint        = user32.NewProc("EndPaint")
	procFillRect        = user32.NewProc("FillRect")
	procDrawTextW       = user32.NewProc("DrawTextW")
	procSetTimerW       = user32.NewProc("SetTimer")
	gdiSetTextColor     = gdi32.NewProc("SetTextColor")
	gdiSetBkMode        = gdi32.NewProc("SetBkMode")
	gdiCreateFontW      = gdi32.NewProc("CreateFontW")
)

const (
	smXVirtual  = 76
	smYVirtual  = 77
	smCXVirtual = 78
	smCYVirtual = 79

	wsExTopmost  = 0x00000008
	wsExToolwin  = 0x00000080
	wmPaint      = 0x000F
	wmTimer      = 0x0113
	wmSetCursor  = 0x0020
	dtCenter     = 0x0001
	dtVCenter    = 0x0004
	dtSingleLine = 0x0020
	dtWordBreak  = 0x0010
	dtNoClip     = 0x0100
)

type paintStruct struct {
	hdc         uintptr
	fErase      int32
	rcPaint     rect
	fRestore    int32
	fIncUpdate  int32
	rgbReserved [32]byte
}

var curtain struct {
	mu   sync.Mutex
	hwnd uintptr
	gen  int
}

func metric(i int) int32 {
	r, _, _ := procGetMetrics.Call(uintptr(i))
	return int32(r)
}

// rLockWindows locks the workstation (the real Windows lock screen).
func rLockWindows() { procLockWorkStation.Call() }

// rCurtain shows or hides CoreKit's custom full-screen lock on the host.
func rCurtain(e *rEngine, on bool) {
	curtain.mu.Lock()
	if !on {
		h := curtain.hwnd
		curtain.hwnd = 0
		curtain.gen++
		curtain.mu.Unlock()
		if h != 0 {
			procPostMessage.Call(h, wmClose, 0, 0)
		}
		return
	}
	if curtain.hwnd != 0 {
		curtain.mu.Unlock()
		return
	}
	curtain.gen++
	gen := curtain.gen
	curtain.mu.Unlock()
	go curtainWindow(e, gen)
}

var (
	curtainClassOnce sync.Once
	curtainClassName = syscall.StringToUTF16Ptr("CoreKitLockCurtain")
	curtainProc      = syscall.NewCallback(curtainWndProc)
)

func drawLine(hdc uintptr, text string, top, bottom, height, weight int32, color uintptr) {
	font, _, _ := gdiCreateFontW.Call(uintptr(-height), 0, 0, 0, uintptr(weight), 0, 0, 0, 1, 0, 0, 4, 0, 0)
	old, _, _ := rpSelectObject.Call(hdc, font)
	gdiSetTextColor.Call(hdc, color)
	t := syscall.StringToUTF16(text)
	r := rect{0, top, metric(smCXVirtual), bottom}
	procDrawTextW.Call(hdc, uintptr(unsafe.Pointer(&t[0])), ^uintptr(0), uintptr(unsafe.Pointer(&r)), dtCenter|dtVCenter|dtWordBreak|dtNoClip)
	rpSelectObject.Call(hdc, old)
	procDeleteObject.Call(font)
}

func curtainWndProc(hwnd uintptr, msg uint32, wParam, lParam uintptr) uintptr {
	switch msg {
	case wmPaint:
		var ps paintStruct
		hdc, _, _ := procBeginPaint.Call(hwnd, uintptr(unsafe.Pointer(&ps)))
		black, _, _ := procCreateBrush.Call(0x00000000)
		full := rect{0, 0, metric(smCXVirtual), metric(smCYVirtual)}
		procFillRect.Call(hdc, uintptr(unsafe.Pointer(&full)), black)
		procDeleteObject.Call(black)
		gdiSetBkMode.Call(hdc, 1) // TRANSPARENT
		cy := metric(smCYVirtual)
		drawLine(hdc, "Locked by CoreKit", cy/2-130, cy/2-30, 46, 600, 0x00E6E6E6)
		drawLine(hdc, "This PC is being managed remotely. It unlocks when the session ends.", cy/2+6, cy/2+120, 22, 400, 0x00A0A0A0)
		procEndPaint.Call(hwnd, uintptr(unsafe.Pointer(&ps)))
		return 0
	case wmSetCursor:
		return 1
	case wmTimer:
		procSetWindowPos.Call(hwnd, ^uintptr(0) /* HWND_TOPMOST */, 0, 0, 0, 0, swpNoMove|swpNoSize)
		procSetForeground.Call(hwnd)
		return 0
	case wmClose:
		procDestroyWindow.Call(hwnd)
		return 0
	case wmDestroy:
		procPostQuit.Call(0)
		return 0
	}
	r, _, _ := procDefWindowProc.Call(hwnd, uintptr(msg), wParam, lParam)
	return r
}

func curtainWindow(e *rEngine, gen int) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	curtainClassOnce.Do(func() {
		arrow, _, _ := procLoadCursor.Call(0, 32512) // IDC_ARROW
		wc := wndClassEx{
			size:      uint32(unsafe.Sizeof(wndClassEx{})),
			wndProc:   curtainProc,
			className: uintptr(unsafe.Pointer(curtainClassName)),
			cursor:    arrow,
		}
		procRegisterClass.Call(uintptr(unsafe.Pointer(&wc)))
	})

	x, y := metric(smXVirtual), metric(smYVirtual)
	w, h := metric(smCXVirtual), metric(smCYVirtual)
	title := syscall.StringToUTF16Ptr("CoreKit")
	hwnd, _, _ := procCreateWindow.Call(
		wsExTopmost|wsExToolwin,
		uintptr(unsafe.Pointer(curtainClassName)),
		uintptr(unsafe.Pointer(title)),
		wsPopup|wsVisible,
		uintptr(x), uintptr(y), uintptr(w), uintptr(h),
		0, 0, 0, 0)
	if hwnd == 0 {
		return
	}
	curtain.mu.Lock()
	if curtain.gen != gen { // a hide raced in before the window existed
		curtain.mu.Unlock()
		procDestroyWindow.Call(hwnd)
		return
	}
	curtain.hwnd = hwnd
	curtain.mu.Unlock()

	procShowWindow.Call(hwnd, swShow)
	procSetForeground.Call(hwnd)
	procSetWindowPos.Call(hwnd, ^uintptr(0), 0, 0, 0, 0, swpNoMove|swpNoSize)
	procSetTimerW.Call(hwnd, 1, 250, 0)

	// safety net: lift the curtain if the session ends or after 30 minutes, whatever happens
	go func() {
		deadline := time.Now().Add(30 * time.Minute)
		for {
			time.Sleep(400 * time.Millisecond)
			curtain.mu.Lock()
			stale := curtain.gen != gen || curtain.hwnd == 0
			curtain.mu.Unlock()
			if stale {
				return
			}
			if e.session() == nil || time.Now().After(deadline) {
				rCurtain(e, false)
				return
			}
		}
	}()

	var msg winMsg
	for {
		r, _, _ := procGetMessage.Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0)
		if int32(r) <= 0 {
			break
		}
		procTranslateMsg.Call(uintptr(unsafe.Pointer(&msg)))
		procDispatchMsg.Call(uintptr(unsafe.Pointer(&msg)))
	}
	curtain.mu.Lock()
	if curtain.gen == gen {
		curtain.hwnd = 0
	}
	curtain.mu.Unlock()
}
