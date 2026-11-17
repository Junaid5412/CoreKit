//go:build windows

package main

// Minimal pure-Go host for the Microsoft Edge WebView2 runtime (built into Windows 10/11).
// No cgo, no loader DLL: the runtime's client DLL is located on disk and called directly,
// and COM interfaces are driven through their vtables.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"unsafe"
)

var (
	ole32               = syscall.NewLazyDLL("ole32.dll")
	procCoInitializeEx  = ole32.NewProc("CoInitializeEx")
	procCoTaskMemAlloc  = ole32.NewProc("CoTaskMemAlloc")
	procCoTaskMemFree   = ole32.NewProc("CoTaskMemFree")
	gdi32               = syscall.NewLazyDLL("gdi32.dll")
	procCreateBrush     = gdi32.NewProc("CreateSolidBrush")
	procCreateRectRgn   = gdi32.NewProc("CreateRectRgn")
	procCombineRgn      = gdi32.NewProc("CombineRgn")
	procDeleteObject    = gdi32.NewProc("DeleteObject")
	procSetWindowRgn    = user32.NewProc("SetWindowRgn")
	dwmapi              = syscall.NewLazyDLL("dwmapi.dll")
	procDwmSetAttr      = dwmapi.NewProc("DwmSetWindowAttribute")
	procRegisterClass   = user32.NewProc("RegisterClassExW")
	procCreateWindow    = user32.NewProc("CreateWindowExW")
	procDefWindowProc   = user32.NewProc("DefWindowProcW")
	procGetMessage      = user32.NewProc("GetMessageW")
	procTranslateMsg    = user32.NewProc("TranslateMessage")
	procDispatchMsg     = user32.NewProc("DispatchMessageW")
	procPostMessage     = user32.NewProc("PostMessageW")
	procPostQuit        = user32.NewProc("PostQuitMessage")
	procShowWindow      = user32.NewProc("ShowWindow")
	procSetWindowPos    = user32.NewProc("SetWindowPos")
	procGetClientRect   = user32.NewProc("GetClientRect")
	procDestroyWindow   = user32.NewProc("DestroyWindow")
	procLoadImage       = user32.NewProc("LoadImageW")
	procLoadCursor      = user32.NewProc("LoadCursorW")
	procGetDpiForWindow = user32.NewProc("GetDpiForWindow")
	procSetDpiContext   = user32.NewProc("SetProcessDpiAwarenessContext")
	procSetDPIAware     = user32.NewProc("SetProcessDPIAware")
	procMonitorFromWnd  = user32.NewProc("MonitorFromWindow")
	procGetMonitorInfo  = user32.NewProc("GetMonitorInfoW")
	procGetPlacement    = user32.NewProc("GetWindowPlacement")
	procSetPlacement    = user32.NewProc("SetWindowPlacement")
	procGetWindowLong   = user32.NewProc("GetWindowLongPtrW")
	procSetWindowLong   = user32.NewProc("SetWindowLongPtrW")
	procSetForeground   = user32.NewProc("SetForegroundWindow")
	procFindWindow      = user32.NewProc("FindWindowW")
	procGetKeyState     = user32.NewProc("GetKeyState")
	procSetWindowText   = user32.NewProc("SetWindowTextW")
	procMessageBox      = user32.NewProc("MessageBoxW")
	procIsIconic        = user32.NewProc("IsIconic")
	procGetModuleHandle = kernel32.NewProc("GetModuleHandleW")
	procLoadLibraryEx   = kernel32.NewProc("LoadLibraryExW")
	procCreateMutex     = kernel32.NewProc("CreateMutexW")
	procOpenMutex       = kernel32.NewProc("OpenMutexW")
	procFreeConsole     = kernel32.NewProc("FreeConsole")
	procSetAffinity     = user32.NewProc("SetWindowDisplayAffinity")
	procGetProcAddress  = kernel32.NewProc("GetProcAddress")
)

const (
	wmDestroy       = 0x0002
	wmMove          = 0x0003
	wmSize          = 0x0005
	wmSetFocus      = 0x0007
	wmClose         = 0x0010
	wmEraseBkgnd    = 0x0014
	wmGetMinMaxInfo = 0x0024
	wmDpiChanged    = 0x02E0
	wmApp           = 0x8000
	wmUIQueue       = wmApp + 1

	wsOverlappedWindow = 0x00CF0000
	wsPopup            = 0x80000000
	wsChild            = 0x40000000
	wsVisible          = 0x10000000
	wsClipChildren     = 0x02000000
	wsClipSiblings     = 0x04000000

	swHide          = 0
	swShowNormal    = 1
	swShowMaximized = 3
	swShow          = 5
	swRestore       = 9

	swpNoSize     = 0x0001
	swpNoMove     = 0x0002
	swpNoZOrder   = 0x0004
	swpNoActivate = 0x0010
	swpFrameChg   = 0x0020
	swpShowWindow = 0x0040

	sOK          = 0
	eNoInterface = 0x80004002
	ePointer     = 0x80004003
)

type rect struct{ L, T, R, B int32 }

type winMsg struct {
	hwnd    uintptr
	message uint32
	wParam  uintptr
	lParam  uintptr
	time    uint32
	ptX     int32
	ptY     int32
	private uint32
}

type wndClassEx struct {
	size       uint32
	style      uint32
	wndProc    uintptr
	clsExtra   int32
	wndExtra   int32
	instance   uintptr
	icon       uintptr
	cursor     uintptr
	background uintptr
	menuName   uintptr
	className  uintptr
	iconSm     uintptr
}

type wndPlacement struct {
	length, flags, showCmd uint32
	minX, minY, maxX, maxY int32
	normal                 rect
}

type monitorInfo struct {
	size    uint32
	monitor rect
	work    rect
	flags   uint32
}

type minMaxInfo struct {
	reserved, maxSize, maxPos, minTrack, maxTrack [2]int32
}

func u16(s string) *uint16 {
	p, err := syscall.UTF16PtrFromString(strings.ReplaceAll(s, "\x00", ""))
	if err != nil {
		p, _ = syscall.UTF16PtrFromString("")
	}
	return p
}

func u16str(p uintptr) string {
	if p == 0 {
		return ""
	}
	n := 0
	for *(*uint16)(unsafe.Pointer(p + uintptr(n)*2)) != 0 {
		n++
		if n > 1<<22 {
			break
		}
	}
	return syscall.UTF16ToString(unsafe.Slice((*uint16)(unsafe.Pointer(p)), n))
}

// ---------------------------------------------------------------- COM plumbing

type guid struct {
	d1     uint32
	d2, d3 uint16
	d4     [8]byte
}

func mustGUID(s string) *guid {
	s = strings.Trim(s, "{}")
	h := strings.ReplaceAll(s, "-", "")
	if len(h) != 32 {
		panic("bad guid " + s)
	}
	b := make([]byte, 16)
	for i := 0; i < 16; i++ {
		v, err := strconv.ParseUint(h[i*2:i*2+2], 16, 8)
		if err != nil {
			panic("bad guid " + s)
		}
		b[i] = byte(v)
	}
	g := &guid{d1: uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3]),
		d2: uint16(b[4])<<8 | uint16(b[5]), d3: uint16(b[6])<<8 | uint16(b[7])}
	copy(g.d4[:], b[8:])
	return g
}

func guidAt(p uintptr, g *guid) bool {
	if p == 0 {
		return false
	}
	return *(*[16]byte)(unsafe.Pointer(p)) == *(*[16]byte)(unsafe.Pointer(g))
}

var (
	iidIUnknown    = mustGUID("00000000-0000-0000-C000-000000000046")
	iidIMarshal    = mustGUID("00000003-0000-0000-C000-000000000046")
	iidEnvOptions  = mustGUID("2fde08a8-1e9a-4766-8c05-95a9ceb9d1c5")
	iidSettings3   = mustGUID("fdb5ab74-af33-4854-84f0-0a631deb5eba")
	iidSettings4   = mustGUID("cb56846c-4168-4d53-b04f-03b6d6796ff2")
	iidController2 = mustGUID("c979903e-d4ca-4228-92eb-47ee3fa96eab")
)

type comPtr uintptr

// comCall invokes vtable slot `slot` of a COM object. uintptrescapes keeps any
// pointer converted to uintptr in the arguments alive (and on the heap) for the call.
//
//go:uintptrescapes
func comCall(o comPtr, slot int, args ...uintptr) uintptr {
	if o == 0 {
		return ePointer
	}
	vt := *(*uintptr)(unsafe.Pointer(uintptr(o)))
	fn := *(*uintptr)(unsafe.Pointer(vt + uintptr(slot)*unsafe.Sizeof(uintptr(0))))
	a := make([]uintptr, 0, len(args)+1)
	a = append(a, uintptr(o))
	a = append(a, args...)
	r, _, _ := syscall.SyscallN(fn, a...)
	return r
}

func failed(hr uintptr) bool   { return int32(uint32(hr)) < 0 }
func hrText(hr uintptr) string { return fmt.Sprintf("0x%08X", uint32(hr)) }

func (o comPtr) addRef() {
	if o != 0 {
		comCall(o, 1)
	}
}
func (o comPtr) release() {
	if o != 0 {
		comCall(o, 2)
	}
}
func (o comPtr) qi(iid *guid) comPtr {
	var out uintptr
	if failed(comCall(o, 0, uintptr(unsafe.Pointer(iid)), uintptr(unsafe.Pointer(&out)))) {
		return 0
	}
	return comPtr(out)
}
func (o comPtr) getStr(slot int) string {
	var p uintptr
	if failed(comCall(o, slot, uintptr(unsafe.Pointer(&p)))) {
		return ""
	}
	s := u16str(p)
	procCoTaskMemFree.Call(p)
	return s
}
func (o comPtr) getBool(slot int) bool {
	var b int32
	if failed(comCall(o, slot, uintptr(unsafe.Pointer(&b)))) {
		return false
	}
	return b != 0
}
func (o comPtr) getU32(slot int) uint32 {
	var v uint32
	comCall(o, slot, uintptr(unsafe.Pointer(&v)))
	return v
}
func (o comPtr) getPtr(slot int) comPtr {
	var v uintptr
	if failed(comCall(o, slot, uintptr(unsafe.Pointer(&v)))) {
		return 0
	}
	return comPtr(v)
}
func (o comPtr) putBool(slot int, v bool) uintptr {
	b := uintptr(0)
	if v {
		b = 1
	}
	return comCall(o, slot, b)
}

func coTaskString(s string) uintptr {
	u := syscall.StringToUTF16(s)
	p, _, _ := procCoTaskMemAlloc.Call(uintptr(len(u) * 2))
	if p != 0 {
		copy(unsafe.Slice((*uint16)(unsafe.Pointer(p)), len(u)), u)
	}
	return p
}

// ---- generic handler object: IUnknown + Invoke(a, b) — every WebView2 callback has two arguments.

type comHandler struct {
	vtbl *[4]uintptr
	refs int32
	fn   func(a, b uintptr) uintptr
}

var (
	handlerMu   sync.Mutex
	handlerLive = map[uintptr]*comHandler{}
	handlerVtbl [4]uintptr
	handlerOnce sync.Once
)

func handlerRef(this uintptr, d int32) uintptr {
	handlerMu.Lock()
	defer handlerMu.Unlock()
	h := handlerLive[this]
	if h == nil {
		return 0
	}
	h.refs += d
	if h.refs <= 0 {
		delete(handlerLive, this)
		return 0
	}
	return uintptr(h.refs)
}

func newHandler(fn func(a, b uintptr) uintptr) uintptr {
	handlerOnce.Do(func() {
		handlerVtbl[0] = syscall.NewCallback(func(this, riid, ppv uintptr) uintptr {
			if ppv == 0 {
				return ePointer
			}
			if guidAt(riid, iidIMarshal) {
				*(*uintptr)(unsafe.Pointer(ppv)) = 0
				return eNoInterface
			}
			*(*uintptr)(unsafe.Pointer(ppv)) = this
			handlerRef(this, 1)
			return sOK
		})
		handlerVtbl[1] = syscall.NewCallback(func(this uintptr) uintptr { return handlerRef(this, 1) })
		handlerVtbl[2] = syscall.NewCallback(func(this uintptr) uintptr { return handlerRef(this, -1) })
		handlerVtbl[3] = syscall.NewCallback(func(this, a, b uintptr) (ret uintptr) {
			handlerMu.Lock()
			h := handlerLive[this]
			handlerMu.Unlock()
			if h == nil {
				return sOK
			}
			defer func() {
				if r := recover(); r != nil {
					sbLog("PANIC in callback: %v\n%s", r, debug.Stack())
					ret = sOK
				}
			}()
			return h.fn(a, b)
		})
	})
	h := &comHandler{vtbl: &handlerVtbl, refs: 1, fn: fn}
	p := uintptr(unsafe.Pointer(h))
	handlerMu.Lock()
	handlerLive[p] = h
	handlerMu.Unlock()
	return p
}

// dropHandler releases our own initial reference once WebView2 holds its own.
func dropHandler(p uintptr) { handlerRef(p, -1) }

// addEvent registers an event handler (add_Xxx at `slot`) — fn(sender, args).
func (o comPtr) addEvent(slot int, fn func(sender, args comPtr)) bool {
	h := newHandler(func(a, b uintptr) uintptr { fn(comPtr(a), comPtr(b)); return sOK })
	var tok int64
	hr := comCall(o, slot, h, uintptr(unsafe.Pointer(&tok)))
	dropHandler(h)
	if failed(hr) {
		sbLog("add event slot %d failed: %s", slot, hrText(hr))
		return false
	}
	return true
}

// ---- ICoreWebView2EnvironmentOptions (static object, lives for the process)

type envOptions struct{ vtbl *[11]uintptr }

var (
	optVtbl [11]uintptr
	optObj  *envOptions
	optArgs string
	optLang string // Accept-Language / UI language, e.g. "en-US"
	optOnce sync.Once
)

func newEnvOptions(args string) uintptr {
	optArgs = args
	optOnce.Do(func() {
		strOut := func(v func() string) uintptr {
			return syscall.NewCallback(func(this, out uintptr) uintptr {
				if out == 0 {
					return ePointer
				}
				*(*uintptr)(unsafe.Pointer(out)) = coTaskString(v())
				return sOK
			})
		}
		ok := syscall.NewCallback(func(this, v uintptr) uintptr { return sOK })
		optVtbl[0] = syscall.NewCallback(func(this, riid, ppv uintptr) uintptr {
			if ppv == 0 {
				return ePointer
			}
			if guidAt(riid, iidIUnknown) || guidAt(riid, iidEnvOptions) {
				*(*uintptr)(unsafe.Pointer(ppv)) = this
				return sOK
			}
			*(*uintptr)(unsafe.Pointer(ppv)) = 0
			return eNoInterface
		})
		optVtbl[1] = syscall.NewCallback(func(this uintptr) uintptr { return 1 })
		optVtbl[2] = syscall.NewCallback(func(this uintptr) uintptr { return 1 })
		optVtbl[3] = strOut(func() string { return optArgs }) // get_AdditionalBrowserArguments
		optVtbl[4] = ok
		optVtbl[5] = strOut(func() string { return optLang }) // get_Language
		optVtbl[6] = ok
		optVtbl[7] = strOut(func() string { return "86.0.616.0" }) // get_TargetCompatibleBrowserVersion
		optVtbl[8] = ok
		optVtbl[9] = syscall.NewCallback(func(this, out uintptr) uintptr { // get_AllowSingleSignOnUsingOSPrimaryAccount
			if out != 0 {
				*(*int32)(unsafe.Pointer(out)) = 0
			}
			return sOK
		})
		optVtbl[10] = ok
		optObj = &envOptions{vtbl: &optVtbl}
	})
	return uintptr(unsafe.Pointer(optObj))
}

// ---------------------------------------------------------------- runtime discovery

var errNoRuntime = errors.New("WebView2 runtime not found")

func verLess(a, b string) bool {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(pa) && i < len(pb); i++ {
		x, _ := strconv.Atoi(pa[i])
		y, _ := strconv.Atoi(pb[i])
		if x != y {
			return x < y
		}
	}
	return len(pa) < len(pb)
}

// findWebView2 returns the newest installed runtime client DLL (EmbeddedBrowserWebView.dll).
func findWebView2() (dll, version string) {
	type cand struct{ dll, ver string }
	var cs []cand
	for _, env := range []string{"ProgramFiles(x86)", "ProgramFiles", "LOCALAPPDATA"} {
		base := os.Getenv(env)
		if base == "" {
			continue
		}
		root := filepath.Join(base, "Microsoft", "EdgeWebView", "Application")
		ents, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, e := range ents {
			if !e.IsDir() || strings.Count(e.Name(), ".") != 3 {
				continue
			}
			p := filepath.Join(root, e.Name(), "EBWebView", "x64", "EmbeddedBrowserWebView.dll")
			if st, err := os.Stat(p); err == nil && !st.IsDir() {
				cs = append(cs, cand{p, e.Name()})
			}
		}
	}
	if len(cs) == 0 {
		return "", ""
	}
	sort.Slice(cs, func(i, j int) bool { return verLess(cs[j].ver, cs[i].ver) })
	return cs[0].dll, cs[0].ver
}

// wvCreateEnvironment starts the WebView2 browser for a user-data folder.
// done runs on the UI thread with an AddRef'd ICoreWebView2Environment.
func wvCreateEnvironment(udf, args string, done func(env comPtr, err error)) (string, error) {
	handler := newHandler(func(a, b uintptr) uintptr {
		if failed(a) || b == 0 {
			done(0, fmt.Errorf("browser engine failed to start (%s)", hrText(a)))
			return sOK
		}
		env := comPtr(b)
		env.addRef()
		done(env, nil)
		return sOK
	})
	defer dropHandler(handler)
	opts := newEnvOptions(args)
	udfp := u16(udf)

	dllPath, ver := findWebView2()
	if dllPath != "" {
		h, _, e := procLoadLibraryEx.Call(uintptr(unsafe.Pointer(u16(dllPath))), 0, 0x00000008) // LOAD_WITH_ALTERED_SEARCH_PATH
		if h == 0 {
			sbLog("LoadLibraryEx(%s) failed: %v", dllPath, e)
		} else {
			name, _ := syscall.BytePtrFromString("CreateWebViewEnvironmentWithOptionsInternal")
			fn, _, _ := procGetProcAddress.Call(h, uintptr(unsafe.Pointer(name)))
			if fn != 0 {
				hr, _, _ := syscall.SyscallN(fn, 1, 0, uintptr(unsafe.Pointer(udfp)), opts, handler)
				if !failed(hr) {
					return ver, nil
				}
				sbLog("CreateWebViewEnvironmentWithOptionsInternal: %s", hrText(hr))
			} else {
				sbLog("entry point missing in %s", dllPath)
			}
		}
	}
	// fallback: WebView2Loader.dll placed next to CoreKit.exe
	if exe, err := os.Executable(); err == nil {
		lp := filepath.Join(filepath.Dir(exe), "WebView2Loader.dll")
		if _, err := os.Stat(lp); err == nil {
			ld := syscall.NewLazyDLL(lp)
			pr := ld.NewProc("CreateCoreWebView2EnvironmentWithOptions")
			if pr.Find() == nil {
				hr, _, _ := pr.Call(0, uintptr(unsafe.Pointer(udfp)), opts, handler)
				if !failed(hr) {
					if ver == "" {
						ver = "loader"
					}
					return ver, nil
				}
				return "", fmt.Errorf("browser engine failed to start (%s)", hrText(hr))
			}
		}
	}
	if dllPath == "" {
		return "", errNoRuntime
	}
	return "", errors.New("browser engine could not be loaded")
}

// ---------------------------------------------------------------- controller / webview wrappers

// vtable slots (IUnknown = 0..2)
const (
	envCreateController = 3

	ctlPutIsVisible     = 4
	ctlPutBounds        = 6
	ctlMoveFocus        = 12
	ctlAddAccelerator   = 19
	ctlNotifyParentMove = 23
	ctlClose            = 24
	ctlGetWebView       = 25
	ctl2PutDefaultBg    = 27

	wvGetSettings             = 3
	wvGetSource               = 4
	wvNavigate                = 5
	wvAddNavigationStarting   = 7
	wvAddSourceChanged        = 11
	wvAddHistoryChanged       = 13
	wvAddNavigationCompleted  = 15
	wvAddProcessFailed        = 25
	wvAddScriptOnDocCreated   = 27
	wvExecuteScript           = 29
	wvCallDevToolsMethod      = 36
	wvReload                  = 31
	wvPostWebMessageAsJSON    = 32
	wvAddWebMessageReceived   = 34
	wvGetCanGoBack            = 38
	wvGetCanGoForward         = 39
	wvGoBack                  = 40
	wvGoForward               = 41
	wvStop                    = 43
	wvAddNewWindowRequested   = 44
	wvAddDocumentTitleChanged = 46
	wvGetDocumentTitle        = 48
	wvAddFullScreenChanged    = 52
	wvGetContainsFullScreen   = 54
	wvAddWindowCloseRequested = 59

	setPutIsWebMessageEnabled     = 6
	setPutIsStatusBarEnabled      = 10
	setPutAreDevToolsEnabled      = 12
	setPutAreDefaultContextMenus  = 14
	setPutIsZoomControlEnabled    = 18
	setPutIsBuiltInErrorPage      = 20
	set3PutBrowserAcceleratorKeys = 24
	set4PutPasswordAutosave       = 26
	set4PutGeneralAutofill        = 28

	msgArgsGetSource    = 3
	msgArgsGetJSON      = 4
	nwArgsGetURI        = 3
	nwArgsPutNewWindow  = 4
	nwArgsPutHandled    = 6
	nwArgsGetIsUser     = 8
	nwArgsGetDeferral   = 9
	navStartGetURI      = 3
	navStartPutCancel   = 8
	navDoneGetIsSuccess = 3
	navDoneGetWebError  = 4
	accGetKind          = 3
	accGetVirtualKey    = 4
	accGetLParam        = 5
	accPutHandled       = 8
	procFailGetKind     = 3
	deferralComplete    = 3
)

type wvView struct {
	ctl comPtr
	wv  comPtr
}

// wvCreateView creates a controller in `parent`. done runs on the UI thread.
func wvCreateView(env comPtr, parent uintptr, done func(v *wvView, err error)) {
	h := newHandler(func(a, b uintptr) uintptr {
		if failed(a) || b == 0 {
			done(nil, fmt.Errorf("view creation failed (%s)", hrText(a)))
			return sOK
		}
		ctl := comPtr(b)
		ctl.addRef()
		wv := ctl.getPtr(ctlGetWebView)
		if wv == 0 {
			ctl.release()
			done(nil, errors.New("view has no web content"))
			return sOK
		}
		done(&wvView{ctl: ctl, wv: wv}, nil)
		return sOK
	})
	hr := comCall(env, envCreateController, parent, h)
	dropHandler(h)
	if failed(hr) {
		done(nil, fmt.Errorf("view creation failed (%s)", hrText(hr)))
	}
}

func (v *wvView) setBounds(r rect)  { comCall(v.ctl, ctlPutBounds, uintptr(unsafe.Pointer(&r))) }
func (v *wvView) setVisible(b bool) { v.ctl.putBool(ctlPutIsVisible, b) }
func (v *wvView) focus()            { comCall(v.ctl, ctlMoveFocus, 0) }
func (v *wvView) parentMoved()      { comCall(v.ctl, ctlNotifyParentMove) }
func (v *wvView) navigate(u string) uintptr {
	return comCall(v.wv, wvNavigate, uintptr(unsafe.Pointer(u16(u))))
}
func (v *wvView) source() string { return v.wv.getStr(wvGetSource) }
func (v *wvView) title() string  { return v.wv.getStr(wvGetDocumentTitle) }
func (v *wvView) canBack() bool  { return v.wv.getBool(wvGetCanGoBack) }
func (v *wvView) canFwd() bool   { return v.wv.getBool(wvGetCanGoForward) }
func (v *wvView) back()          { comCall(v.wv, wvGoBack) }
func (v *wvView) forward()       { comCall(v.wv, wvGoForward) }
func (v *wvView) reload()        { comCall(v.wv, wvReload) }
func (v *wvView) stop()          { comCall(v.wv, wvStop) }
func (v *wvView) postJSON(js string) {
	comCall(v.wv, wvPostWebMessageAsJSON, uintptr(unsafe.Pointer(u16(js))))
}

// execScript runs JavaScript and returns its JSON-encoded result on the UI thread.
func (v *wvView) execScript(js string, done func(json string, err error)) {
	h := newHandler(func(a, b uintptr) uintptr {
		if failed(a) {
			done("", fmt.Errorf("script failed (%s)", hrText(a)))
		} else {
			done(u16str(b), nil)
		}
		return sOK
	})
	hr := comCall(v.wv, wvExecuteScript, uintptr(unsafe.Pointer(u16(js))), h)
	dropHandler(h)
	if failed(hr) {
		done("", fmt.Errorf("script failed (%s)", hrText(hr)))
	}
}

// cdp calls a DevTools protocol method on this view (overrides persist across navigations).
func (v *wvView) cdp(method, params string, done func(result string, err error)) {
	h := newHandler(func(a, b uintptr) uintptr {
		if failed(a) {
			done("", fmt.Errorf("%s failed (%s)", method, hrText(a)))
		} else {
			done(u16str(b), nil)
		}
		return sOK
	})
	hr := comCall(v.wv, wvCallDevToolsMethod, uintptr(unsafe.Pointer(u16(method))), uintptr(unsafe.Pointer(u16(params))), h)
	dropHandler(h)
	if failed(hr) {
		done("", fmt.Errorf("%s failed (%s)", method, hrText(hr)))
	}
}

// addInitScript injects JavaScript into every document before its own scripts run.
func (v *wvView) addInitScript(js string, done func(err error)) {
	h := newHandler(func(a, b uintptr) uintptr {
		if failed(a) {
			done(fmt.Errorf("init script failed (%s)", hrText(a)))
		} else {
			done(nil)
		}
		return sOK
	})
	hr := comCall(v.wv, wvAddScriptOnDocCreated, uintptr(unsafe.Pointer(u16(js))), h)
	dropHandler(h)
	if failed(hr) {
		done(fmt.Errorf("init script failed (%s)", hrText(hr)))
	}
}

func (v *wvView) close() {
	if v == nil || v.ctl == 0 {
		return
	}
	comCall(v.ctl, ctlClose)
	v.wv.release()
	v.ctl.release()
	v.wv, v.ctl = 0, 0
}

type viewSettings struct {
	webMessages, statusBar, devTools, contextMenus, zoom, browserKeys, passwords bool
}

func (v *wvView) configure(s viewSettings) {
	st := v.wv.getPtr(wvGetSettings)
	if st == 0 {
		return
	}
	defer st.release()
	st.putBool(setPutIsWebMessageEnabled, s.webMessages)
	st.putBool(setPutIsStatusBarEnabled, s.statusBar)
	st.putBool(setPutAreDevToolsEnabled, s.devTools)
	st.putBool(setPutAreDefaultContextMenus, s.contextMenus)
	st.putBool(setPutIsZoomControlEnabled, s.zoom)
	st.putBool(setPutIsBuiltInErrorPage, true)
	if s3 := st.qi(iidSettings3); s3 != 0 {
		s3.putBool(set3PutBrowserAcceleratorKeys, s.browserKeys)
		s3.release()
	}
	if s4 := st.qi(iidSettings4); s4 != 0 {
		s4.putBool(set4PutPasswordAutosave, s.passwords)
		s4.putBool(set4PutGeneralAutofill, s.passwords)
		s4.release()
	}
}

// setBackground sets the color shown before a page paints (COREWEBVIEW2_COLOR {A,R,G,B} by value).
func (v *wvView) setBackground(r, g, b byte) {
	if c2 := v.ctl.qi(iidController2); c2 != 0 {
		comCall(c2, ctl2PutDefaultBg, uintptr(255)|uintptr(r)<<8|uintptr(g)<<16|uintptr(b)<<24)
		c2.release()
	}
}

// ---------------------------------------------------------------- window helpers

var (
	uiMu    sync.Mutex
	uiQueue []func()
	uiHwnd  uintptr
)

// uiPost runs f on the UI thread (all WebView2 calls must happen there).
func uiPost(f func()) {
	uiMu.Lock()
	uiQueue = append(uiQueue, f)
	h := uiHwnd
	uiMu.Unlock()
	if h != 0 {
		procPostMessage.Call(h, wmUIQueue, 0, 0)
	}
}

func uiDrain() {
	uiMu.Lock()
	q := uiQueue
	uiQueue = nil
	uiMu.Unlock()
	for _, f := range q {
		func() {
			defer func() {
				if r := recover(); r != nil {
					sbLog("PANIC in UI task: %v\n%s", r, debug.Stack())
				}
			}()
			f()
		}()
	}
}

func setDPIAwareness() {
	if procSetDpiContext.Find() == nil {
		if r, _, _ := procSetDpiContext.Call(^uintptr(3)); r != 0 { // PER_MONITOR_AWARE_V2
			return
		}
	}
	procSetDPIAware.Call()
}

func windowDPI(hwnd uintptr) int {
	if procGetDpiForWindow.Find() == nil {
		if d, _, _ := procGetDpiForWindow.Call(hwnd); d > 0 {
			return int(d)
		}
	}
	return 96
}

func clientRect(hwnd uintptr) rect {
	var r rect
	procGetClientRect.Call(hwnd, uintptr(unsafe.Pointer(&r)))
	return r
}

func darkTitleBar(hwnd uintptr, caption uint32) {
	one := int32(1)
	if r, _, _ := procDwmSetAttr.Call(hwnd, 20, uintptr(unsafe.Pointer(&one)), 4); r != 0 {
		procDwmSetAttr.Call(hwnd, 19, uintptr(unsafe.Pointer(&one)), 4)
	}
	procDwmSetAttr.Call(hwnd, 35, uintptr(unsafe.Pointer(&caption)), 4) // caption color (Windows 11)
}

func appIcon(size int) uintptr {
	inst, _, _ := procGetModuleHandle.Call(0)
	h, _, _ := procLoadImage.Call(inst, 1, 1, uintptr(size), uintptr(size), 0) // IMAGE_ICON, resource #1
	return h
}

func registerClass(name string, proc uintptr, bg uintptr) error {
	inst, _, _ := procGetModuleHandle.Call(0)
	cur, _, _ := procLoadCursor.Call(0, 32512) // IDC_ARROW
	wc := wndClassEx{
		style:      0x0002 | 0x0001, // CS_HREDRAW|CS_VREDRAW
		wndProc:    proc,
		instance:   inst,
		icon:       appIcon(32),
		iconSm:     appIcon(16),
		cursor:     cur,
		background: bg,
		className:  uintptr(unsafe.Pointer(u16(name))),
	}
	wc.size = uint32(unsafe.Sizeof(wc))
	if r, _, e := procRegisterClass.Call(uintptr(unsafe.Pointer(&wc))); r == 0 {
		return fmt.Errorf("RegisterClassEx: %v", e)
	}
	return nil
}

func createWindow(class, title string, style uint32, x, y, w, h int32, parent uintptr) uintptr {
	inst, _, _ := procGetModuleHandle.Call(0)
	hwnd, _, _ := procCreateWindow.Call(0, uintptr(unsafe.Pointer(u16(class))), uintptr(unsafe.Pointer(u16(title))),
		uintptr(style), uintptr(x), uintptr(y), uintptr(w), uintptr(h), parent, 0, inst, 0)
	return hwnd
}

func messageLoop() {
	var m winMsg
	for {
		r, _, _ := procGetMessage.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(r) <= 0 {
			return
		}
		procTranslateMsg.Call(uintptr(unsafe.Pointer(&m)))
		procDispatchMsg.Call(uintptr(unsafe.Pointer(&m)))
	}
}

func keyDown(vk int) bool {
	r, _, _ := procGetKeyState.Call(uintptr(vk))
	return int16(r) < 0
}

func msgBox(text, title string, flags uint32) int {
	r, _, _ := procMessageBox.Call(uiHwnd, uintptr(unsafe.Pointer(u16(text))), uintptr(unsafe.Pointer(u16(title))), uintptr(flags))
	return int(r)
}

func monitorRect(hwnd uintptr, work bool) rect {
	mon, _, _ := procMonitorFromWnd.Call(hwnd, 2) // MONITOR_DEFAULTTONEAREST
	mi := monitorInfo{}
	mi.size = uint32(unsafe.Sizeof(mi))
	procGetMonitorInfo.Call(mon, uintptr(unsafe.Pointer(&mi)))
	if work {
		return mi.work
	}
	return mi.monitor
}

func setWindowPos(hwnd, after uintptr, x, y, w, h int32, flags uint32) {
	procSetWindowPos.Call(hwnd, after, uintptr(x), uintptr(y), uintptr(w), uintptr(h), uintptr(flags))
}

// singleInstance returns false if another window already owns this profile.
func singleInstance(name string) bool {
	h, _, e := procCreateMutex.Call(0, 0, uintptr(unsafe.Pointer(u16(name))))
	if h == 0 {
		return true
	}
	return e != syscall.Errno(183) // ERROR_ALREADY_EXISTS
}

func focusExisting(class string) bool {
	h, _, _ := procFindWindow.Call(uintptr(unsafe.Pointer(u16(class))), 0)
	if h == 0 {
		return false
	}
	if r, _, _ := procIsIconic.Call(h); r != 0 {
		procShowWindow.Call(h, swRestore)
	}
	procSetForeground.Call(h)
	return true
}

// clipOut makes hwnd (w x h) invisible inside the rectangle hole (empty hole = no clipping).
func clipOut(hwnd uintptr, w, h int32, hole rect) {
	if hole.R <= hole.L || hole.B <= hole.T {
		procSetWindowRgn.Call(hwnd, 0, 1)
		return
	}
	all, _, _ := procCreateRectRgn.Call(0, 0, uintptr(w), uintptr(h))
	cut, _, _ := procCreateRectRgn.Call(uintptr(hole.L), uintptr(hole.T), uintptr(hole.R), uintptr(hole.B))
	procCombineRgn.Call(all, all, cut, 4) // RGN_DIFF
	procDeleteObject.Call(cut)
	procSetWindowRgn.Call(hwnd, all, 1) // the system owns the region now
}

// hideFromCapture excludes a window from screenshots, screen recorders and capture-based
// remote viewers (VNC, TeamViewer, AnyDesk...). Windows 10 2004+; older builds show it black.
func hideFromCapture(hwnd uintptr, on bool) bool {
	if !on {
		r, _, _ := procSetAffinity.Call(hwnd, 0)
		return r != 0
	}
	if r, _, _ := procSetAffinity.Call(hwnd, 0x11); r != 0 { // WDA_EXCLUDEFROMCAPTURE
		return true
	}
	r, _, _ := procSetAffinity.Call(hwnd, 0x01) // WDA_MONITOR
	return r != 0
}
