//go:build windows

package main

// CoreKit Browser — its own window: left sidebar with vertical tabs + toolbar
// (an HTML UI hosted in one WebView2 view) and one WebView2 view per tab.

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

type sbTab struct {
	id       int
	view     *wvView
	url      string
	title    string
	loading  bool
	canBack  bool
	canFwd   bool
	creating bool
	pending  string
	crashed  bool
	gone     bool
	alt      bool // "mobile view" on (desktop) for this tab
	// translation
	pageLang string
	trState  string // "" | offer | working | done | original | error | dismissed
	trMsg    string
	trSeq    int
}

type sbApp struct {
	profID     string
	proxy      *brProxy
	port       int
	bypass     string
	hwnd       uintptr
	content    uintptr
	chromeHost uintptr
	clipKey    rect
	env        comPtr
	chrome     *wvView
	ready      bool // chrome UI loaded
	layoutOK   bool
	sideW      float64
	topH       float64
	covered    bool
	fullscreen bool
	fsStyle    uintptr
	fsPlace    wndPlacement
	tabs       []*sbTab
	active     *sbTab
	nextID     int
	srv        *sbServer
	sess       *sbSession
	closed     []sbTabRec
	restored   bool
	state      string // connecting | engine | ready | error | leak
	stateMsg   string
	ip         string
	country    string
	ms         int
	wvVersion  string
	pushQueued bool
	saveTimer  *time.Timer
	quitting   bool
	checkSeq   int
	class      string
	envTries   int
	geo        geoInfo // time zone / location of the proxy exit (spoofed into pages)
	tunnelIP   string
	checks     []sbCheck
	noTrace    bool
	capture    bool // window hidden from screen capture
	relaunched bool // this process is exiting to restart
	tr         *translator
	hist       *historyStore
	adblock    bool
	defaultUA  string
}

type sbCheck struct {
	ID     string `json:"id"`
	Label  string `json:"label"`
	State  string `json:"state"` // wait | run | ok | warn | fail
	Detail string `json:"detail"`
}

var app *sbApp

func (a *sbApp) prof() *brProfile {
	brMu.Lock()
	defer brMu.Unlock()
	if p := brLoad().profile(a.profID); p != nil {
		return p
	}
	return &brProfile{ID: a.profID, Name: "Profile", Color: profileColors[0], Search: "google"}
}

// runBrowser is the entry point for `CoreKit.exe --browser <profile>`.
func runBrowser(id string, waitPID int, reset, keepPw bool) {
	runtime.LockOSThread()
	defer func() {
		if r := recover(); r != nil {
			sbLog("PANIC: %v", r)
			msgBox(fmt.Sprintf("CoreKit Browser stopped unexpectedly.\n\n%v\n\nLog: %s", r, sbLogPath()), "CoreKit Browser", 0x10)
		}
	}()
	procFreeConsole.Call() // the browser has no console window
	sbLog("start profile=%q wait=%d reset=%v", id, waitPID, reset)
	if waitPID > 0 {
		if h, err := syscall.OpenProcess(0x00100000, false, uint32(waitPID)); err == nil { // SYNCHRONIZE
			syscall.WaitForSingleObject(h, 20000)
			syscall.CloseHandle(h)
		}
	}
	p := pickProfile(id)
	a := &sbApp{profID: p.ID, nextID: 1, sideW: 248, topH: 48, class: "CoreKitBrowser." + p.ID}
	app = a
	if !singleInstance("CoreKit.Browser." + p.ID) {
		focusExisting(a.class)
		return
	}
	udf := profileDir(p.ID)
	os.MkdirAll(udf, 0700)
	waitProfileFree(udf)
	if reset {
		if err := resetIdentity(p.ID, keepPw); err != nil {
			sbLog("reset: %v", err)
		}
		os.Remove(sessionPath(p.ID))
	}
	procCoInitializeEx.Call(0, 0x2) // apartment threaded
	setDPIAwareness()
	a.noTrace = !p.KeepHistory
	if a.noTrace && waitPID == 0 && !reset {
		wipeTraces(p.ID) // leftovers of a crash or of a session that ended with the power button
	}
	a.sess = loadSession(p.ID)
	if a.noTrace {
		if waitPID == 0 {
			a.sess.Tabs, a.sess.Active = nil, 0 // nothing from earlier sessions
		}
		a.sess.Closed = nil
		os.Remove(sessionPath(p.ID))
	}
	a.closed = a.sess.Closed
	a.tr = &translator{client: a.netClient}
	a.hist = loadHistory(p.ID, !a.noTrace)
	optLang = acceptLanguage(p.Lang)
	if a.sess.Collapsed {
		a.sideW = 60
	}
	brMu.Lock()
	a.proxy = brLoad().proxyFor(p)
	brMu.Unlock()
	a.bypass = p.Bypass
	a.adblock = !p.NoAdblock
	xrayBlockAds = a.adblock
	if a.proxy != nil {
		a.port = pickPort()
		if a.port == 0 {
			a.port = 39321
		}
	}
	srv, err := startSBServer(func() string { return a.prof().Search })
	if srv != nil {
		srv.lang = func() string {
			if p := a.prof(); !p.NoGoogleFix {
				return a.lang()
			}
			return ""
		}
	}
	if err != nil {
		msgBox("CoreKit Browser could not start its local page server:\n"+err.Error(), "CoreKit Browser", 0x10)
		return
	}
	a.srv = srv
	if err := a.createWindows(p); err != nil {
		msgBox("CoreKit Browser could not create its window:\n"+err.Error(), "CoreKit Browser", 0x10)
		return
	}
	a.capture = !p.AllowCapture
	if a.capture && !hideFromCapture(a.hwnd, true) {
		sbLog("screen-capture shield not available on this Windows build")
	}
	a.startEngine(udf)
	messageLoop()
	a.shutdown()
}

// waitProfileFree waits until a previous browser engine for this profile has released it.
func waitProfileFree(udf string) {
	for i := 0; i < 40 && profileRunning(filepath.Join(udf, "EBWebView")); i++ {
		time.Sleep(250 * time.Millisecond)
	}
}

func (a *sbApp) startEngine(udf string) {
	args := browserArgs(a.port, a.bypass, a.adblock)
	ver, err := wvCreateEnvironment(udf, args, func(env comPtr, err error) {
		if err != nil {
			sbLog("environment: %v", err)
			if strings.Contains(err.Error(), "0x8007139F") && a.envTries < 6 { // profile still held by the old engine
				a.envTries++
				go func() { time.Sleep(1200 * time.Millisecond); uiPost(func() { a.startEngine(udf) }) }()
				return
			}
			a.fatal("The browser engine could not start.\n\n" + err.Error())
			return
		}
		a.env = env
		a.createChrome()
	})
	a.wvVersion = ver
	if err != nil {
		sbLog("create environment: %v", err)
		if errors.Is(err, errNoRuntime) {
			if msgBox("CoreKit Browser needs the Microsoft WebView2 Runtime (a built-in part of Windows 10/11), but it was not found on this PC.\n\nOpen the official Microsoft download page now?", "CoreKit Browser", 0x4|0x30) == 6 {
				openDefaultBrowser("https://developer.microsoft.com/microsoft-edge/webview2/#download-section")
			}
			procPostMessage.Call(a.hwnd, wmClose, 0, 0)
			return
		}
		a.fatal("The browser engine could not start.\n\n" + err.Error())
	}
}

func (a *sbApp) fatal(msg string) {
	sbLog("fatal: %s", msg)
	msgBox(msg+"\n\nLog file: "+sbLogPath(), "CoreKit Browser", 0x10)
	procPostMessage.Call(a.hwnd, wmClose, 0, 0)
}

// ---------------------------------------------------------------- windows

const bgR, bgG, bgB = 0x0a, 0x0e, 0x13

func (a *sbApp) createWindows(p *brProfile) error {
	brush, _, _ := procCreateBrush.Call(uintptr(bgR) | uintptr(bgG)<<8 | uintptr(bgB)<<16)
	if err := registerClass(a.class, syscall.NewCallback(a.wndProc), brush); err != nil {
		return err
	}
	if err := registerClass("CoreKitView", syscall.NewCallback(func(h, m, w, l uintptr) uintptr {
		if m == wmEraseBkgnd {
			return 1
		}
		r, _, _ := procDefWindowProc.Call(h, m, w, l)
		return r
	}), brush); err != nil {
		return err
	}
	sw, sh := screenSize()
	w, h := int32(min(1440, sw*86/100)), int32(min(920, sh*86/100))
	x, y := int32(sw)/2-w/2, int32(sh)/2-h/2
	maxed := false
	if wp := a.sess.Win; wp != nil && wp.W >= 400 && wp.H >= 300 && wp.X > -wp.W+60 && wp.Y > -20 && wp.X < sw-60 && wp.Y < sh-60 {
		x, y, w, h, maxed = int32(wp.X), int32(wp.Y), int32(wp.W), int32(wp.H), wp.Max
	}
	a.hwnd = createWindow(a.class, "CoreKit Browser — "+p.Name, wsOverlappedWindow|wsClipChildren, x, y, w, h, 0)
	if a.hwnd == 0 {
		return errors.New("CreateWindowEx failed")
	}
	uiMu.Lock()
	uiHwnd = a.hwnd
	uiMu.Unlock()
	darkTitleBar(a.hwnd, uint32(bgR)|uint32(bgG)<<8|uint32(bgB)<<16)
	a.chromeHost = createWindow("CoreKitView", "", wsChild|wsVisible|wsClipChildren|wsClipSiblings, 0, 0, 10, 10, a.hwnd)
	a.content = createWindow("CoreKitView", "", wsChild|wsClipChildren|wsClipSiblings, 0, 0, 10, 10, a.hwnd)
	show := uintptr(swShowNormal)
	if maxed {
		show = swShowMaximized
	}
	// twice: the first ShowWindow may be overridden by the launcher's hidden start-up state
	procShowWindow.Call(a.hwnd, show)
	procShowWindow.Call(a.hwnd, show)
	procSetForeground.Call(a.hwnd)
	return nil
}

func (a *sbApp) wndProc(hwnd, msg, wp, lp uintptr) uintptr {
	switch msg {
	case wmUIQueue:
		uiDrain()
		return 0
	case wmSize:
		if wp != 1 { // not minimized
			a.layout()
		}
	case wmMove:
		a.eachView(func(v *wvView) { v.parentMoved() })
	case wmSetFocus:
		if a.active != nil && a.active.view != nil && a.contentShown() {
			a.active.view.focus()
		} else if a.chrome != nil {
			a.chrome.focus()
		}
		return 0
	case wmGetMinMaxInfo:
		mi := (*minMaxInfo)(unsafe.Pointer(lp))
		s := float64(windowDPI(hwnd)) / 96
		mi.minTrack = [2]int32{int32(720 * s), int32(460 * s)}
		return 0
	case wmDpiChanged:
		r := (*rect)(unsafe.Pointer(lp))
		setWindowPos(hwnd, 0, r.L, r.T, r.R-r.L, r.B-r.T, swpNoZOrder|swpNoActivate)
		return 0
	case wmEraseBkgnd:
		return 1
	case wmClose:
		if !a.quitting {
			a.quitting = true
			a.saveNow(true)
			engineStopAll()
		}
		procDestroyWindow.Call(hwnd)
		return 0
	case wmDestroy:
		procPostQuit.Call(0)
		return 0
	}
	r, _, _ := procDefWindowProc.Call(hwnd, msg, wp, lp)
	return r
}

func (a *sbApp) eachView(f func(v *wvView)) {
	if a.chrome != nil {
		f(a.chrome)
	}
	for _, t := range a.tabs {
		if t.view != nil {
			f(t.view)
		}
	}
}

func (a *sbApp) contentShown() bool {
	if a.fullscreen {
		return true
	}
	return a.ready && a.layoutOK && a.state == "ready" && !a.covered
}

// layout: the UI view fills the window; the tab area sits on top, right of the sidebar
// and below the toolbar (sizes reported by the UI in CSS pixels).
func (a *sbApp) layout() {
	if a.hwnd == 0 {
		return
	}
	cr := clientRect(a.hwnd)
	setWindowPos(a.chromeHost, 1, 0, 0, max(cr.R, 1), max(cr.B, 1), swpNoActivate) // HWND_BOTTOM
	if a.chrome != nil {
		a.chrome.setBounds(cr)
	}
	s := float64(windowDPI(a.hwnd)) / 96
	x, y := int32(math.Round(a.sideW*s)), int32(math.Round(a.topH*s))
	if a.fullscreen {
		x, y = 0, 0
	}
	w, h := max(cr.R-x, 1), max(cr.B-y, 1)
	flags := uint32(swpNoActivate)
	hole := rect{}
	if a.contentShown() {
		flags |= swpShowWindow
		hole = rect{x, y, cr.R, cr.B}
	} else {
		procShowWindow.Call(a.content, swHide)
	}
	setWindowPos(a.content, 0, x, y, w, h, flags)
	// the UI view never paints under the tab area (avoids overlap between the two engine windows)
	if key := (rect{hole.L, hole.T, cr.R*boolI(hole.R > 0) + 1, cr.B}); key != a.clipKey {
		a.clipKey = key
		clipOut(a.chromeHost, cr.R, cr.B, hole)
	}
	for _, t := range a.tabs {
		if t.view != nil {
			t.view.setBounds(rect{0, 0, w, h})
		}
	}
}

func (a *sbApp) setFullscreen(on bool) {
	if on == a.fullscreen {
		return
	}
	a.fullscreen = on
	if on {
		a.fsStyle, _, _ = procGetWindowLong.Call(a.hwnd, ^uintptr(15)) // GWL_STYLE (-16)
		a.fsPlace.length = uint32(unsafe.Sizeof(a.fsPlace))
		procGetPlacement.Call(a.hwnd, uintptr(unsafe.Pointer(&a.fsPlace)))
		procSetWindowLong.Call(a.hwnd, ^uintptr(15), (a.fsStyle&^wsOverlappedWindow)|wsPopup|wsVisible|wsClipChildren)
		m := monitorRect(a.hwnd, false)
		setWindowPos(a.hwnd, 0, m.L, m.T, m.R-m.L, m.B-m.T, swpFrameChg|swpNoZOrder)
	} else {
		procSetWindowLong.Call(a.hwnd, ^uintptr(15), a.fsStyle)
		procSetPlacement.Call(a.hwnd, uintptr(unsafe.Pointer(&a.fsPlace)))
		setWindowPos(a.hwnd, 0, 0, 0, 0, 0, swpFrameChg|swpNoMove|swpNoSize|swpNoZOrder)
	}
	a.layout()
}

// ---------------------------------------------------------------- browser UI view

func (a *sbApp) createChrome() {
	wvCreateView(a.env, a.chromeHost, func(v *wvView, err error) {
		if err != nil {
			a.fatal("The browser window could not be created.\n\n" + err.Error())
			return
		}
		a.chrome = v
		v.configure(viewSettings{webMessages: true})
		v.setBackground(bgR, bgG, bgB)
		ui := a.srv.UIURL()
		v.wv.addEvent(wvAddNavigationStarting, func(_, args comPtr) {
			if u := args.getStr(navStartGetURI); !strings.HasPrefix(u, ui) {
				args.putBool(navStartPutCancel, true)
			}
		})
		v.wv.addEvent(wvAddNewWindowRequested, func(_, args comPtr) {
			u := args.getStr(nwArgsGetURI)
			args.putBool(nwArgsPutHandled, true)
			if strings.HasPrefix(u, "http") {
				uiPost(func() { a.newTab(u, true) })
			}
		})
		v.wv.addEvent(wvAddWebMessageReceived, func(_, args comPtr) {
			if !strings.HasPrefix(args.getStr(msgArgsGetSource), ui) {
				return
			}
			a.onUIMessage(args.getStr(msgArgsGetJSON))
		})
		v.wv.addEvent(wvAddProcessFailed, func(_, args comPtr) {
			kind := args.getU32(procFailGetKind)
			sbLog("ui process failed kind=%d", kind)
			if kind == 0 {
				a.engineLost()
			} else if kind == 1 {
				a.ready = false
				v.navigate(ui)
			}
		})
		v.ctl.addEvent(ctlAddAccelerator, func(_, args comPtr) { a.onAccel(args) })
		a.layout()
		v.navigate(ui)
	})
}

func (a *sbApp) engineLost() {
	if a.quitting {
		return
	}
	sbLog("browser engine process exited - restarting window")
	a.relaunch()
}

func (a *sbApp) post(v any) {
	if a.chrome == nil || !a.ready {
		return
	}
	b, _ := json.Marshal(v)
	a.chrome.postJSON(string(b))
}

type uiMsg struct {
	T      string  `json:"t"`
	ID     string  `json:"id"`
	Tab    int     `json:"tab"`
	URL    string  `json:"url"`
	On     bool    `json:"on"`
	Name   string  `json:"name"`
	Link   string  `json:"link"`
	Color  string  `json:"color"`
	Engine string  `json:"engine"`
	Bypass string  `json:"bypass"`
	KeepPw bool    `json:"keepPw"`
	To     int     `json:"to"`
	SW     float64 `json:"sw"`
	TH     float64 `json:"th"`
}

func (a *sbApp) onUIMessage(js string) {
	var m uiMsg
	if json.Unmarshal([]byte(js), &m) != nil {
		return
	}
	switch m.T {
	case "ready":
		a.ready = true
		a.sendState()
		a.pushTabs()
		a.pushStatus()
		if a.state == "" {
			a.begin()
		}
	case "layout":
		if m.SW >= 0 && m.SW < 600 && m.TH >= 0 && m.TH < 200 {
			a.sideW, a.topH, a.layoutOK = m.SW, m.TH, true
			a.layout()
		}
	case "cover":
		a.covered = m.On
		a.layout()
		if !m.On && a.active != nil && a.active.view != nil && a.contentShown() {
			a.active.view.focus()
		}
	case "nav":
		u := normalizeInput(m.URL, a.prof().Search)
		if u == "" {
			return
		}
		if !a.prof().NoGoogleFix {
			if fixed, ok := googleFix(u, a.lang()); ok {
				u = fixed
			}
		}
		if m.On { // open in a new tab
			a.newTab(u, true)
			return
		}
		if a.active == nil {
			a.newTab(u, true)
			return
		}
		a.navigate(a.active, u)
		if a.active.view != nil {
			a.active.view.focus()
		}
	case "newtab":
		a.newTab("", true)
	case "activate":
		if t := a.tabByID(m.Tab); t != nil {
			a.activate(t)
		}
	case "close":
		if t := a.tabByID(m.Tab); t != nil {
			a.closeTab(t)
		}
	case "move":
		a.moveTab(m.Tab, m.To)
	case "back", "fwd", "reload", "stop":
		if t := a.active; t != nil && t.view != nil {
			switch m.T {
			case "back":
				t.view.back()
			case "fwd":
				t.view.forward()
			case "reload":
				t.crashed = false
				t.view.reload()
			case "stop":
				t.view.stop()
			}
		}
	case "focusTab":
		if a.active != nil && a.active.view != nil {
			a.active.view.focus()
		}
	case "reopen":
		a.reopenClosed()
	case "collapsed":
		a.sess.Collapsed = m.On
		a.scheduleSave()
	case "search":
		brMutate(func(c *brConfig) {
			if p := c.profile(a.profID); p != nil {
				p.Search = engineByID(m.Engine).ID
			}
		})
		a.sendState()
	case "profileSave":
		name := strings.TrimSpace(m.Name)
		if name == "" || len([]rune(name)) > 32 {
			a.post(map[string]any{"t": "toast", "msg": "Name must be 1–32 characters", "bad": true})
			return
		}
		brMutate(func(c *brConfig) {
			if p := c.profile(a.profID); p != nil {
				p.Name = name
				if colorRe.MatchString(m.Color) {
					p.Color = m.Color
				}
			}
		})
		a.setTitle()
		a.sendState()
		a.post(map[string]any{"t": "toast", "msg": "Profile saved"})
	case "profileNew":
		name := strings.TrimSpace(m.Name)
		if name == "" || len([]rune(name)) > 32 {
			a.post(map[string]any{"t": "toast", "msg": "Name must be 1–32 characters", "bad": true})
			return
		}
		color := m.Color
		if !colorRe.MatchString(color) {
			color = profileColors[1]
		}
		np := &brProfile{ID: newID(), Name: name, Color: color, Search: a.prof().Search, Created: time.Now().Unix()}
		brMutate(func(c *brConfig) { c.Profiles = append(c.Profiles, np) })
		a.sendState()
		a.openProfile(np.ID)
	case "profileOpen":
		if m.ID == a.profID {
			return
		}
		a.openProfile(m.ID)
	case "profileDel":
		a.deleteProfile(m.ID)
	case "proxyAdd":
		a.addProxy(m.Name, m.Link)
	case "proxyTest":
		a.testProxy(m.ID)
	case "proxyDel":
		a.deleteProxy(m.ID)
	case "proxyApply":
		a.applyProxy(m.On, m.ID, m.Bypass)
	case "proxyOff":
		a.applyProxy(false, "", a.bypass)
	case "install":
		a.installEngine()
	case "retry":
		a.begin()
	case "reset":
		a.saveNow(true)
		os.Remove(sessionPath(a.profID))
		args := []string{"--reset"}
		if m.KeepPw {
			args = append(args, "--keep-pw")
		}
		a.sess = &sbSession{Collapsed: a.sess.Collapsed}
		a.tabs = nil
		a.relaunchNoSave(args...)
	case "tr":
		a.onTranslateOp(m.ID)
	case "history":
		a.post(map[string]any{"t": "history", "items": a.hist.search(m.Name, 400), "persist": !a.noTrace})
	case "histDel":
		a.hist.remove(m.URL, int64(m.To))
		a.post(map[string]any{"t": "history", "items": a.hist.search(m.Name, 400), "persist": !a.noTrace})
		a.scheduleSave()
	case "histClear":
		a.hist.clear()
		a.post(map[string]any{"t": "history", "items": []histEntry{}, "persist": !a.noTrace})
	case "lang":
		code := ""
		for _, l := range uiLanguages {
			if l.Code == m.ID {
				code = l.Code
			}
		}
		if code == "" {
			return
		}
		brMutate(func(c *brConfig) {
			if p := c.profile(a.profID); p != nil {
				p.Lang = code
			}
		})
		a.sendState()
		if t := a.active; t != nil && t.view != nil {
			a.decideTranslate(t)
		}
	case "transOpt":
		brMutate(func(c *brConfig) {
			if p := c.profile(a.profID); p != nil {
				switch m.ID {
				case "offer":
					p.NoTransOffer = !m.On
				case "auto":
					p.TransAuto = m.On
				case "google":
					p.NoGoogleFix = !m.On
				}
			}
		})
		a.sendState()
	case "langList":
		brMutate(func(c *brConfig) {
			if p := c.profile(a.profID); p != nil {
				p.AlwaysLangs = without(p.AlwaysLangs, m.ID)
				p.NeverLangs = without(p.NeverLangs, m.ID)
			}
		})
		a.sendState()
	case "adblock", "langMatch":
		brMutate(func(c *brConfig) {
			if p := c.profile(a.profID); p != nil {
				if m.T == "adblock" {
					p.NoAdblock = !m.On
				} else {
					p.NoLangMatch = !m.On
				}
			}
		})
		a.relaunch() // engine options are fixed per start; tabs are kept
	case "siteMode":
		if t := a.active; t != nil && t.view != nil {
			a.setMobileView(t, m.On)
		}
	case "privacy":
		brMutate(func(c *brConfig) {
			if p := c.profile(a.profID); p != nil {
				switch m.ID {
				case "capture":
					p.AllowCapture = !m.On
				case "trace":
					p.KeepHistory = !m.On
				}
			}
		})
		switch m.ID {
		case "capture":
			a.capture = m.On
			hideFromCapture(a.hwnd, m.On)
			if a.proxy != nil && len(a.checks) > 0 {
				if m.On {
					a.setCheck("capture", "ok", "Screenshots & remote viewers see nothing")
				} else {
					a.setCheck("capture", "warn", "Off in settings")
				}
			}
		case "trace":
			a.noTrace = m.On
			a.hist.setPersist(!m.On)
		}
		a.sendState()
	}
}

// ---------------------------------------------------------------- state for the UI

func (a *sbApp) sendState() {
	p := a.prof()
	brMu.Lock()
	c := brLoad()
	profs := []map[string]any{}
	for _, x := range c.Profiles {
		profs = append(profs, map[string]any{"id": x.ID, "name": x.Name, "color": x.Color, "current": x.ID == a.profID, "running": x.ID != a.profID && profileOpenElsewhere(x.ID)})
	}
	pxs := []map[string]any{}
	for _, x := range c.Proxies {
		_, kind, _, err := parseProxy(x.Link)
		if err != nil {
			kind = "invalid"
		}
		pxs = append(pxs, map[string]any{"id": x.ID, "name": x.Name, "kind": kind, "test": x.Test})
	}
	activeProxy := ""
	if a.proxy != nil {
		activeProxy = a.proxy.ID
	}
	chosen := ""
	if px := c.proxyFor(p); px != nil {
		chosen = px.ID
	}
	brMu.Unlock()
	engines := []map[string]string{}
	for _, e := range searchEngines {
		engines = append(engines, map[string]string{"id": e.ID, "name": e.Name})
	}
	a.post(map[string]any{
		"t": "state", "version": appVersion, "webview": a.wvVersion, "xray": engineVersionHook(),
		"profile":  map[string]any{"id": p.ID, "name": p.Name, "color": p.Color, "search": p.Search, "bypass": p.Bypass},
		"profiles": profs, "proxies": pxs, "proxyActive": activeProxy, "proxyChosen": chosen, "proxyOn": p.Proxy != "",
		"engines": engines, "collapsed": a.sess.Collapsed, "colors": profileColors,
		"shield": a.capture, "noTrace": a.noTrace, "tz": a.geo.TZ, "platform": "windows",
		"adblock": !p.NoAdblock, "langMatch": !p.NoLangMatch,
		"lang": a.lang(), "langs": uiLanguages, "transOffer": !p.NoTransOffer, "transAuto": p.TransAuto, "googleFix": !p.NoGoogleFix,
		"alwaysLangs": namedLangs(p.AlwaysLangs), "neverLangs": namedLangs(p.NeverLangs),
	})
}

func (a *sbApp) setStatus(state, msg string) {
	a.state, a.stateMsg = state, msg
	a.layout()
	a.pushStatus()
}

func (a *sbApp) pushStatus() {
	name := ""
	if a.proxy != nil {
		name = a.proxy.Name
	}
	a.post(map[string]any{"t": "status", "state": a.state, "msg": a.stateMsg, "proxy": name,
		"ip": maskIP(a.ip), "country": a.country, "ms": a.ms, "checks": a.checks, "tz": a.geo.TZ})
}

func (a *sbApp) pushTabs() {
	if a.pushQueued {
		return
	}
	a.pushQueued = true
	uiPost(func() {
		a.pushQueued = false
		list := []map[string]any{}
		for _, t := range a.tabs {
			list = append(list, map[string]any{"id": t.id, "title": a.tabTitle(t), "url": a.srv.Display(a.tabURL(t)),
				"loading": t.loading, "crashed": t.crashed})
		}
		msg := map[string]any{"t": "tabs", "tabs": list, "active": 0, "closedCount": len(a.closed)}
		if t := a.active; t != nil {
			msg["active"] = t.id
			msg["canBack"], msg["canFwd"], msg["loading"] = t.canBack, t.canFwd, t.loading
			msg["url"] = a.srv.Display(a.tabURL(t))
			msg["alt"] = t.alt
			msg["tr"] = map[string]any{"state": t.trState, "from": t.pageLang, "fromName": langName(t.pageLang),
				"to": a.lang(), "toName": langName(a.lang()), "msg": t.trMsg, "page": strings.HasPrefix(t.url, "http") && !a.srv.IsStart(t.url)}
		}
		a.post(msg)
	})
}

func (a *sbApp) tabURL(t *sbTab) string {
	if t.url != "" {
		return t.url
	}
	return t.pending
}

func (a *sbApp) tabTitle(t *sbTab) string {
	u := a.tabURL(t)
	if a.srv.IsStart(u) && (t.title == "" || strings.HasPrefix(t.title, "127.0.0.1") || t.title == "New tab") {
		return "New tab"
	}
	if t.title != "" {
		return t.title
	}
	return u
}

func (a *sbApp) setTitle() {
	p := a.prof()
	title := "CoreKit Browser — " + p.Name
	if t := a.active; t != nil && !a.srv.IsStart(a.tabURL(t)) {
		title = a.tabTitle(t) + " — CoreKit Browser (" + p.Name + ")"
	}
	procSetWindowText.Call(a.hwnd, uintptr(unsafe.Pointer(u16(title))))
}

// ---------------------------------------------------------------- start-up flow + leak check

func (a *sbApp) begin() {
	if a.proxy == nil {
		a.setStatus("ready", "")
		a.restoreTabs()
		return
	}
	a.checkSeq++
	seq := a.checkSeq
	a.ip, a.country, a.ms = "", "", 0
	a.resetChecks()
	a.setCheck("tunnel", "run", "Connecting to "+a.proxy.Name)
	a.setStatus("connecting", "Starting secure tunnel")
	px := a.proxy
	go func() {
		if engineExe() == "" {
			uiPost(func() { a.setStatus("engine", "") })
			return
		}
		if _, err := engineRun("main", px, a.port); err != nil {
			uiPost(func() {
				a.setCheck("tunnel", "fail", "Engine could not start")
				a.setStatus("error", "The proxy engine could not start: "+shortErr(err))
			})
			return
		}
		uiPost(func() { a.setStatus("connecting", "Checking the proxy connection") })
		t := proxyTestHook(px, a.port)
		brMutate(func(c *brConfig) {
			if x := c.proxy(px.ID); x != nil {
				tt := t
				x.Test = &tt
			}
		})
		if !t.OK {
			uiPost(func() {
				a.setCheck("tunnel", "fail", t.Err)
				a.setStatus("error", "No connection through "+px.Name+": "+t.Err)
			})
			return
		}
		if done := engineDone("main"); done != nil {
			go func() {
				<-done
				uiPost(func() {
					if !a.quitting && seq == a.checkSeq {
						a.setStatus("error", "The proxy tunnel stopped. Browsing is paused so your real IP stays hidden.")
					}
				})
			}()
		}
		uiPost(func() {
			if seq != a.checkSeq {
				return
			}
			a.ms, a.tunnelIP = t.Ms, t.IP
			_, kind, _, _ := parseProxy(px.Link)
			a.setCheck("tunnel", "ok", fmt.Sprintf("%s · %d ms", kind, t.Ms))
			a.setCheck("tz", "run", "Looking up the proxy location")
			a.setStatus("connecting", "Matching time zone and location")
		})
		g := geoLookup(a.port, t.Country)
		uiPost(func() {
			if seq != a.checkSeq {
				return
			}
			a.geo = g
			a.setStatus("connecting", "Running leak tests")
			a.browserCheck(seq)
		})
	}()
}

func (a *sbApp) resetChecks() {
	a.checks = []sbCheck{
		{ID: "tunnel", Label: "Encrypted tunnel"},
		{ID: "ip", Label: "Real IP hidden"},
		{ID: "dns", Label: "DNS only through the tunnel"},
		{ID: "webrtc", Label: "WebRTC leak blocked"},
		{ID: "tz", Label: "Time zone matches the proxy"},
		{ID: "geo", Label: "Location masked"},
		{ID: "dnt", Label: "Do Not Track on"},
		{ID: "capture", Label: "Hidden from screen capture"},
	}
	for i := range a.checks {
		a.checks[i].State = "wait"
	}
}

func (a *sbApp) setCheck(id, state, detail string) {
	for i := range a.checks {
		if a.checks[i].ID == id {
			a.checks[i].State, a.checks[i].Detail = state, detail
		}
	}
	a.pushStatus()
}

// prepareView applies the privacy overrides to a view before it loads anything.
func (a *sbApp) prepareView(v *wvView, then func()) {
	var steps []func(next func())
	if a.proxy != nil && a.geo.TZ != "" {
		tz := a.geo.TZ
		steps = append(steps, func(next func()) {
			v.cdp("Emulation.setTimezoneOverride", `{"timezoneId":"`+tz+`"}`, func(_ string, err error) {
				if err != nil {
					sbLog("tz override: %v", err)
				}
				next()
			})
		})
	}
	if a.proxy != nil {
		params := `{}` // no position at all
		if a.geo.HasLoc {
			params = fmt.Sprintf(`{"latitude":%.4f,"longitude":%.4f,"accuracy":3000}`, a.geo.Lat, a.geo.Lon)
		}
		steps = append(steps, func(next func()) {
			v.cdp("Emulation.setGeolocationOverride", params, func(_ string, err error) {
				if err != nil {
					sbLog("geo override: %v", err)
				}
				next()
			})
		})
	}
	if l := a.langList(); l != nil {
		// the header (Accept-Language) and Intl locale must match navigator.languages, or
		// checkers like whoer still see the real language
		steps = append(steps, func(next func()) {
			a.uaOverride(v, false, func() {
				v.cdp("Emulation.setLocaleOverride", `{"locale":"`+l[0]+`"}`, func(_ string, err error) {
					if err != nil {
						sbLog("locale override: %v", err)
					}
					next()
				})
			})
		})
	}
	page := privacyScript
	if a.adblock {
		page += adCosmeticScript
	}
	if a.proxy != nil && !a.prof().NoLangMatch {
		page += langMatchScript(a.geo.Country)
	}
	steps = append(steps, func(next func()) {
		v.addInitScript(page, func(err error) {
			if err != nil {
				sbLog("privacy script: %v", err)
			}
			next()
		})
	})
	var run func(i int)
	run = func(i int) {
		if i == len(steps) {
			then()
			return
		}
		steps[i](func() { run(i + 1) })
	}
	run(0)
}

// browserCheck runs every leak test inside the browser engine itself (hidden view, same
// settings as real tabs) before any page is shown. Any failure keeps browsing blocked.
func (a *sbApp) browserCheck(seq int) {
	done := false
	var view *wvView
	finish := func(ok bool, state, msg string) {
		if done {
			return
		}
		done = true
		if view != nil {
			v := view
			uiPost(func() { v.close() })
		}
		if seq != a.checkSeq {
			return
		}
		if !ok {
			a.setStatus(state, msg)
			return
		}
		a.setStatus("ready", "")
		a.restoreTabs()
	}
	fail := func(id, detail, state, msg string) {
		a.setCheck(id, "fail", detail)
		finish(false, state, msg)
	}
	time.AfterFunc(45*time.Second, func() {
		uiPost(func() { finish(false, "error", "The protection checks timed out. The proxy may be slow or blocked.") })
	})
	a.setCheck("dns", "ok", "Local DNS disabled · names resolved by the proxy")
	if a.capture {
		a.setCheck("capture", "ok", "Screenshots & remote viewers see nothing")
	} else {
		a.setCheck("capture", "warn", "Off in settings")
	}
	wvCreateView(a.env, a.content, func(v *wvView, err error) {
		if err != nil {
			fail("ip", "Test view failed", "error", "Protection check failed: "+err.Error())
			return
		}
		if done {
			v.close()
			return
		}
		view = v
		v.configure(viewSettings{})
		v.setVisible(false)
		eval := func(js string, next func(string)) {
			v.execScript(js, func(res string, err error) {
				var txt string
				if err != nil || json.Unmarshal([]byte(res), &txt) != nil {
					fail("ip", "Script error", "error", "A protection check could not run.")
					return
				}
				next(txt)
			})
		}
		v.wv.addEvent(wvAddNavigationCompleted, func(_, args comPtr) {
			if done {
				return
			}
			if !args.getBool(navDoneGetIsSuccess) {
				fail("ip", "Page did not load", "error", fmt.Sprintf("The browser could not connect through the proxy (error %d).", args.getU32(navDoneGetWebError)))
				return
			}
			// 1) IP address seen by websites
			eval("document.body ? document.body.innerText : ''", func(txt string) {
				kv := map[string]string{}
				for _, l := range strings.Split(txt, "\n") {
					if i := strings.Index(l, "="); i > 0 {
						kv[l[:i]] = strings.TrimSpace(l[i+1:])
					}
				}
				ip := kv["ip"]
				if ip == "" {
					fail("ip", "No answer", "error", "The IP check returned nothing.")
					return
				}
				if a.tunnelIP != "" && ip != a.tunnelIP {
					sbLog("LEAK: browser address differs from tunnel exit")
					fail("ip", "Different address than the tunnel", "leak", "")
					return
				}
				a.ip, a.country = ip, kv["loc"]
				a.setCheck("ip", "ok", "Sites see "+maskIP(ip)+countryName(kv["loc"]))
				// 2) WebRTC must not reveal any address
				a.setCheck("webrtc", "run", "Testing")
				eval(webrtcProbe, func(string) {
					time.AfterFunc(3500*time.Millisecond, func() {
						uiPost(func() {
							if done {
								return
							}
							eval("JSON.stringify(window.__ck||{})", func(res string) {
								var r struct {
									C   []string `json:"c"`
									Err string   `json:"err"`
								}
								json.Unmarshal([]byte(res), &r)
								for _, c := range r.C {
									if leakyCandidate(c, ip) {
										sbLog("LEAK: WebRTC candidate exposes an address")
										fail("webrtc", "Address exposed", "leak", "")
										return
									}
								}
								a.setCheck("webrtc", "ok", "No address exposed")
								// 3) time zone, location and Do-Not-Track as pages see them
								eval(`[Intl.DateTimeFormat().resolvedOptions().timeZone, navigator.doNotTrack, String(new Date().getTimezoneOffset())].join("|")`, func(res string) {
									f := strings.Split(res, "|")
									for len(f) < 3 {
										f = append(f, "")
									}
									switch {
									case a.geo.TZ == "":
										a.setCheck("tz", "warn", "Proxy location unknown · system time zone kept")
									case f[0] == a.geo.TZ:
										a.setCheck("tz", "ok", strings.ReplaceAll(a.geo.TZ, "_", " "))
									default:
										fail("tz", "Could not apply "+a.geo.TZ, "error", "The time zone could not be matched to the proxy, so pages stay hidden.")
										return
									}
									if a.geo.HasLoc {
										a.setCheck("geo", "ok", "Sites asking for location get the proxy's area")
									} else {
										a.setCheck("geo", "ok", "Location requests get no position")
									}
									if f[1] == "1" {
										a.setCheck("dnt", "ok", "Sites are asked not to track you")
									} else {
										a.setCheck("dnt", "warn", "Not supported by this engine")
									}
									sbLog("protection checks passed")
									finish(true, "", "")
								})
							})
						})
					})
				})
			})
		})
		a.prepareView(v, func() {
			a.setCheck("ip", "run", "Checking")
			v.navigate("https://www.cloudflare.com/cdn-cgi/trace")
		})
	})
}

func countryName(code string) string {
	if code == "" {
		return ""
	}
	return " · " + code
}

func (a *sbApp) installEngine() {
	go func() {
		ver, err := engineInstallHook(func(pct int, msg string) {
			uiPost(func() { a.post(map[string]any{"t": "install", "pct": pct, "msg": msg}) })
		})
		uiPost(func() {
			if err != nil {
				a.post(map[string]any{"t": "install", "pct": -1, "msg": err.Error()})
				return
			}
			a.post(map[string]any{"t": "install", "pct": 100, "msg": "Installed " + ver})
			a.sendState()
			if a.state == "engine" {
				a.begin()
			}
		})
	}()
}

// ---------------------------------------------------------------- tabs

func (a *sbApp) tabByID(id int) *sbTab {
	for _, t := range a.tabs {
		if t.id == id {
			return t
		}
	}
	return nil
}

func (a *sbApp) indexOf(t *sbTab) int {
	for i, x := range a.tabs {
		if x == t {
			return i
		}
	}
	return -1
}

func (a *sbApp) restoreTabs() {
	if a.restored {
		a.layout()
		if a.active != nil {
			a.activate(a.active)
		}
		return
	}
	a.restored = true
	for _, r := range a.sess.Tabs {
		t := &sbTab{id: a.nextID, pending: r.URL, title: r.Title}
		a.nextID++
		a.tabs = append(a.tabs, t)
	}
	if len(a.tabs) == 0 {
		a.newTab("", true)
		return
	}
	a.activate(a.tabs[min(a.sess.Active, len(a.tabs)-1)])
}

// newTab opens a tab after the active one ("" = new-tab page).
func (a *sbApp) newTab(u string, activate bool) *sbTab {
	t := &sbTab{id: a.nextID, pending: u}
	a.nextID++
	i := len(a.tabs)
	if a.active != nil && u != "" {
		i = a.indexOf(a.active) + 1
	}
	a.tabs = append(a.tabs, nil)
	copy(a.tabs[i+1:], a.tabs[i:])
	a.tabs[i] = t
	if activate || a.active == nil {
		a.activate(t)
	} else {
		a.ensureView(t, nil)
	}
	a.pushTabs()
	a.scheduleSave()
	return t
}

func (a *sbApp) activate(t *sbTab) {
	prev := a.active
	a.active = t
	if prev != nil && prev != t && prev.view != nil {
		prev.view.setVisible(false)
	}
	if t.view != nil {
		t.view.setVisible(true)
		if a.srv.IsStart(a.tabURL(t)) {
			a.focusAddress()
		} else if a.contentShown() {
			t.view.focus()
		}
	} else {
		a.ensureView(t, nil)
	}
	a.setTitle()
	a.pushTabs()
	a.scheduleSave()
}

func (a *sbApp) focusAddress() {
	if a.chrome != nil {
		a.chrome.focus()
	}
	a.post(map[string]any{"t": "focusAddress"})
}

// ensureView creates the engine view for a tab on demand (lazy tabs keep start-up fast).
func (a *sbApp) ensureView(t *sbTab, popup func(v *wvView)) {
	if t.view != nil || t.creating || a.env == 0 {
		return
	}
	t.creating = true
	wvCreateView(a.env, a.content, func(v *wvView, err error) {
		t.creating = false
		if t.gone {
			if v != nil {
				v.close()
			}
			return
		}
		if err != nil {
			sbLog("tab view: %v", err)
			t.title, t.crashed = "Could not open tab", true
			if popup != nil {
				popup(nil)
			}
			a.pushTabs()
			return
		}
		t.view = v
		a.setupTab(t)
		cr := clientRect(a.content)
		v.setBounds(rect{0, 0, max(cr.R, 1), max(cr.B, 1)})
		v.setVisible(t == a.active)
		a.prepareView(v, func() {
			if t.gone {
				return
			}
			if popup != nil {
				popup(v)
				return
			}
			u := t.pending
			if u == "" {
				u = a.srv.StartURL()
			}
			v.navigate(u)
		})
		if t == a.active {
			if a.srv.IsStart(t.pending) {
				a.focusAddress()
			} else if a.contentShown() {
				v.focus()
			}
		}
	})
}

func (a *sbApp) navigate(t *sbTab, u string) {
	t.pending = u
	t.crashed = false
	if t.view != nil {
		t.view.navigate(u)
	} else {
		a.ensureView(t, nil)
	}
}

func (a *sbApp) setupTab(t *sbTab) {
	v := t.view
	v.configure(viewSettings{statusBar: true, devTools: true, contextMenus: true, zoom: true, browserKeys: true, passwords: true})
	v.wv.addEvent(wvAddNavigationStarting, func(_, args comPtr) {
		u := args.getStr(navStartGetURI)
		if !a.prof().NoGoogleFix {
			if fixed, ok := googleFix(u, a.lang()); ok {
				args.putBool(navStartPutCancel, true)
				uiPost(func() {
					if !t.gone && t.view != nil {
						t.view.navigate(fixed)
					}
				})
				return
			}
		}
		t.loading = true
		t.trSeq++
		t.pageLang, t.trState, t.trMsg = "", "", ""
		a.pushTabs()
	})
	v.wv.addEvent(wvAddSourceChanged, func(_, _ comPtr) {
		t.url = v.source()
		if t == a.active {
			a.setTitle()
		}
		a.pushTabs()
		a.scheduleSave()
	})
	v.wv.addEvent(wvAddHistoryChanged, func(_, _ comPtr) {
		t.canBack, t.canFwd = v.canBack(), v.canFwd()
		if t.trState == "done" || t.trState == "doneHidden" {
			a.translate(t, true)
		}
		a.pushTabs()
	})
	v.wv.addEvent(wvAddNavigationCompleted, func(_, args comPtr) {
		t.loading = false
		t.url = v.source()
		t.title = v.title()
		t.canBack, t.canFwd = v.canBack(), v.canFwd()
		if args.getBool(navDoneGetIsSuccess) && strings.HasPrefix(t.url, "http") && !a.srv.IsStart(t.url) {
			a.hist.add(t.url, t.title, time.Now())
			a.afterLoad(t)
		}
		a.pushTabs()
		a.scheduleSave()
	})
	v.wv.addEvent(wvAddDocumentTitleChanged, func(_, _ comPtr) {
		t.title = v.title()
		a.hist.setTitle(t.url, t.title)
		if t == a.active {
			a.setTitle()
		}
		a.pushTabs()
		a.scheduleSave()
	})
	v.wv.addEvent(wvAddNewWindowRequested, func(_, args comPtr) { a.onNewWindow(args) })
	v.wv.addEvent(wvAddWindowCloseRequested, func(_, _ comPtr) { uiPost(func() { a.closeTab(t) }) })
	v.wv.addEvent(wvAddFullScreenChanged, func(_, _ comPtr) {
		if t == a.active {
			a.setFullscreen(v.wv.getBool(wvGetContainsFullScreen))
		}
	})
	v.wv.addEvent(wvAddProcessFailed, func(_, args comPtr) {
		kind := args.getU32(procFailGetKind)
		sbLog("tab process failed kind=%d", kind)
		if kind == 0 {
			uiPost(a.engineLost)
			return
		}
		if kind == 1 { // page renderer exited
			t.crashed, t.loading = true, false
			t.title = "Page crashed — reload"
			a.pushTabs()
		}
	})
	v.ctl.addEvent(ctlAddAccelerator, func(_, args comPtr) { a.onAccel(args) })
}

// onNewWindow: window.open / target=_blank / ctrl+click open as a tab, keeping the
// opener relationship (needed by "Sign in with ..." pop-ups).
func (a *sbApp) onNewWindow(args comPtr) {
	u := args.getStr(nwArgsGetURI)
	bg := keyDown(0x11) // ctrl-click -> background tab
	deferral := args.getPtr(nwArgsGetDeferral)
	args.addRef()
	t := &sbTab{id: a.nextID, pending: u}
	a.nextID++
	i := len(a.tabs)
	if a.active != nil {
		i = a.indexOf(a.active) + 1
	}
	a.tabs = append(a.tabs, nil)
	copy(a.tabs[i+1:], a.tabs[i:])
	a.tabs[i] = t
	completed := false
	complete := func() {
		if completed {
			return
		}
		completed = true
		if deferral != 0 {
			comCall(deferral, deferralComplete)
			deferral.release()
		}
		args.release()
	}
	a.ensureView(t, func(v *wvView) {
		if v == nil {
			args.putBool(nwArgsPutHandled, true)
			complete()
			return
		}
		hr := comCall(args, nwArgsPutNewWindow, uintptr(v.wv))
		args.putBool(nwArgsPutHandled, true)
		complete()
		if failed(hr) {
			sbLog("put_NewWindow: %s", hrText(hr))
			v.navigate(u)
		}
	})
	if t.view == nil && !t.creating && !completed { // creation could not start
		args.putBool(nwArgsPutHandled, true)
		complete()
	}
	if !bg || a.active == nil {
		a.activate(t)
	}
	a.pushTabs()
	a.scheduleSave()
}

func (a *sbApp) closeTab(t *sbTab) {
	i := a.indexOf(t)
	if i < 0 {
		return
	}
	if u := a.tabURL(t); !a.srv.IsStart(u) {
		a.closed = append(a.closed, sbTabRec{URL: u, Title: a.tabTitle(t)})
		if len(a.closed) > 25 {
			a.closed = a.closed[len(a.closed)-25:]
		}
	}
	t.gone = true
	a.tabs = append(a.tabs[:i], a.tabs[i+1:]...)
	if t == a.active {
		a.active = nil
		if t.view != nil {
			t.view.setVisible(false)
		}
		if a.fullscreen {
			a.setFullscreen(false)
		}
		if len(a.tabs) > 0 {
			a.activate(a.tabs[min(i, len(a.tabs)-1)])
		}
	}
	if t.view != nil {
		v := t.view
		t.view = nil
		v.close()
	}
	if len(a.tabs) == 0 {
		a.newTab("", true)
	}
	a.pushTabs()
	a.scheduleSave()
}

func (a *sbApp) reopenClosed() {
	if len(a.closed) == 0 {
		return
	}
	r := a.closed[len(a.closed)-1]
	a.closed = a.closed[:len(a.closed)-1]
	t := a.newTab(r.URL, true)
	t.title = r.Title
}

func (a *sbApp) moveTab(id, to int) {
	i := -1
	for k, t := range a.tabs {
		if t.id == id {
			i = k
		}
	}
	if i < 0 || to < 0 || to >= len(a.tabs) || to == i {
		return
	}
	t := a.tabs[i]
	a.tabs = append(a.tabs[:i], a.tabs[i+1:]...)
	a.tabs = append(a.tabs[:to], append([]*sbTab{t}, a.tabs[to:]...)...)
	a.pushTabs()
	a.scheduleSave()
}

func (a *sbApp) cycle(d int) {
	if len(a.tabs) < 2 || a.active == nil {
		return
	}
	i := (a.indexOf(a.active) + d + len(a.tabs)) % len(a.tabs)
	a.activate(a.tabs[i])
}

// ---------------------------------------------------------------- keyboard shortcuts

func (a *sbApp) onAccel(args comPtr) {
	kind := args.getU32(accGetKind)
	if kind != 0 && kind != 2 { // KEY_DOWN / SYSTEM_KEY_DOWN
		return
	}
	vk := args.getU32(accGetVirtualKey)
	repeat := args.getU32(accGetLParam)&(1<<30) != 0
	ctrl, shift, alt := keyDown(0x11), keyDown(0x10), keyDown(0x12)
	handled := true
	switch {
	case ctrl && shift && vk == 'T':
		if !repeat {
			a.reopenClosed()
		}
	case ctrl && (vk == 'T' || vk == 'N'):
		if !repeat {
			a.newTab("", true)
		}
	case ctrl && (vk == 'W' || vk == 0x73):
		if !repeat && a.active != nil {
			a.closeTab(a.active)
		}
	case (ctrl && vk == 'L') || (alt && vk == 'D') || vk == 0x75:
		a.focusAddress()
	case (ctrl && vk == 'R') || vk == 0x74:
		if a.active != nil && a.active.view != nil {
			a.active.crashed = false
			a.active.view.reload()
		}
	case ctrl && vk == 0x09:
		if shift {
			a.cycle(-1)
		} else {
			a.cycle(1)
		}
	case ctrl && vk >= '1' && vk <= '9':
		if len(a.tabs) > 0 {
			i := int(vk - '1')
			if vk == '9' || i >= len(a.tabs) {
				i = len(a.tabs) - 1
			}
			a.activate(a.tabs[i])
		}
	case ctrl && vk == 'H':
		if !repeat {
			a.post(map[string]any{"t": "openHistory"})
			a.chrome.focus()
		}
	case alt && vk == 0x25:
		if a.active != nil && a.active.view != nil {
			a.active.view.back()
		}
	case alt && vk == 0x27:
		if a.active != nil && a.active.view != nil {
			a.active.view.forward()
		}
	case vk == 0x1B && a.fullscreen:
		handled = false
	default:
		handled = false
	}
	if handled {
		args.putBool(accPutHandled, true)
	}
}

// ---------------------------------------------------------------- session

func (a *sbApp) scheduleSave() {
	if a.saveTimer != nil {
		a.saveTimer.Stop()
	}
	a.saveTimer = time.AfterFunc(1500*time.Millisecond, func() { uiPost(func() { a.saveNow(false) }) })
}

func (a *sbApp) saveNow(sync bool) {
	if a.hwnd == 0 || a.sess == nil {
		return
	}
	s := &sbSession{Collapsed: a.sess.Collapsed, Closed: append([]sbTabRec(nil), a.closed...)}
	for i, t := range a.tabs {
		u := a.tabURL(t)
		if a.srv != nil && a.srv.IsStart(u) {
			u = ""
		}
		s.Tabs = append(s.Tabs, sbTabRec{URL: u, Title: a.tabTitle(t)})
		if t == a.active {
			s.Active = i
		}
	}
	if !a.restored {
		s.Tabs, s.Active = a.sess.Tabs, a.sess.Active
	}
	wp := wndPlacement{}
	wp.length = uint32(unsafe.Sizeof(wp))
	if a.fullscreen {
		wp = a.fsPlace
	} else {
		procGetPlacement.Call(a.hwnd, uintptr(unsafe.Pointer(&wp)))
	}
	if wp.normal.R > wp.normal.L {
		s.Win = &sbWin{X: int(wp.normal.L), Y: int(wp.normal.T), W: int(wp.normal.R - wp.normal.L), H: int(wp.normal.B - wp.normal.T), Max: wp.showCmd == swShowMaximized}
	}
	a.sess.Win = s.Win
	id := a.profID
	if sync {
		saveSession(id, s)
		a.hist.save()
	} else {
		go func() { saveSession(id, s); a.hist.save() }()
	}
}

func (a *sbApp) shutdown() {
	for _, t := range a.tabs {
		if t.view != nil {
			t.view.close()
		}
	}
	if a.chrome != nil {
		a.chrome.close()
	}
	a.env.release()
	engineStopAll()
	if a.noTrace && !a.relaunched {
		waitProfileFree(profileDir(a.profID))
		waitProfileFree(filepath.Join(profileDir(a.profID), "EBWebView"))
		wipeTraces(a.profID)
		os.Remove(sbLogPath())
		os.Remove(sbLogPath() + ".old")
		return
	}
	sbLog("exit")
}

// ---------------------------------------------------------------- restarts / profiles / proxies

func selfCommand(args ...string) *exec.Cmd {
	exe, _ := os.Executable()
	c := exec.Command(exe, args...)
	c.SysProcAttr = &syscall.SysProcAttr{CreationFlags: createNoWindow}
	return c
}

// relaunch restarts this window (engine options such as the proxy are fixed per start).
func (a *sbApp) relaunch(extra ...string) {
	a.saveNow(true)
	a.relaunchNoSave(extra...)
}

func (a *sbApp) relaunchNoSave(extra ...string) {
	args := append([]string{"--browser", a.profID, "--wait", strconv.Itoa(os.Getpid())}, extra...)
	if err := selfCommand(args...).Start(); err != nil {
		a.post(map[string]any{"t": "toast", "msg": "Could not restart: " + err.Error(), "bad": true})
		return
	}
	a.quitting = true
	a.relaunched = true
	engineStopAll()
	procPostMessage.Call(a.hwnd, wmClose, 0, 0)
}

func (a *sbApp) openProfile(id string) {
	if err := selfCommand("--browser", id).Start(); err != nil {
		a.post(map[string]any{"t": "toast", "msg": "Could not open profile: " + err.Error(), "bad": true})
	}
}

func profileOpenElsewhere(id string) bool {
	h, _, _ := procOpenMutex.Call(0x00100000, 0, uintptr(unsafe.Pointer(u16("CoreKit.Browser."+id))))
	if h != 0 {
		syscall.CloseHandle(syscall.Handle(h))
		return true
	}
	return false
}

func (a *sbApp) deleteProfile(id string) {
	if id == a.profID {
		return
	}
	if profileOpenElsewhere(id) {
		a.post(map[string]any{"t": "toast", "msg": "Close that profile's window first", "bad": true})
		return
	}
	brMutate(func(c *brConfig) {
		out := c.Profiles[:0]
		for _, p := range c.Profiles {
			if p.ID != id {
				out = append(out, p)
			}
		}
		c.Profiles = out
	})
	go func() {
		for i := 0; i < 10; i++ {
			if os.RemoveAll(profileDir(id)) == nil {
				break
			}
			time.Sleep(500 * time.Millisecond)
		}
	}()
	a.sendState()
	a.post(map[string]any{"t": "toast", "msg": "Profile deleted"})
}

func (a *sbApp) addProxy(name, link string) {
	px, err := newProxy(name, link)
	if err != nil {
		a.post(map[string]any{"t": "proxyAdded", "error": err.Error()})
		return
	}
	brMutate(func(c *brConfig) {
		c.Proxies = append(c.Proxies, px)
		if c.Default == "" {
			c.Default = px.ID
		}
	})
	a.sendState()
	a.post(map[string]any{"t": "proxyAdded", "id": px.ID})
	a.testProxy(px.ID)
}

func (a *sbApp) testProxy(id string) {
	brMu.Lock()
	px := brLoad().proxy(id)
	brMu.Unlock()
	if px == nil {
		return
	}
	cp := *px
	a.post(map[string]any{"t": "proxyTesting", "id": id})
	go func() {
		var t brTest
		key := "test:" + id
		port, err := engineRun(key, &cp, 0)
		if err != nil {
			if errors.Is(err, errNeedEngine) {
				uiPost(func() { a.post(map[string]any{"t": "proxyTested", "id": id, "needEngine": true}) })
				return
			}
			t = brTest{Err: shortErr(err), At: time.Now().Unix()}
		} else {
			t = proxyTestHook(&cp, port)
			engineStop(key)
		}
		brMutate(func(c *brConfig) {
			if x := c.proxy(id); x != nil {
				tt := t
				x.Test = &tt
			}
		})
		uiPost(func() {
			a.post(map[string]any{"t": "proxyTested", "id": id, "test": t})
			a.sendState()
		})
	}()
}

func (a *sbApp) deleteProxy(id string) {
	inUse := a.proxy != nil && a.proxy.ID == id
	brMutate(func(c *brConfig) {
		out := c.Proxies[:0]
		for _, p := range c.Proxies {
			if p.ID != id {
				out = append(out, p)
			}
		}
		c.Proxies = out
		if c.Default == id {
			c.Default = ""
			if len(out) > 0 {
				c.Default = out[0].ID
			}
		}
		for _, p := range c.Profiles {
			if p.Proxy == id {
				p.Proxy = ""
			}
		}
	})
	if inUse {
		a.relaunch()
		return
	}
	a.sendState()
}

// applyProxy saves the profile's proxy choice and restarts the window if it changed.
func (a *sbApp) applyProxy(on bool, id, bypass string) {
	var newProxy *brProxy
	brMutate(func(c *brConfig) {
		p := c.profile(a.profID)
		if p == nil {
			return
		}
		p.Bypass = strings.TrimSpace(bypass)
		if on && c.proxy(id) != nil {
			p.Proxy = id
		} else {
			p.Proxy = ""
		}
		newProxy = c.proxyFor(p)
	})
	same := (newProxy == nil && a.proxy == nil) || (newProxy != nil && a.proxy != nil && newProxy.ID == a.proxy.ID && newProxy.Link == a.proxy.Link)
	if same && strings.TrimSpace(bypass) == a.bypass {
		a.sendState()
		a.post(map[string]any{"t": "toast", "msg": "No change"})
		return
	}
	a.relaunch()
}

func boolI(b bool) int32 {
	if b {
		return 1
	}
	return 0
}

// ---------------------------------------------------------------- translation

func (a *sbApp) lang() string {
	if l := a.prof().Lang; l != "" {
		return l
	}
	return "en"
}

// netClient reaches the internet the same way the browser does (through the tunnel when on).
func (a *sbApp) netClient() *http.Client {
	if a.proxy != nil {
		pu, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", a.port+1))
		return &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(pu)}}
	}
	return &http.Client{Timeout: 20 * time.Second}
}

func without(list []string, v string) []string {
	var out []string
	for _, x := range list {
		if primaryLang(x) != primaryLang(v) {
			out = append(out, x)
		}
	}
	return out
}

func hasLang(list []string, v string) bool {
	for _, x := range list {
		if primaryLang(x) == primaryLang(v) {
			return true
		}
	}
	return false
}

func namedLangs(list []string) []map[string]string {
	out := []map[string]string{}
	for _, l := range sortedLangs(list) {
		out = append(out, map[string]string{"code": l, "name": langName(l)})
	}
	return out
}

// afterLoad finds out which language a loaded page is in.
func (a *sbApp) afterLoad(t *sbTab) {
	seq := t.trSeq
	v := t.view
	v.execScript(detectScript, func(res string, err error) {
		var js string
		var d struct {
			L string `json:"l"`
			S string `json:"s"`
		}
		if err != nil || json.Unmarshal([]byte(res), &js) != nil || json.Unmarshal([]byte(js), &d) != nil || seq != t.trSeq {
			return
		}
		if d.L != "" && primaryLang(d.L) != "" {
			t.pageLang = d.L
			a.decideTranslate(t)
			return
		}
		if len([]rune(d.S)) < 40 {
			return
		}
		go func() {
			l := a.tr.detect(d.S)
			uiPost(func() {
				if seq == t.trSeq && l != "" {
					t.pageLang = l
					a.decideTranslate(t)
				}
			})
		}()
	})
}

func (a *sbApp) decideTranslate(t *sbTab) {
	p := a.prof()
	switch {
	case t.pageLang == "" || primaryLang(t.pageLang) == primaryLang(a.lang()):
		if t.trState == "offer" {
			t.trState = ""
		}
	case t.trState == "done" || t.trState == "doneHidden" || t.trState == "working":
	case hasLang(p.NeverLangs, t.pageLang):
		t.trState = ""
	case p.TransAuto || hasLang(p.AlwaysLangs, t.pageLang):
		a.translate(t, false)
		return
	case p.NoTransOffer:
		t.trState = ""
	default:
		t.trState = "offer"
	}
	a.pushTabs()
}

// translate replaces the page's text in place (logins and scripts keep working).
// more=true translates only content that appeared since the last pass.
func (a *sbApp) translate(t *sbTab, more bool) {
	if t.view == nil {
		return
	}
	seq := t.trSeq
	if !more {
		t.trState, t.trMsg = "working", ""
		a.pushTabs()
	}
	v, to := t.view, a.lang()
	v.execScript(collectScript, func(res string, err error) {
		var js string
		var c struct {
			Base  int      `json:"base"`
			Texts []string `json:"texts"`
		}
		if seq != t.trSeq || t.gone {
			return
		}
		if err != nil || json.Unmarshal([]byte(res), &js) != nil || json.Unmarshal([]byte(js), &c) != nil {
			if !more {
				t.trState, t.trMsg = "error", "This page cannot be translated in place."
				a.pushTabs()
			}
			return
		}
		if len(c.Texts) == 0 {
			if !more {
				t.trState = "done"
				a.pushTabs()
				a.followTranslate(t, seq, 0)
			}
			return
		}
		go func() {
			det, err := a.tr.translateAll(c.Texts, to, func(idx []int, out []string) {
				top := 0
				for _, i := range idx {
					top = max(top, i+1)
				}
				arr := make([]any, top)
				for k, i := range idx {
					arr[i] = out[k]
				}
				b, _ := json.Marshal(arr)
				script := fmt.Sprintf("window.__ckA&&window.__ckA(%d,%s)", c.Base, b)
				uiPost(func() {
					if seq == t.trSeq && !t.gone && t.view != nil && t.trState != "original" {
						t.view.execScript(script, func(string, error) {})
					}
				})
			})
			uiPost(func() {
				if seq != t.trSeq || t.trState == "original" {
					return
				}
				if err != nil {
					if !more {
						sbLog("translate: %v", err)
						t.trState, t.trMsg = "error", "The translation service could not be reached."
						a.pushTabs()
					}
					return
				}
				if t.pageLang == "" && det != "" {
					t.pageLang = det
				}
				if !more {
					t.trState = "done"
					a.pushTabs()
					a.followTranslate(t, seq, 0)
				}
			})
		}()
	})
}

// followTranslate keeps translating content that loads later (feeds, chats, pop-ups).
func (a *sbApp) followTranslate(t *sbTab, seq, n int) {
	if n >= 40 {
		return
	}
	time.AfterFunc(3*time.Second, func() {
		uiPost(func() {
			if seq != t.trSeq || t.gone || (t.trState != "done" && t.trState != "doneHidden") {
				return
			}
			if t == a.active {
				a.translate(t, true)
			}
			a.followTranslate(t, seq, n+1)
		})
	})
}

func (a *sbApp) onTranslateOp(op string) {
	t := a.active
	if t == nil || t.view == nil {
		return
	}
	switch op {
	case "translate", "retry":
		t.trState = ""
		a.translate(t, false)
	case "original":
		t.trState = "original"
		t.view.execScript("window.__ckR&&window.__ckR()", func(string, error) {})
		a.pushTabs()
	case "always":
		if t.pageLang != "" {
			brMutate(func(c *brConfig) {
				if p := c.profile(a.profID); p != nil {
					p.AlwaysLangs = append(without(p.AlwaysLangs, t.pageLang), primaryLang(t.pageLang))
					p.NeverLangs = without(p.NeverLangs, t.pageLang)
				}
			})
			a.sendState()
		}
		if t.trState != "done" && t.trState != "doneHidden" && t.trState != "working" {
			a.translate(t, false)
		}
	case "never":
		if t.pageLang != "" {
			brMutate(func(c *brConfig) {
				if p := c.profile(a.profID); p != nil {
					p.NeverLangs = append(without(p.NeverLangs, t.pageLang), primaryLang(t.pageLang))
					p.AlwaysLangs = without(p.AlwaysLangs, t.pageLang)
				}
			})
			a.sendState()
		}
		t.trState = "dismissed"
		a.pushTabs()
	case "dismiss":
		if t.trState != "done" {
			t.trState = "dismissed"
		} else {
			t.trState = "doneHidden"
		}
		a.pushTabs()
	case "google":
		u := t.url
		t.trState = ""
		t.view.navigate(googleTranslatePage(u, a.lang()))
	}
}

// setMobileView shows the active page as a phone would (narrow layout, mobile site).
func (a *sbApp) setMobileView(t *sbTab, on bool) {
	v := t.view
	a.uaOverride(v, on, func() {
		if on {
			cr := clientRect(a.content)
			dpr := float64(windowDPI(a.hwnd)) / 96
			v.cdp("Emulation.setDeviceMetricsOverride", fmt.Sprintf(`{"width":412,"height":%d,"deviceScaleFactor":0,"mobile":true}`, int(float64(cr.B)/dpr)), func(string, error) {})
			v.cdp("Emulation.setTouchEmulationEnabled", `{"enabled":true,"maxTouchPoints":5}`, func(string, error) {})
		} else {
			v.cdp("Emulation.clearDeviceMetricsOverride", `{}`, func(string, error) {})
			v.cdp("Emulation.setTouchEmulationEnabled", `{"enabled":false}`, func(string, error) {})
		}
		t.alt = on
		v.reload()
		a.pushTabs()
	})
}

// langList is the language list pages should see: the VPN country's when the proxy is on
// and "match language" is enabled, otherwise nil (the browser's own setting).
func (a *sbApp) langList() []string {
	if a.proxy == nil || a.prof().NoLangMatch {
		return nil
	}
	return langMatchList(a.geo.Country)
}

// uaOverride sets the user agent (desktop or phone) together with the Accept-Language list.
func (a *sbApp) uaOverride(v *wvView, mobile bool, done func()) {
	apply := func() {
		if a.defaultUA == "" {
			done()
			return
		}
		params := map[string]any{"userAgent": a.defaultUA}
		if mobile {
			params["userAgent"], params["platform"] = mobileUA(a.defaultUA), "Android"
		}
		if l := a.langList(); l != nil {
			params["acceptLanguage"] = strings.Join(l, ",")
		}
		b, _ := json.Marshal(params)
		v.cdp("Emulation.setUserAgentOverride", string(b), func(_ string, err error) {
			if err != nil {
				sbLog("ua override: %v", err)
			}
			done()
		})
	}
	if a.defaultUA != "" {
		apply()
		return
	}
	v.cdp("Browser.getVersion", `{}`, func(res string, err error) {
		var r struct {
			UserAgent string `json:"userAgent"`
		}
		if err == nil && json.Unmarshal([]byte(res), &r) == nil {
			a.defaultUA = r.UserAgent
		}
		apply()
	})
}

func mobileUA(desktop string) string {
	ver := "131.0.0.0"
	if i := strings.Index(desktop, "Chrome/"); i >= 0 {
		ver = strings.Fields(desktop[i+7:])[0]
	}
	return "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" + ver + " Mobile Safari/537.36"
}
