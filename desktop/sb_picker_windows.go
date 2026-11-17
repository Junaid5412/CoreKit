//go:build windows

package main

// Start-up profile picker: a small window (own engine instance with an empty, private
// data folder and no network use) that opens the chosen profile's browser window.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
)

func runPicker() {
	runtime.LockOSThread()
	procFreeConsole.Call()
	if !singleInstance("CoreKit.BrowserPicker") {
		focusExisting("CoreKitPicker")
		return
	}
	procCoInitializeEx.Call(0, 0x2)
	setDPIAwareness()
	srv, err := startSBServer(func() string { return "google" })
	if err != nil {
		msgBox("CoreKit Browser could not start:\n"+err.Error(), "CoreKit Browser", 0x10)
		return
	}
	var (
		hwnd uintptr
		view *wvView
		done bool
	)
	brush, _, _ := procCreateBrush.Call(uintptr(bgR) | uintptr(bgG)<<8 | uintptr(bgB)<<16)
	proc := syscall.NewCallback(func(h, msg, wp, lp uintptr) uintptr {
		switch msg {
		case wmUIQueue:
			uiDrain()
			return 0
		case wmSize:
			if view != nil {
				view.setBounds(clientRect(h))
			}
		case wmMove:
			if view != nil {
				view.parentMoved()
			}
		case wmEraseBkgnd:
			return 1
		case wmDestroy:
			procPostQuit.Call(0)
			return 0
		}
		r, _, _ := procDefWindowProc.Call(h, msg, wp, lp)
		return r
	})
	if err := registerClass("CoreKitPicker", proc, brush); err != nil {
		msgBox(err.Error(), "CoreKit Browser", 0x10)
		return
	}
	sw, sh := screenSize()
	w, h := int32(min(980, sw*80/100)), int32(min(680, sh*80/100))
	hwnd = createWindow("CoreKitPicker", "CoreKit Browser", wsOverlappedWindow|wsClipChildren, int32(sw)/2-w/2, int32(sh)/2-h/2, w, h, 0)
	uiMu.Lock()
	uiHwnd = hwnd
	uiMu.Unlock()
	darkTitleBar(hwnd, uint32(bgR)|uint32(bgG)<<8|uint32(bgB)<<16)
	hideFromCapture(hwnd, true)
	procShowWindow.Call(hwnd, swShowNormal)
	procShowWindow.Call(hwnd, swShowNormal)
	procSetForeground.Call(hwnd)

	post := func(v any) {
		if view != nil {
			b, _ := json.Marshal(v)
			view.postJSON(string(b))
		}
	}
	openProfile := func(id string) {
		if done {
			return
		}
		if err := selfCommand("--browser", id).Start(); err != nil {
			post(map[string]any{"t": "error", "msg": "Could not open the profile: " + err.Error()})
			return
		}
		done = true
		// keep the picker until the browser window has appeared, then close
		time.AfterFunc(1500*time.Millisecond, func() { procPostMessage.Call(hwnd, wmClose, 0, 0) })
	}
	udf := filepath.Join(dataDir(), "Launcher")
	os.MkdirAll(udf, 0700)
	optLang = "en-US"
	_, err = wvCreateEnvironment(udf, "--no-first-run --disable-background-networking --disable-component-update", func(env comPtr, err error) {
		if err != nil {
			msgBox("The browser engine could not start.\n\n"+err.Error()+"\n\nLog file: "+sbLogPath(), "CoreKit Browser", 0x10)
			procPostMessage.Call(hwnd, wmClose, 0, 0)
			return
		}
		wvCreateView(env, hwnd, func(v *wvView, err error) {
			if err != nil {
				msgBox("The browser window could not be created.\n\n"+err.Error(), "CoreKit Browser", 0x10)
				procPostMessage.Call(hwnd, wmClose, 0, 0)
				return
			}
			view = v
			v.configure(viewSettings{webMessages: true})
			v.setBackground(bgR, bgG, bgB)
			v.setBounds(clientRect(hwnd))
			page := srv.PickerURL()
			v.wv.addEvent(wvAddNavigationStarting, func(_, args comPtr) {
				if !strings.HasPrefix(args.getStr(navStartGetURI), page) {
					args.putBool(navStartPutCancel, true)
				}
			})
			v.wv.addEvent(wvAddNewWindowRequested, func(_, args comPtr) { args.putBool(nwArgsPutHandled, true) })
			v.wv.addEvent(wvAddWebMessageReceived, func(_, args comPtr) {
				if !strings.HasPrefix(args.getStr(msgArgsGetSource), page) {
					return
				}
				var m uiMsg
				if json.Unmarshal([]byte(args.getStr(msgArgsGetJSON)), &m) != nil {
					return
				}
				switch m.T {
				case "ready":
					post(pickerState(profileOpenElsewhere))
				case "open":
					openProfile(m.ID)
				case "new":
					name := strings.TrimSpace(m.Name)
					if name == "" || len([]rune(name)) > 32 {
						post(map[string]any{"t": "error", "msg": "Name must be 1-32 characters"})
						return
					}
					color := m.Color
					if !colorRe.MatchString(color) {
						color = profileColors[1]
					}
					np := &brProfile{ID: newID(), Name: name, Color: color, Search: "google", Created: time.Now().Unix()}
					brMutate(func(c *brConfig) { c.Profiles = append(c.Profiles, np) })
					openProfile(np.ID)
				}
			})
			v.navigate(page)
			v.focus()
		})
	})
	if err != nil {
		if err == errNoRuntime {
			if msgBox("CoreKit Browser needs the Microsoft WebView2 Runtime (part of Windows 10/11), but it was not found.\n\nOpen the official Microsoft download page now?", "CoreKit Browser", 0x4|0x30) == 6 {
				openDefaultBrowser("https://developer.microsoft.com/microsoft-edge/webview2/#download-section")
			}
		} else {
			msgBox("The browser engine could not start.\n\n"+err.Error(), "CoreKit Browser", 0x10)
		}
		return
	}
	messageLoop()
	if view != nil {
		view.close()
	}
}
