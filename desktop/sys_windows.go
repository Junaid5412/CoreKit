//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

var (
	kernel32           = syscall.NewLazyDLL("kernel32.dll")
	procSetConsoleMode = kernel32.NewProc("SetConsoleMode")
	procSetTitle       = kernel32.NewProc("SetConsoleTitleW")
	procGetCSBI        = kernel32.NewProc("GetConsoleScreenBufferInfo")
	procSetBufSize     = kernel32.NewProc("SetConsoleScreenBufferSize")
	procSetWinInfo     = kernel32.NewProc("SetConsoleWindowInfo")
	procLargestWin     = kernel32.NewProc("GetLargestConsoleWindowSize")
	shell32            = syscall.NewLazyDLL("shell32.dll")
	procIsUserAnAdmin  = shell32.NewProc("IsUserAnAdmin")
	user32             = syscall.NewLazyDLL("user32.dll")
	procGetMetrics     = user32.NewProc("GetSystemMetrics")
	ntdll              = syscall.NewLazyDLL("ntdll.dll")
	procRtlGetVersion  = ntdll.NewProc("RtlGetVersion")
)

const (
	enableProcessedOutput = 0x0001
	enableVTProcessing    = 0x0004
	enableLineInput       = 0x0002
	enableEchoInput       = 0x0004
	createNoWindow        = 0x08000000
)

func initConsole() {
	var mode uint32
	if syscall.GetConsoleMode(syscall.Stdout, &mode) == nil {
		procSetConsoleMode.Call(uintptr(syscall.Stdout), uintptr(mode|enableProcessedOutput|enableVTProcessing))
	}
	t, _ := syscall.UTF16PtrFromString("COREKIT :: TERMINAL")
	procSetTitle.Call(uintptr(unsafe.Pointer(t)))
	sizeConsole(104, 40, 3000)
}

type smallRect struct{ L, T, R, B int16 }
type screenBufInfo struct {
	SizeX, SizeY int16
	CurX, CurY   int16
	Attr         uint16
	Win          smallRect
	MaxX, MaxY   int16
}

// sizeConsole sets a visible window of cols x rows but keeps `history` lines of
// scroll-back (unlike "mode con", which shrinks the scroll-back to the window).
func sizeConsole(cols, rows, history int) {
	h := uintptr(syscall.Stdout)
	var ci screenBufInfo
	if r, _, _ := procGetCSBI.Call(h, uintptr(unsafe.Pointer(&ci))); r == 0 {
		return // not a classic console (e.g. Windows Terminal keeps its own scroll-back)
	}
	lg, _, _ := procLargestWin.Call(h)
	if mx := int(int16(lg & 0xffff)); mx > 0 && cols > mx {
		cols = mx
	}
	if my := int(int16((lg >> 16) & 0xffff)); my > 0 && rows > my {
		rows = my
	}
	curW := int(ci.Win.R-ci.Win.L) + 1
	curH := int(ci.Win.B-ci.Win.T) + 1
	if int(ci.SizeY) > history {
		history = int(ci.SizeY)
	}
	// 1) shrink window so the new buffer always fits, 2) set buffer, 3) set final window
	r1 := smallRect{0, 0, int16(min(cols, curW) - 1), int16(min(rows, curH) - 1)}
	procSetWinInfo.Call(h, 1, uintptr(unsafe.Pointer(&r1)))
	procSetBufSize.Call(h, uintptr(uint32(cols)|uint32(history)<<16))
	r2 := smallRect{0, 0, int16(cols - 1), int16(rows - 1)}
	procSetWinInfo.Call(h, 1, uintptr(unsafe.Pointer(&r2)))
}

func readKey() byte {
	var mode uint32
	h := syscall.Stdin
	if syscall.GetConsoleMode(h, &mode) == nil {
		procSetConsoleMode.Call(uintptr(h), uintptr(mode&^(enableLineInput|enableEchoInput)))
		defer procSetConsoleMode.Call(uintptr(h), uintptr(mode))
	}
	buf := make([]byte, 1)
	for {
		n, err := os.Stdin.Read(buf)
		if err != nil {
			return '0'
		}
		if n == 1 && buf[0] != '\r' && buf[0] != '\n' {
			return buf[0]
		}
	}
}

var procShellExecute = shell32.NewProc("ShellExecuteW")

// relaunchElevated asks for administrator rights (UAC) for the toolkit menu.
// Returns true if an elevated copy was started and this one should exit.
func relaunchElevated() bool {
	if isAdmin() {
		return false
	}
	exe, err := os.Executable()
	if err != nil {
		return false
	}
	var parts []string
	for _, a := range os.Args[1:] {
		parts = append(parts, syscall.EscapeArg(a))
	}
	verb, _ := syscall.UTF16PtrFromString("runas")
	file, _ := syscall.UTF16PtrFromString(exe)
	params, _ := syscall.UTF16PtrFromString(strings.Join(parts, " "))
	dir, _ := syscall.UTF16PtrFromString(filepath.Dir(exe))
	r, _, _ := procShellExecute.Call(0, uintptr(unsafe.Pointer(verb)), uintptr(unsafe.Pointer(file)), uintptr(unsafe.Pointer(params)), uintptr(unsafe.Pointer(dir)), 1)
	return r > 32
}

func isAdmin() bool {
	r, _, _ := procIsUserAnAdmin.Call()
	return r != 0
}

type osVersionInfo struct {
	size, major, minor, build, platform uint32
	csd                                 [128]uint16
}

func osName() string {
	var v osVersionInfo
	v.size = uint32(unsafe.Sizeof(v))
	procRtlGetVersion.Call(uintptr(unsafe.Pointer(&v)))
	name := "Windows 10"
	if v.build >= 22000 {
		name = "Windows 11"
	}
	if v.major < 10 {
		name = fmt.Sprintf("Windows %d.%d", v.major, v.minor)
	}
	return fmt.Sprintf("%s  (build %d)", name, v.build)
}

type appWindow struct {
	cmd     *exec.Cmd
	done    atomic.Bool
	profile string
}

func (a *appWindow) exited() bool { return a.cmd == nil || a.done.Load() }

// keepTag identifies our own app-window browser process (protected from "close browsers").
func (a *appWindow) keepTag() string { return filepath.Base(a.profile) }

func openTarget(what string) {
	sr := os.Getenv("SystemRoot")
	switch what {
	case "portal":
		openDefaultBrowser("http://www.msftconnecttest.com/redirect")
	case "wifi":
		_ = exec.Command(sr+`\explorer.exe`, "ms-settings:network-wifi").Start()
	case "network":
		_ = exec.Command(sr+`\explorer.exe`, "ms-settings:network-status").Start()
	case "devmgmt":
		_ = exec.Command(sr+`\System32\mmc.exe`, "devmgmt.msc").Start()
	case "ncpa":
		_ = exec.Command(sr+`\System32\control.exe`, "ncpa.cpl").Start()
	}
}

func (a *appWindow) cleanup() {
	if a.cmd != nil && !a.done.Load() && a.cmd.Process != nil {
		_ = a.cmd.Process.Kill()
	}
	if a.profile != "" {
		for i := 0; i < 10; i++ {
			if os.RemoveAll(a.profile) == nil {
				break
			}
			time.Sleep(400 * time.Millisecond)
		}
	}
}

func findBrowser() string {
	cands := []string{}
	for _, env := range []string{"ProgramFiles(x86)", "ProgramFiles", "LOCALAPPDATA"} {
		if b := os.Getenv(env); b != "" {
			cands = append(cands, filepath.Join(b, `Microsoft\Edge\Application\msedge.exe`))
		}
	}
	for _, env := range []string{"ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA"} {
		if b := os.Getenv(env); b != "" {
			cands = append(cands, filepath.Join(b, `Google\Chrome\Application\chrome.exe`))
		}
	}
	for _, c := range cands {
		if st, err := os.Stat(c); err == nil && !st.IsDir() {
			return c
		}
	}
	return ""
}

func screenSize() (int, int) {
	w, _, _ := procGetMetrics.Call(0)
	h, _, _ := procGetMetrics.Call(1)
	return int(w), int(h)
}

// launchWindow opens the UI as a standalone app window (Edge/Chrome --app mode, private temp profile).
func launchWindow(url string) *appWindow {
	if p := os.Getenv("PCHI_URLFILE"); p != "" { // automated tests drive the page themselves
		os.WriteFile(p, []byte(url), 0644)
		return nil
	}
	br := findBrowser()
	if br == "" {
		openDefaultBrowser(url)
		return nil
	}
	profile, _ := os.MkdirTemp("", "corekit-ui-")
	sw, sh := screenSize()
	w, h := 1280, 840
	if sw > 0 && sw < w+40 {
		w = sw * 92 / 100
	}
	if sh > 0 && sh < h+80 {
		h = sh * 88 / 100
	}
	x, y := (sw-w)/2, (sh-h)/2-20
	if y < 0 {
		y = 0
	}
	args := []string{
		"--app=" + url,
		"--user-data-dir=" + profile,
		fmt.Sprintf("--window-size=%d,%d", w, h),
		fmt.Sprintf("--window-position=%d,%d", x, y),
		"--no-first-run", "--no-default-browser-check", "--disable-sync", "--disable-extensions",
		"--disable-background-mode", // the browser must exit when the window closes
		"--hide-crash-restore-bubble", "--disable-background-timer-throttling",
		"--disable-renderer-backgrounding", "--disable-backgrounding-occluded-windows",
		"--disable-features=Translate,msEdgeShopping,msUndersideButton,msEdgeSidebarV2,EdgeCollections",
		"--autoplay-policy=no-user-gesture-required",
	}
	cmd := exec.Command(br, args...)
	if err := cmd.Start(); err != nil {
		openDefaultBrowser(url)
		return nil
	}
	a := &appWindow{cmd: cmd, profile: profile}
	go func() { _ = cmd.Wait(); a.done.Store(true) }()
	return a
}

func openDefaultBrowser(url string) {
	c := exec.Command(os.Getenv("SystemRoot")+`\System32\rundll32.exe`, "url.dll,FileProtocolHandler", url)
	_ = c.Start()
}

func revealFile(path string) {
	exe := os.Getenv("SystemRoot") + `\explorer.exe`
	c := exec.Command(exe)
	c.SysProcAttr = &syscall.SysProcAttr{CmdLine: fmt.Sprintf(`"%s" /select,"%s"`, exe, path)}
	_ = c.Start()
}
