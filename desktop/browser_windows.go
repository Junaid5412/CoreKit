//go:build windows

package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const (
	engineFile  = "xray.exe"
	engineAsset = "Xray-windows-64.zip"
)

var (
	crypt32          = syscall.NewLazyDLL("crypt32.dll")
	procProtect      = crypt32.NewProc("CryptProtectData")
	procUnprotect    = crypt32.NewProc("CryptUnprotectData")
	procLocalFree    = kernel32.NewProc("LocalFree")
	advapi32         = syscall.NewLazyDLL("advapi32.dll")
	procDupTokenEx   = advapi32.NewProc("DuplicateTokenEx")
	procCreateWithTk = advapi32.NewProc("CreateProcessWithTokenW")
	procShellWindow  = user32.NewProc("GetShellWindow")
	procWinThreadPID = user32.NewProc("GetWindowThreadProcessId")
	procCreateJob    = kernel32.NewProc("CreateJobObjectW")
	procSetJobInfo   = kernel32.NewProc("SetInformationJobObject")
	procAssignJob    = kernel32.NewProc("AssignProcessToJobObject")
	engineJob        syscall.Handle
)

func appDataRoot() string {
	b := os.Getenv("LOCALAPPDATA")
	if b == "" {
		b, _ = os.UserConfigDir()
	}
	d := filepath.Join(b, "CoreKit")
	os.MkdirAll(d, 0700)
	return d
}

// ---------------------------------------------------------------- DPAPI (encryption tied to this Windows user)

type dataBlob struct {
	n    uint32
	data *byte
}

func blobOf(b []byte) *dataBlob {
	if len(b) == 0 {
		return &dataBlob{}
	}
	return &dataBlob{n: uint32(len(b)), data: &b[0]}
}

func (b *dataBlob) bytes() []byte {
	out := make([]byte, b.n)
	copy(out, unsafe.Slice(b.data, b.n))
	return out
}

var entropy = []byte("CoreKit.SafeBrowser.v1")

func protect(plain []byte) ([]byte, error) {
	var out dataBlob
	r, _, err := procProtect.Call(uintptr(unsafe.Pointer(blobOf(plain))), 0, uintptr(unsafe.Pointer(blobOf(entropy))), 0, 0, 0x1, uintptr(unsafe.Pointer(&out)))
	if r == 0 {
		return nil, err
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(out.data)))
	return out.bytes(), nil
}

func unprotect(enc []byte) ([]byte, error) {
	var out dataBlob
	r, _, err := procUnprotect.Call(uintptr(unsafe.Pointer(blobOf(enc))), 0, uintptr(unsafe.Pointer(blobOf(entropy))), 0, 0, 0x1, uintptr(unsafe.Pointer(&out)))
	if r == 0 {
		return nil, err
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(out.data)))
	return out.bytes(), nil
}

// ---------------------------------------------------------------- engine process

func engineCommand(exe string, args ...string) *exec.Cmd {
	c := exec.Command(exe, args...)
	c.Dir = filepath.Dir(exe)
	c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
	return c
}

type jobBasic struct {
	PerProcessUserTimeLimit int64
	PerJobUserTimeLimit     int64
	LimitFlags              uint32
	MinimumWorkingSetSize   uintptr
	MaximumWorkingSetSize   uintptr
	ActiveProcessLimit      uint32
	Affinity                uintptr
	PriorityClass           uint32
	SchedulingClass         uint32
}
type ioCounters struct{ a, b, c, d, e, f uint64 }
type jobExtended struct {
	Basic                 jobBasic
	IO                    ioCounters
	ProcessMemoryLimit    uintptr
	JobMemoryLimit        uintptr
	PeakProcessMemoryUsed uintptr
	PeakJobMemoryUsed     uintptr
}

// bindToJob makes Windows kill the engine automatically if CoreKit exits or crashes.
func bindToJob(c *exec.Cmd) {
	if engineJob == 0 {
		h, _, _ := procCreateJob.Call(0, 0)
		if h == 0 {
			return
		}
		info := jobExtended{}
		info.Basic.LimitFlags = 0x2000 // JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
		procSetJobInfo.Call(h, 9, uintptr(unsafe.Pointer(&info)), unsafe.Sizeof(info))
		engineJob = syscall.Handle(h)
	}
	ph, err := syscall.OpenProcess(0x0100|0x0001, false, uint32(c.Process.Pid)) // SET_QUOTA | TERMINATE
	if err != nil {
		return
	}
	procAssignJob.Call(uintptr(engineJob), uintptr(ph))
	syscall.CloseHandle(ph)
}

// ---------------------------------------------------------------- browsers

func findBrowserPaths() (edge, chrome string) {
	look := func(rel string) string {
		for _, env := range []string{"ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA"} {
			if b := os.Getenv(env); b != "" {
				p := filepath.Join(b, rel)
				if st, err := os.Stat(p); err == nil && !st.IsDir() {
					return p
				}
			}
		}
		return ""
	}
	return look(`Microsoft\Edge\Application\msedge.exe`), look(`Google\Chrome\Application\chrome.exe`)
}

// launchUnelevated starts the browser with the desktop user's normal (non-admin) rights,
// using the token of the Windows shell. Falls back to a normal start if that is not possible.
func launchUnelevated(exe string, args []string, flags uint32) error {
	parts := []string{syscall.EscapeArg(exe)}
	for _, a := range args {
		parts = append(parts, syscall.EscapeArg(a))
	}
	cmdline := strings.Join(parts, " ")
	if !isAdmin() {
		c := exec.Command(exe, args...)
		c.SysProcAttr = &syscall.SysProcAttr{CreationFlags: flags}
		return c.Start()
	}
	err := createWithShellToken(exe, cmdline, flags)
	if err == nil {
		return nil
	}
	sbLog("unelevated launch failed (%v) - starting normally", err)
	c := exec.Command(exe, args...)
	c.SysProcAttr = &syscall.SysProcAttr{CreationFlags: flags}
	return c.Start()
}

// launchBrowserWindow opens CoreKit Browser's profile picker as its own process.
func launchBrowserWindow() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return "choose a profile", launchUnelevated(exe, []string{"--pick"}, createNoWindow)
}

func createWithShellToken(exe, cmdline string, flags uint32) error {
	hwnd, _, _ := procShellWindow.Call()
	if hwnd == 0 {
		return errors.New("no shell window")
	}
	var pid uint32
	procWinThreadPID.Call(hwnd, uintptr(unsafe.Pointer(&pid)))
	if pid == 0 {
		return errors.New("no shell pid")
	}
	hp, err := syscall.OpenProcess(0x0400, false, pid) // PROCESS_QUERY_INFORMATION
	if err != nil {
		return err
	}
	defer syscall.CloseHandle(hp)
	var tok syscall.Token
	if err := syscall.OpenProcessToken(hp, 0x0002|0x0008|0x0001, &tok); err != nil { // DUPLICATE|QUERY|ASSIGN_PRIMARY
		return err
	}
	defer tok.Close()
	var dup syscall.Handle
	if r, _, e := procDupTokenEx.Call(uintptr(tok), 0x02000000, 0, 2, 1, uintptr(unsafe.Pointer(&dup))); r == 0 {
		return e
	}
	defer syscall.CloseHandle(dup)
	si := syscall.StartupInfo{}
	si.Cb = uint32(unsafe.Sizeof(si))
	if flags&createNoWindow != 0 { // CreateProcessWithTokenW does not take CREATE_NO_WINDOW: start the console hidden instead
		si.Flags, si.ShowWindow = 0x1, 0 // STARTF_USESHOWWINDOW, SW_HIDE
		flags &^= createNoWindow
	}
	var pi syscall.ProcessInformation
	app, _ := syscall.UTF16PtrFromString(exe)
	cl, _ := syscall.UTF16PtrFromString(cmdline)
	cwd, _ := syscall.UTF16PtrFromString(filepath.Dir(exe))
	r, _, e := procCreateWithTk.Call(uintptr(dup), 0, uintptr(unsafe.Pointer(app)), uintptr(unsafe.Pointer(cl)), uintptr(flags), 0, uintptr(unsafe.Pointer(cwd)), uintptr(unsafe.Pointer(&si)), uintptr(unsafe.Pointer(&pi)))
	if r == 0 {
		return e
	}
	syscall.CloseHandle(pi.Thread)
	syscall.CloseHandle(pi.Process)
	return nil
}

// profileRunning: Chromium keeps "lockfile" open (no delete sharing) while the profile is in use.
func profileRunning(dir string) bool {
	lf := filepath.Join(dir, "lockfile")
	if _, err := os.Stat(lf); err != nil {
		return false
	}
	return os.Remove(lf) != nil
}

var closeScript = []byte(`param([string]$Dir)
$ErrorActionPreference = 'SilentlyContinue'
$n = 0
Get-CimInstance Win32_Process -Filter "Name='msedge.exe' OR Name='chrome.exe'" | Where-Object { $_.CommandLine -and $_.CommandLine.IndexOf($Dir, [StringComparison]::OrdinalIgnoreCase) -ge 0 -and $_.CommandLine -notmatch '--type=' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force; $n++ }
[Console]::Out.WriteLine('R|{"closed":' + $n + '}')
`)

// closeProfile closes the browser instance that uses this profile folder.
func closeProfile(dir string) {
	if !profileRunning(dir) {
		return
	}
	ctx, cancel := contextTimeout(20 * time.Second)
	defer cancel()
	_, _ = runPS(ctx, closeScript, []string{"-Dir", dir}, func(string, string, string) {})
	for i := 0; i < 25 && profileRunning(dir); i++ {
		time.Sleep(200 * time.Millisecond)
	}
}
