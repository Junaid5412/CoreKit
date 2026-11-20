//go:build windows

package main

// Security module, Windows side: running the collector and fixer, stopping processes,
// Quarantine moves, and Live Shield (a background watcher started by Task Scheduler at sign-in).

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"
)

var (
	procQueryImageName = kernel32.NewProc("QueryFullProcessImageNameW")
	procMoveFileEx     = kernel32.NewProc("MoveFileExW")
	procNtQueryInfo    = ntdll.NewProc("NtQueryInformationProcess")
	procNtSuspend      = ntdll.NewProc("NtSuspendProcess")
	procNtResume       = ntdll.NewProc("NtResumeProcess")
	wintrust           = syscall.NewLazyDLL("wintrust.dll")
	procWinVerifyTrust = wintrust.NewProc("WinVerifyTrust")
)

const (
	processTerminate     = 0x0001
	processSuspendResume = 0x0800
	processQueryLimited  = 0x1000
	shieldTask           = "CoreKit Live Shield"
)

func secDir() string {
	if isAdmin() {
		d := filepath.Join(os.Getenv("ProgramData"), "CoreKit", "Security")
		if os.MkdirAll(d, 0700) == nil {
			// only SYSTEM and administrators may read the store and the Quarantine
			c := exec.Command(filepath.Join(os.Getenv("SystemRoot"), "System32", "icacls.exe"), d, "/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F")
			c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
			_ = c.Run()
			return d
		}
	}
	d := filepath.Join(appDataRoot(), "Security")
	os.MkdirAll(d, 0700)
	return d
}

func secProtect(b []byte) ([]byte, error)   { return protect(b) }
func secUnprotect(b []byte) ([]byte, error) { return unprotect(b) }

func secCollect(ctx context.Context, cb func(kind, a, b string)) ([]byte, error) {
	return runPS(ctx, securityPS, nil, cb)
}

type psFix struct {
	OK   bool            `json:"ok"`
	Msg  string          `json:"msg"`
	Undo json.RawMessage `json:"undo"`
	Data json.RawMessage `json:"data"`
}

func secRunFix(ctx context.Context, req map[string]any) (psFix, error) {
	f, err := os.CreateTemp("", "corekit-req-*.json")
	if err != nil {
		return psFix{}, err
	}
	defer os.Remove(f.Name())
	_ = json.NewEncoder(f).Encode(req)
	f.Close()
	out, err := runPS(ctx, securityFixPS, []string{"-req", f.Name()}, func(_, _, _ string) {})
	if err != nil {
		return psFix{}, err
	}
	var r psFix
	if err := json.Unmarshal(out, &r); err != nil {
		return psFix{}, err
	}
	if !r.OK {
		return r, errors.New(r.Msg)
	}
	if string(r.Undo) == "null" {
		r.Undo = nil
	}
	return r, nil
}

func secAutorunRemove(ctx context.Context, a autoRef) (json.RawMessage, error) {
	if strings.HasPrefix(a.Key, "file|") { // a file in the Startup folder: quarantine it
		m, err := quarantineFile(strings.TrimPrefix(a.Key, "file|"), a.Name)
		if err != nil {
			return nil, err
		}
		b, _ := json.Marshal(map[string]string{"op": "q", "id": m.ID})
		return b, nil
	}
	r, err := secRunFix(ctx, map[string]any{"op": "autorun-remove", "key": a.Key})
	return r.Undo, err
}

func secFixSetting(ctx context.Context, key string) (json.RawMessage, error) {
	r, err := secRunFix(ctx, map[string]any{"op": "fixsetting", "key": key})
	return r.Undo, err
}

func secUndo(ctx context.Context, raw json.RawMessage) error {
	var u struct {
		Op string `json:"op"`
		ID string `json:"id"`
	}
	_ = json.Unmarshal(raw, &u)
	if u.Op == "q" {
		_, err := restoreQuarantine(u.ID)
		return err
	}
	_, err := secRunFix(ctx, map[string]any{"op": "undo", "undo": raw})
	return err
}

func secHarden(ctx context.Context, ids []string) (hardenOut, error) {
	r, err := secRunFix(ctx, map[string]any{"op": "harden", "ids": ids, "asr": asrRules})
	if err != nil {
		return hardenOut{}, err
	}
	var out hardenOut
	if e := json.Unmarshal(r.Data, &out); e != nil {
		return hardenOut{}, errors.New("Windows did not report back. Try again.")
	}
	out.fill()
	return out, nil
}

// secProtStatus reads the real state of each protection from Windows (nothing is assumed).
func secProtStatus(ctx context.Context, ids []string) ([]protRes, error) {
	r, err := secRunFix(ctx, map[string]any{"op": "protstatus", "ids": ids, "asr": asrRules})
	if err != nil {
		return nil, err
	}
	var out []protRes
	if e := json.Unmarshal(r.Data, &out); e != nil {
		return nil, e
	}
	for i := range out {
		out[i].Name = protName(out[i].ID)
		out[i].OK = out[i].State == "on"
	}
	return out, nil
}

// secFileInfo asks Windows for the facts it records about a file: owner, times, streams,
// version resource and signature details.
func secFileInfo(ctx context.Context, path string) (json.RawMessage, error) {
	r, err := secRunFix(ctx, map[string]any{"op": "fileinfo", "path": path})
	if err != nil {
		return r.Data, err
	}
	// trust and owner come from Windows directly (WinVerifyTrust, `dir /q`)
	var m map[string]any
	if json.Unmarshal(r.Data, &m) != nil || m == nil {
		return r.Data, nil
	}
	sig, _ := m["sig"].(map[string]any)
	if sig == nil {
		sig = map[string]any{}
	}
	st := map[string]string{"valid": "Valid", "unsigned": "NotSigned", "invalid": "HashMismatch"}[fileSigned(path)]
	if st == "" {
		st = "UnknownError"
	}
	sig["status"] = st
	m["sig"] = sig
	if o := fileOwner(ctx, path); o != "" {
		m["owner"] = o
	}
	b, _ := json.Marshal(m)
	return b, nil
}

// fileOwner reads the owner column of `dir /q` (the account that owns the file).
func fileOwner(ctx context.Context, path string) string {
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, filepath.Join(os.Getenv("SystemRoot"), `System32\cmd.exe`), "/c", "dir", "/q", "/a", path)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	base := filepath.Base(path)
	for _, l := range strings.Split(string(out), "\n") {
		l = strings.TrimRight(l, "\r ")
		if strings.HasSuffix(l, " "+base) {
			if m := dirOwnerRe.FindStringSubmatch(strings.TrimSuffix(l, " "+base)); m != nil {
				return strings.TrimSpace(m[1])
			}
		}
	}
	return ""
}

var dirOwnerRe = regexp.MustCompile(`(?i)\d{1,2}:\d{2}(?:\s*[ap]m)?\s+(?:<\w+>|[\d,.]+)\s+(.+)$`)

func secBloatAction(ctx context.Context, b secBloat) (string, json.RawMessage, error) {
	r, err := secRunFix(ctx, map[string]any{"op": "bloat", "kind": b.Kind, "key": b.Key})
	return r.Msg, r.Undo, err
}

var threatLine = regexp.MustCompile(`(?m)^\s*Threat\s*:\s*(.+?)\s*$`)

// secDefenderScan asks Windows Defender about one file: (name, true) if it is a threat,
// ("", true) if clean, ("", false) if Defender is not available.
func secDefenderScan(ctx context.Context, path string) (string, bool) {
	cands := []string{filepath.Join(os.Getenv("ProgramFiles"), "Windows Defender", "MpCmdRun.exe")}
	if ents, _ := filepath.Glob(filepath.Join(os.Getenv("ProgramData"), `Microsoft\Windows Defender\Platform\*\MpCmdRun.exe`)); len(ents) > 0 {
		cands = append([]string{ents[len(ents)-1]}, cands...)
	}
	exe := ""
	for _, c := range cands {
		if st, err := os.Stat(c); err == nil && !st.IsDir() {
			exe = c
			break
		}
	}
	if exe == "" {
		return "", false
	}
	cctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, exe, "-Scan", "-ScanType", "3", "-File", path, "-DisableRemediation")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
	out, err := cmd.CombinedOutput()
	if m := threatLine.FindSubmatch(out); m != nil {
		return string(m[1]), true
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) && ee.ExitCode() == 2 {
		return "a threat", true
	}
	if err != nil && !errors.As(err, &ee) {
		return "", false
	}
	return "", true
}

// ---------------------------------------------------------------- processes

type procInfo struct {
	PID, PPID int
	Name      string
	Path      string
	Start     int64 // creation time, 100 ns ticks
}

func openProc(pid int, access uint32) (syscall.Handle, error) {
	return syscall.OpenProcess(access, false, uint32(pid))
}

func procImage(h syscall.Handle) string {
	buf := make([]uint16, 1024)
	n := uint32(len(buf))
	r, _, _ := procQueryImageName.Call(uintptr(h), 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&n)))
	if r == 0 {
		return ""
	}
	return syscall.UTF16ToString(buf[:n])
}

func procStart(h syscall.Handle) int64 {
	var c, e, k, u syscall.Filetime
	if syscall.GetProcessTimes(h, &c, &e, &k, &u) != nil {
		return 0
	}
	return int64(c.HighDateTime)<<32 | int64(c.LowDateTime)
}

// procCmdLine reads a process's command line (ProcessCommandLineInformation, Windows 8.1+).
func procCmdLine(h syscall.Handle) string {
	buf := make([]byte, 32<<10)
	var ret uint32
	st, _, _ := procNtQueryInfo.Call(uintptr(h), 60, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), uintptr(unsafe.Pointer(&ret)))
	if st != 0 {
		return ""
	}
	n := int(*(*uint16)(unsafe.Pointer(&buf[0])))
	p := *(*uintptr)(unsafe.Pointer(&buf[8]))
	if n == 0 || p == 0 {
		return ""
	}
	off := int(p - uintptr(unsafe.Pointer(&buf[0])))
	if off < 0 || off+n > len(buf) {
		return ""
	}
	u := unsafe.Slice((*uint16)(unsafe.Pointer(&buf[off])), n/2)
	return string(utf16.Decode(u))
}

func listProcs(full bool) []procInfo {
	snap, err := syscall.CreateToolhelp32Snapshot(syscall.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil
	}
	defer syscall.CloseHandle(snap)
	var pe syscall.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	out := []procInfo{}
	for err = syscall.Process32First(snap, &pe); err == nil; err = syscall.Process32Next(snap, &pe) {
		p := procInfo{PID: int(pe.ProcessID), PPID: int(pe.ParentProcessID), Name: syscall.UTF16ToString(pe.ExeFile[:])}
		if full && p.PID > 4 {
			if h, e := openProc(p.PID, processQueryLimited); e == nil {
				p.Path = procImage(h)
				p.Start = procStart(h)
				syscall.CloseHandle(h)
			}
		}
		out = append(out, p)
	}
	return out
}

func secPIDsOf(path string) []int {
	var out []int
	for _, p := range listProcs(true) {
		if p.Path != "" && strings.EqualFold(normPath(p.Path), normPath(path)) {
			out = append(out, p.PID)
		}
	}
	return out
}

var critical = map[string]bool{"csrss.exe": true, "lsass.exe": true, "wininit.exe": true, "winlogon.exe": true, "smss.exe": true, "services.exe": true, "system": true, "registry": true}

func secKill(pid int) error {
	if pid <= 4 || pid == os.Getpid() {
		return errors.New("protected process")
	}
	h, err := openProc(pid, processTerminate|processQueryLimited)
	if err != nil {
		return err
	}
	defer syscall.CloseHandle(h)
	img := procImage(h)
	if critical[lc(filepath.Base(img))] && sysDir(img) {
		return errors.New("Windows needs this process to run")
	}
	return syscall.TerminateProcess(h, 1)
}

func suspendPID(pid int, on bool) bool {
	h, err := openProc(pid, processSuspendResume)
	if err != nil {
		return false
	}
	defer syscall.CloseHandle(h)
	p := procNtResume
	if on {
		p = procNtSuspend
	}
	r, _, _ := p.Call(uintptr(h))
	return r == 0
}

// removeFileHard deletes a file; if Windows still holds it, it is deleted at the next restart.
func removeFileHard(path string) error {
	var err error
	for i := 0; i < 6; i++ {
		if err = os.Remove(path); err == nil || os.IsNotExist(err) {
			return nil
		}
		_ = os.Chmod(path, 0666)
		time.Sleep(250 * time.Millisecond)
	}
	p, _ := syscall.UTF16PtrFromString(path)
	if r, _, _ := procMoveFileEx.Call(uintptr(unsafe.Pointer(p)), 0, 4 /* MOVEFILE_DELAY_UNTIL_REBOOT */); r != 0 {
		logLine("~", "File is in use; it will be deleted when Windows restarts: "+path)
		return nil
	}
	return err
}

// ---------------------------------------------------------------- signatures (WinVerifyTrust)

var actionGenericVerifyV2 = guid{0xaac56b, 0xcd44, 0x11d0, [8]byte{0x8c, 0xc2, 0x00, 0xc0, 0x4f, 0xc2, 0x95, 0xee}}

type winTrustFileInfo struct {
	cbStruct       uint32
	pcwszFilePath  *uint16
	hFile          uintptr
	pgKnownSubject uintptr
}

type winTrustData struct {
	cbStruct            uint32
	pPolicyCallbackData uintptr
	pSIPClientData      uintptr
	dwUIChoice          uint32
	fdwRevocationChecks uint32
	dwUnionChoice       uint32
	pFile               *winTrustFileInfo
	dwStateAction       uint32
	hWVTStateData       uintptr
	pwszURLReference    *uint16
	dwProvFlags         uint32
	dwUIContext         uint32
	pSignatureSettings  uintptr
}

// fileSigned checks an embedded Authenticode signature (system files signed by catalog are
// covered by the folder check instead).
func fileSigned(path string) string {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return "unknown"
	}
	fi := winTrustFileInfo{pcwszFilePath: p}
	fi.cbStruct = uint32(unsafe.Sizeof(fi))
	d := winTrustData{dwUIChoice: 2, dwUnionChoice: 1, pFile: &fi, dwStateAction: 1, dwProvFlags: 0x10 | 0x1000}
	d.cbStruct = uint32(unsafe.Sizeof(d))
	r, _, _ := procWinVerifyTrust.Call(^uintptr(0), uintptr(unsafe.Pointer(&actionGenericVerifyV2)), uintptr(unsafe.Pointer(&d)))
	d.dwStateAction = 2
	procWinVerifyTrust.Call(^uintptr(0), uintptr(unsafe.Pointer(&actionGenericVerifyV2)), uintptr(unsafe.Pointer(&d)))
	switch uint32(r) {
	case 0:
		return "valid"
	case 0x800B0100: // TRUST_E_NOSIGNATURE
		return "unsigned"
	case 0x80096010, 0x800B0004, 0x800B0109, 0x800B010C: // bad digest, subject not trusted, untrusted root, revoked
		return "invalid"
	}
	return "unknown"
}

func zoneOf(path string) int {
	b, err := os.ReadFile(path + ":Zone.Identifier")
	if err != nil {
		return -1
	}
	if m := regexp.MustCompile(`ZoneId=(\d)`).FindSubmatch(b); m != nil {
		return int(m[1][0] - '0')
	}
	return -1
}

func fileSHA(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	if st, err := f.Stat(); err != nil || st.Size() > 150<<20 {
		return ""
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

// ---------------------------------------------------------------- Live Shield

type shieldState struct {
	PID     int    `json:"pid"`
	Started int64  `json:"started"`
	Beat    int64  `json:"beat"`
	Checked int    `json:"checked"`
	Blocked int    `json:"blocked"`
	Warned  int    `json:"warned"`
	Version string `json:"version"`
	Exe     string `json:"exe"`
}

func shieldExe() string {
	return filepath.Join(os.Getenv("ProgramFiles"), "CoreKit", "CoreKit.exe")
}

func schtasks(args ...string) ([]byte, error) {
	c := exec.Command(filepath.Join(os.Getenv("SystemRoot"), "System32", "schtasks.exe"), args...)
	c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
	return c.CombinedOutput()
}

func secShieldStatus() map[string]any {
	secDB.open()
	out := map[string]any{"platform": "windows", "installed": false, "running": false, "admin": isAdmin()}
	if _, err := schtasks("/Query", "/TN", shieldTask); err == nil {
		out["installed"] = true
	}
	if b, err := os.ReadFile(filepath.Join(secDB.dir, "shield.json")); err == nil {
		var s shieldState
		if json.Unmarshal(b, &s) == nil {
			out["running"] = time.Now().Unix()-s.Beat < 25
			out["since"] = s.Started
			out["checked"] = s.Checked
			out["blocked"] = s.Blocked
			out["warned"] = s.Warned
		}
	}
	return out
}

func currentUserSID() string {
	tok, err := syscall.OpenCurrentProcessToken()
	if err != nil {
		return ""
	}
	defer tok.Close()
	u, err := tok.GetTokenUser()
	if err != nil {
		return ""
	}
	s, _ := u.User.Sid.String()
	return s
}

func secShieldSet(on bool) error {
	if !isAdmin() {
		return errors.New("Live Shield needs CoreKit to run as administrator")
	}
	stop := func() {
		_, _ = schtasks("/End", "/TN", shieldTask)
		if b, err := os.ReadFile(filepath.Join(secDB.dir, "shield.json")); err == nil {
			var s shieldState
			if json.Unmarshal(b, &s) == nil && s.PID > 0 {
				if h, err := openProc(s.PID, processTerminate|processQueryLimited); err == nil {
					if strings.EqualFold(filepath.Base(procImage(h)), "CoreKit.exe") {
						_ = syscall.TerminateProcess(h, 0)
					}
					syscall.CloseHandle(h)
				}
			}
		}
	}
	if !on {
		stop()
		_, _ = schtasks("/Delete", "/TN", shieldTask, "/F")
		_ = os.Remove(filepath.Join(secDB.dir, "shield.json"))
		return nil
	}
	stop()
	// a stable copy in Program Files (only administrators can replace it)
	self, err := os.Executable()
	if err != nil {
		return err
	}
	dst := shieldExe()
	if !strings.EqualFold(self, dst) {
		_ = os.MkdirAll(filepath.Dir(dst), 0755)
		b, err := os.ReadFile(self)
		if err != nil {
			return err
		}
		time.Sleep(400 * time.Millisecond)
		if err := os.WriteFile(dst, b, 0755); err != nil {
			return fmt.Errorf("could not copy CoreKit to Program Files: %w", err)
		}
	}
	sid := currentUserSID()
	xml := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>CoreKit Live Shield: checks programs as they start and stops threats.</Description><Author>CoreKit</Author></RegistrationInfo>
  <Triggers><LogonTrigger><Enabled>true</Enabled><UserId>%s</UserId></LogonTrigger></Triggers>
  <Principals><Principal id="Author"><UserId>%s</UserId><LogonType>InteractiveToken</LogonType><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <IdleSettings><StopOnIdleEnd>false</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>6</Priority>
    <RestartOnFailure><Interval>PT1M</Interval><Count>99</Count></RestartOnFailure>
  </Settings>
  <Actions Context="Author"><Exec><Command>"%s"</Command><Arguments>--shield</Arguments></Exec></Actions>
</Task>`, sid, sid, dst)
	u := utf16.Encode([]rune(xml))
	var buf bytes.Buffer
	buf.Write([]byte{0xFF, 0xFE})
	for _, c := range u {
		buf.WriteByte(byte(c))
		buf.WriteByte(byte(c >> 8))
	}
	tf, err := os.CreateTemp("", "corekit-shield-*.xml")
	if err != nil {
		return err
	}
	tf.Write(buf.Bytes())
	tf.Close()
	defer os.Remove(tf.Name())
	if out, err := schtasks("/Create", "/TN", shieldTask, "/XML", tf.Name(), "/F"); err != nil {
		return fmt.Errorf("could not register Live Shield: %s", strings.TrimSpace(string(out)))
	}
	if out, err := schtasks("/Run", "/TN", shieldTask); err != nil {
		return fmt.Errorf("Live Shield is set up but did not start: %s", strings.TrimSpace(string(out)))
	}
	for i := 0; i < 20; i++ {
		time.Sleep(250 * time.Millisecond)
		if st := secShieldStatus(); st["running"] == true {
			break
		}
	}
	return nil
}

func messageBox(title, text string, flags uintptr) int {
	t, _ := syscall.UTF16PtrFromString(title)
	m, _ := syscall.UTF16PtrFromString(text)
	r, _, _ := procMessageBox.Call(0, uintptr(unsafe.Pointer(m)), uintptr(unsafe.Pointer(t)), flags)
	return int(r)
}

const (
	mbOK          = 0x0
	mbYesNo       = 0x4
	mbIconWarning = 0x30
	mbIconInfo    = 0x40
	mbTopmost     = 0x40000
	mbSetFg       = 0x10000
	mbSysModal    = 0x1000
)

var alertMu sync.Mutex
var lastAlert = map[string]time.Time{}

func shieldAlert(title string, ev shieldEvent, rs []secReason, blocked bool) {
	alertMu.Lock()
	k := lc(ev.Path + ev.Name)
	if t, ok := lastAlert[k]; ok && time.Since(t) < 90*time.Second {
		alertMu.Unlock()
		return
	}
	lastAlert[k] = time.Now()
	alertMu.Unlock()
	why := []string{}
	for _, r := range rs {
		if r.W > 0 && len(why) < 3 {
			why = append(why, "• "+r.Text)
		}
	}
	where := ev.Path
	if where == "" {
		where = ev.Name
	}
	go func() {
		if blocked {
			msg := fmt.Sprintf("CoreKit stopped a threat before it could do harm.\n\n%s\n%s\n\nWhy:\n%s\n\nIt was moved to Quarantine. You can restore it from CoreKit › Security › History.\n\nOpen CoreKit Security now?", ev.Name, where, strings.Join(why, "\n"))
			if messageBox(title, msg, mbYesNo|mbIconWarning|mbTopmost|mbSetFg|mbSysModal) == 6 {
				if self, err := os.Executable(); err == nil {
					_ = exec.Command(self, "--no-elevate", "--serve", "security").Start()
				}
			}
			return
		}
		msg := fmt.Sprintf("CoreKit noticed something suspicious and let it run.\n\n%s\n%s\n\nWhy:\n%s\n\nIf you didn't start this, open CoreKit › Security and run a scan.", ev.Name, where, strings.Join(why, "\n"))
		messageBox(title, msg, mbOK|mbIconInfo|mbTopmost|mbSetFg)
	}()
}

// runShield is the background watcher (CoreKit.exe --shield, started by Task Scheduler).
func runShield() int {
	name, _ := syscall.UTF16PtrFromString(`Global\CoreKitLiveShield`)
	h, _, e := procCreateMutex.Call(0, 0, uintptr(unsafe.Pointer(name)))
	if h == 0 || e == syscall.ERROR_ALREADY_EXISTS {
		return 0
	}
	secDB.open()
	self, _ := os.Executable()
	st := shieldState{PID: os.Getpid(), Started: time.Now().Unix(), Version: appVersion, Exe: self}
	statePath := filepath.Join(secDB.dir, "shield.json")
	writeState := func() {
		st.Beat = time.Now().Unix()
		b, _ := json.Marshal(st)
		_ = os.WriteFile(statePath, b, 0600)
	}
	writeState()
	trusted := secDB.trustedFn()
	key := secDB.apiKey()
	known := map[string]bool{}
	byPID := map[int]procInfo{}
	sigCache := map[string]string{}
	pkey := func(p procInfo) string { return fmt.Sprintf("%d:%d", p.PID, p.Start) }
	for _, p := range listProcs(true) {
		known[pkey(p)] = true
		byPID[p.PID] = p
	}
	dl := filepath.Join(os.Getenv("USERPROFILE"), "Downloads")
	seenDL := map[string]int64{}
	if ents, err := os.ReadDir(dl); err == nil {
		for _, e := range ents {
			if i, err := e.Info(); err == nil {
				_ = i
				seenDL[e.Name()] = -2 // existing files were covered by scans
			}
		}
	}
	lastBeat, lastReload, lastDL := time.Now(), time.Now(), time.Now()
	for {
		time.Sleep(120 * time.Millisecond)
		now := time.Now()
		if now.Sub(lastBeat) > 5*time.Second {
			writeState()
			lastBeat = now
		}
		if now.Sub(lastReload) > 30*time.Second {
			trusted, key, lastReload = secDB.trustedFn(), secDB.apiKey(), now
			if len(sigCache) > 4000 {
				sigCache = map[string]string{}
			}
		}
		cur := listProcs(true)
		alive := map[string]bool{}
		for _, p := range cur {
			k := pkey(p)
			alive[k] = true
			if known[k] {
				continue
			}
			known[k] = true
			byPID[p.PID] = p
			if p.PID <= 4 || p.PID == os.Getpid() {
				continue
			}
			st.Checked++
			shieldCheck(p, byPID, sigCache, trusted, key, &st)
		}
		for k := range known {
			if !alive[k] {
				delete(known, k)
			}
		}
		if now.Sub(lastDL) > 3*time.Second {
			lastDL = now
			shieldDownloads(dl, seenDL, trusted, key, &st)
		}
	}
}

func shieldCheck(p procInfo, byPID map[int]procInfo, sigCache map[string]string, trusted func(string) bool, key string, st *shieldState) {
	ev := shieldEvent{Name: p.Name, Path: p.Path, Zone: -1}
	if par, ok := byPID[p.PPID]; ok && (par.Start == 0 || p.Start == 0 || par.Start <= p.Start) {
		ev.Parent, ev.ParentPath = par.Name, par.Path
	}
	if h, err := openProc(p.PID, processQueryLimited); err == nil {
		ev.Cmd = procCmdLine(h)
		syscall.CloseHandle(h)
	}
	quick := total(shieldQuick(ev))
	suspended := false
	if quick >= 40 {
		suspended = suspendPID(p.PID, true)
	}
	// slower facts only for programs outside Windows' own folders
	if p.Path != "" && !sysDir(p.Path) {
		k := lc(p.Path)
		if s, ok := sigCache[k]; ok {
			ev.Signed = s
		} else {
			ev.Signed = fileSigned(p.Path)
			sigCache[k] = ev.Signed
		}
		ev.Zone = zoneOf(p.Path)
		if trusted(k) {
			ev.Trusted = true
		}
		if ev.Signed != "valid" {
			if sha := fileSHA(p.Path); sha != "" {
				if trusted(sha) {
					ev.Trusted = true
				}
				uw, _ := userWritable(p.Path)
				if key != "" && (uw || quick >= 40) {
					ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
					m, _, _ := lookupHashes(ctx, key, []string{sha}, nil)
					cancel()
					if it, ok := m[sha]; ok {
						ev.Intel = &it
					}
				} else if m, _, _ := lookupHashes(context.Background(), "", []string{sha}, nil); m[sha].Verdict == "malicious" {
					it := m[sha]
					ev.Intel = &it
				}
			}
		}
	} else {
		ev.Signed = "valid"
	}
	score, rs, verdict := shieldScore(ev)
	chain := []secStep{{PID: p.PID, Name: p.Name, Path: p.Path, Cmd: trimCmd(ev.Cmd)}}
	for cur, i := byPID[p.PPID], 0; cur.PID != 0 && i < 5; cur, i = byPID[cur.PPID], i+1 {
		chain = append([]secStep{{PID: cur.PID, Name: cur.Name, Path: cur.Path}}, chain...)
		if cur.PPID == cur.PID {
			break
		}
	}
	rec := secRecord{Source: "shield", Title: p.Name, Sub: p.Path, Path: p.Path, Sev: sevOf(score), Score: score, Reasons: rs, Chain: chain}
	if ev.Intel != nil {
		rec.Intel = []secIntel{*ev.Intel}
	}
	if o := zoneText(ev.Zone); o != "" {
		rec.Origin = &secOrigin{Zone: ev.Zone, Text: o}
	}
	switch verdict {
	case "block":
		rec.Action = "blocked"
		if secKill(p.PID) == nil {
			rec.Done = append(rec.Done, "Stopped it the moment it started")
		} else {
			rec.Failed = append(rec.Failed, "Could not stop the process")
		}
		if p.Path != "" && !sysDir(p.Path) {
			time.Sleep(200 * time.Millisecond)
			if m, err := quarantineFile(p.Path, p.Name); err == nil {
				rec.QID, rec.SHA, rec.CanUndo = m.ID, m.SHA, true
				rec.Done = append(rec.Done, "Moved the file to Quarantine")
			} else {
				rec.Failed = append(rec.Failed, "Quarantine: "+shortErr(err))
			}
		}
		st.Blocked++
		secDB.addRecord(rec)
		shieldAlert("CoreKit Live Shield: threat blocked", ev, rs, true)
	case "warn":
		if suspended {
			suspendPID(p.PID, false)
		}
		rec.Action = "warned"
		rec.Done = []string{"Allowed to run, you were told"}
		st.Warned++
		secDB.addRecord(rec)
		shieldAlert("CoreKit Live Shield: please check", ev, rs, false)
	default:
		if suspended {
			suspendPID(p.PID, false)
		}
	}
}

func zoneText(z int) string {
	switch z {
	case 3:
		return "Came from the internet"
	case 4:
		return "Came from an untrusted website"
	}
	return ""
}

// shieldDownloads looks at new program files in Downloads before they are opened.
func shieldDownloads(dl string, seen map[string]int64, trusted func(string) bool, key string, st *shieldState) {
	ents, err := os.ReadDir(dl)
	if err != nil {
		return
	}
	for _, e := range ents {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		n := e.Name()
		prev, ok := seen[n]
		switch {
		case prev == -2: // already looked at
			continue
		case !ok || prev != info.Size(): // new or still arriving: look again next round
			seen[n] = info.Size()
			continue
		}
		if !exeExt[lc(filepath.Ext(n))] {
			seen[n] = -2
			continue
		}
		p := filepath.Join(dl, n)
		seen[n] = -2
		ev := shieldEvent{Name: n, Path: p, Zone: zoneOf(p), Signed: fileSigned(p)}
		sha := fileSHA(p)
		if trusted(lc(p)) || (sha != "" && trusted(sha)) {
			continue
		}
		if key != "" && sha != "" && ev.Signed != "valid" {
			ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
			m, _, _ := lookupHashes(ctx, key, []string{sha}, nil)
			cancel()
			if it, ok := m[sha]; ok {
				ev.Intel = &it
			}
		}
		score, rs, verdict := shieldScore(ev)
		if verdict != "block" {
			continue
		}
		rec := secRecord{Source: "shield", Title: n, Sub: "Downloads", Path: p, SHA: sha, Sev: sevOf(score), Score: score, Reasons: rs, Action: "blocked"}
		if ev.Intel != nil {
			rec.Intel = []secIntel{*ev.Intel}
		}
		if m, err := quarantineFile(p, n); err == nil {
			rec.QID, rec.CanUndo = m.ID, true
			rec.Done = []string{"Caught in Downloads before it was opened", "Moved the file to Quarantine"}
			st.Blocked++
			secDB.addRecord(rec)
			shieldAlert("CoreKit Live Shield: dangerous download", ev, rs, true)
		}
	}
}
