//go:build windows

package main

// Runs the Security module against the real Windows of the CI runner (CK_LIVE=1 only).

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func live(t *testing.T) {
	if os.Getenv("CK_LIVE") != "1" {
		t.Skip("set CK_LIVE=1 to run against this PC")
	}
	t.Setenv("ProgramData", t.TempDir()) // keep the test store away from a real one
	secDB = &secStore{}
}

func TestSecLiveCollectAndAnalyze(t *testing.T) {
	live(t)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	start := time.Now()
	raw, err := secCollect(ctx, func(kind, a, b string) {
		if kind == "P" {
			t.Logf("%3s%% %s", a, b)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	var r rawSec
	if err := json.Unmarshal(raw, &r); err != nil {
		t.Fatalf("collector JSON: %v\n%s", err, string(raw[:min(len(raw), 2000)]))
	}
	t.Logf("collected in %s: %d processes, %d autoruns, %d signatures, %d files, %d connections, %d appx, %d programs, defender present=%v rtp=%v",
		time.Since(start).Round(time.Millisecond), len(r.Procs), len(r.Autoruns), len(r.Sigs), len(r.Files), len(r.Conns), len(r.Appx), len(r.Programs), r.Defender.Present, r.Defender.RTP)
	if len(r.Procs) < 10 || len(r.Sigs) < 5 {
		t.Fatalf("too little data")
	}
	t.Logf("self=%d parent=%d %s", r.Self, r.SelfPar, r.SelfPath)
	res := analyzeSec(&r, time.Now().Unix(), func(string) bool { return false }, nil)
	t.Logf("verdict %s score %d counts %+v", res.Verdict, res.Score, res.Counts)
	for i, f := range res.Findings {
		if i < 25 {
			t.Logf("  %-4s %3d %-8s %s | %s", f.Sev, f.Score, f.Kind, f.Title, f.Summary)
			t.Logf("        path=%q signed=%s signer=%q reasons=%v", f.Path, f.Signed, f.Signer, f.Reasons)
		}
	}
	for _, p := range res.Protection {
		t.Logf("  protection %-12s %-7s %s", p.ID, p.State, p.Detail)
	}
	if _, err := json.Marshal(res); err != nil {
		t.Fatal(err)
	}
}

func reg(args ...string) error {
	return exec.Command(filepath.Join(os.Getenv("SystemRoot"), "System32", "reg.exe"), args...).Run()
}

func TestSecLiveFixAndUndo(t *testing.T) {
	live(t)
	ctx := context.Background()
	const k = `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
	if err := reg("add", k, "/v", "CoreKitTestEntry", "/t", "REG_SZ", "/d", `C:\Users\Public\cktest.exe /quiet`, "/f"); err != nil {
		t.Fatal(err)
	}
	defer reg("delete", k, "/v", "CoreKitTestEntry", "/f")
	undo, err := secAutorunRemove(ctx, autoRef{Kind: "run", Key: `reg|HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run|CoreKitTestEntry`, Name: "CoreKitTestEntry"})
	if err != nil {
		t.Fatalf("remove: %v", err)
	}
	if reg("query", k, "/v", "CoreKitTestEntry") == nil {
		t.Fatal("entry still there")
	}
	t.Logf("undo record: %s", undo)
	if err := secUndo(ctx, undo); err != nil {
		t.Fatalf("undo: %v", err)
	}
	if reg("query", k, "/v", "CoreKitTestEntry") != nil {
		t.Fatal("entry not restored")
	}
	// start-up switch (Task Manager's StartupApproved)
	msg, u2, err := secBloatAction(ctx, secBloat{Kind: "startup", Key: `reg|HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run|CoreKitTestEntry|CoreKitTestEntry`})
	if err != nil {
		t.Fatalf("disable at start-up: %v", err)
	}
	t.Logf("%s / undo %s", msg, u2)
	if len(u2) > 0 {
		if err := secUndo(ctx, u2); err != nil {
			t.Fatalf("undo start-up switch: %v", err)
		}
	}
	// a refused registry path must be rejected by the fixer
	if _, err := secAutorunRemove(ctx, autoRef{Kind: "run", Key: `reg|HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip|Start`}); err == nil {
		t.Fatal("fixer accepted an unrelated registry key")
	}
}

func TestSecLiveQuarantineAndProcesses(t *testing.T) {
	live(t)
	secDB.open()
	p := filepath.Join(t.TempDir(), "evil.pdf.exe")
	if err := os.WriteFile(p, []byte("MZ test body"), 0755); err != nil {
		t.Fatal(err)
	}
	m, err := quarantineFile(p, "evil")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restoreQuarantine(m.ID); err != nil {
		t.Fatal(err)
	}
	ps := listProcs(true)
	me := false
	for _, x := range ps {
		if x.PID == os.Getpid() && x.Path != "" && x.Start > 0 {
			me = true
		}
	}
	if len(ps) < 10 || !me {
		t.Fatalf("listProcs: %d, found myself=%v", len(ps), me)
	}
	h, err := openProc(os.Getpid(), processQueryLimited)
	if err != nil {
		t.Fatal(err)
	}
	cl := procCmdLine(h)
	if !strings.Contains(lc(cl), "test") {
		t.Errorf("command line of this test: %q", cl)
	}
	self, _ := os.Executable()
	t.Logf("signature of notepad: %s, of this test: %s, of cmd zone: %d", fileSigned(filepath.Join(os.Getenv("SystemRoot"), "notepad.exe")), fileSigned(self), zoneOf(self))
	ev := shieldEvent{Name: "powershell.exe", Path: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, Parent: "WINWORD.EXE", Cmd: "powershell -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA", Signed: "valid", Zone: -1}
	if _, _, v := shieldScore(ev); v != "block" {
		t.Fatal("shield verdict")
	}
	if name, ok := secDefenderScan(context.Background(), self); ok {
		t.Logf("Defender second opinion on the test binary: %q", name)
	} else {
		t.Log("Defender command-line scanner not available on this runner")
	}
}

func TestSecLiveShieldTask(t *testing.T) {
	live(t)
	if !isAdmin() {
		t.Skip("not elevated")
	}
	t.Setenv("ProgramFiles", t.TempDir())
	if err := secShieldSet(true); err != nil {
		t.Logf("shield on: %v", err)
	}
	st := secShieldStatus()
	t.Logf("shield status: %+v", st)
	if st["installed"] != true {
		t.Error("Live Shield task was not registered")
	}
	if err := secShieldSet(false); err != nil {
		t.Fatal(err)
	}
	if secShieldStatus()["installed"] == true {
		t.Error("Live Shield task still registered")
	}
}
