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

// Protection is read back from Windows; one item failing must not stop the others.
func TestSecLiveProtectionReadBack(t *testing.T) {
	live(t)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	all, err := secProtStatus(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, it := range all {
		t.Logf("status %-12s %-8s %s", it.ID, it.State, it.Detail)
		if it.State != "on" && it.State != "off" && it.State != "partial" && it.State != "unknown" {
			t.Errorf("odd state %+v", it)
		}
	}
	if len(all) < 8 {
		t.Fatalf("expected every protection to be reported, got %d", len(all))
	}
	// 'sigs' goes first on purpose: it can fail (offline) and must not stop 'pua' or 'rtp'
	h, err := secHarden(ctx, []string{"sigs", "pua", "rtp"})
	if err != nil {
		if strings.Contains(err.Error(), "administrator") {
			t.Skip("runner is not an administrator")
		}
		t.Fatal(err)
	}
	if len(h.Items) != 3 {
		t.Fatalf("every item must be reported: %+v", h.Items)
	}
	after, err := secProtStatus(ctx, []string{"pua", "rtp"})
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range after {
		for _, it := range h.Items {
			if it.ID == a.ID && it.State != a.State {
				t.Errorf("%s: harden said %s but Windows says %s", a.ID, it.State, a.State)
			}
		}
	}
	for _, it := range h.Items {
		t.Logf("harden %-6s ok=%v state=%s err=%q detail=%q", it.ID, it.OK, it.State, it.Err, it.Detail)
	}
}

// Origin: the Mark of the Web written by a browser is read back, the file is read inside, and
// "Delete it myself" removes it.
func TestSecLiveInspectAndDelete(t *testing.T) {
	live(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	// a real signed Windows program
	exe := filepath.Join(os.Getenv("SystemRoot"), "System32", "notepad.exe")
	raw, err := secFileInfo(ctx, exe)
	if err != nil {
		t.Fatal(err)
	}
	var plat inPlat
	if err := json.Unmarshal(raw, &plat); err != nil {
		t.Fatal(err)
	}
	if plat.Sig == nil || plat.Ver == nil || !strings.Contains(plat.Ver.Company, "Microsoft") || plat.Created == 0 || plat.Owner == "" {
		t.Fatalf("file info: %s", raw)
	}
	t.Logf("notepad owner=%s signature=%s", plat.Owner, plat.Sig.Status)
	// a program with its own embedded signature: certificate details must come through
	if edge := filepath.Join(os.Getenv("ProgramFiles(x86)"), `Microsoft\Edge\Application\msedge.exe`); fileExists(edge) {
		raw2, err := secFileInfo(ctx, edge)
		var p2 inPlat
		if err != nil || json.Unmarshal(raw2, &p2) != nil || p2.Sig == nil || p2.Sig.Status != "Valid" || !strings.Contains(p2.Sig.Subject, "Microsoft") || p2.Sig.Thumb == "" {
			t.Fatalf("edge signature: %v %s", err, raw2)
		}
		t.Logf("edge signed by %s until %d", p2.Sig.Subject, p2.Sig.To)
	}
	r := inspectFile(exe, plat)
	if r.Kind != "program" || !strings.Contains(r.KindText, "Windows") || len(r.Creator) < 4 || r.SHA256 == "" {
		t.Fatalf("inspect: %+v", r)
	}
	t.Logf("notepad: %s · risk %s · %d creator facts, %d servers, %d abilities", r.KindText, r.Risk, len(r.Creator), len(r.Servers), len(r.Caps))
	for _, c := range r.Creator {
		t.Logf("  creator %s = %s", c.K, c.V)
	}

	// a downloaded archive with a browser's Mark of the Web
	dir := t.TempDir()
	zp := filepath.Join(dir, "Noobspy-master.zip")
	os.WriteFile(zp, zipBytes(t, "0123456789abcdef0123456789abcdef01234567", map[string][]byte{"Noobspy-master/README.md": []byte("hi https://203.0.113.9/x")}), 0o600)
	if err := os.WriteFile(zp+":Zone.Identifier", []byte("[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=https://github.com/someone/Noobspy\r\nHostUrl=https://codeload.github.com/someone/Noobspy/zip/refs/heads/master\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f := &secFinding{ID: "live1", Kind: "threat", Title: "Trojan:AndroidOS/Test", Path: zp, Inner: `app\base.apk->classes.dex`, Score: 80}
	rep := secInspect(ctx, f)
	kv := map[string]string{}
	for _, e := range rep.Source {
		kv[e.K] = e.V
	}
	if !strings.Contains(kv["Downloaded from"], "codeload.github.com") || kv["GitHub project"] != "someone/Noobspy" || !strings.Contains(kv["Windows marked it as from"], "internet") || kv["Owner account"] == "" {
		t.Fatalf("source rows: %+v", rep.Source)
	}
	if rep.Created == 0 || len(rep.Servers) != 1 {
		t.Fatalf("report: created=%d servers=%+v", rep.Created, rep.Servers)
	}
	f.Actions = actionsFor(f)
	out := applyFix(ctx, f, "delete")
	if !out.OK {
		t.Fatalf("delete: %+v", out)
	}
	if _, err := os.Stat(zp); !os.IsNotExist(err) {
		t.Fatal("archive is still there after Delete it myself")
	}
}

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }
