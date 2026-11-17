package main

// Module 3: Safe Browser - persistent multi-profile browser launcher with
// per-profile proxy (Xray engine: VLESS/Reality, VMess, Trojan, Shadowsocks, SOCKS5, HTTP).

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------- model

type brProfile struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Color    string `json:"color"`
	Browser  string `json:"browser"`  // auto | chrome | edge
	Proxy    string `json:"proxy"`    // "" = direct, "default", or a proxy id
	StartURL string `json:"startUrl"` // page opened at start when Startup is "page"
	Startup  string `json:"startup"`  // restore (default) | newtab | page | clear
	Search   string `json:"search"`
	Bypass   string `json:"bypass"`
	// secure defaults: zero value = protected
	NoAdblock    bool `json:"noAdblock"`    // ad blocker off
	NoLangMatch  bool `json:"noLangMatch"`  // don't match page language to the VPN country
	AllowCapture bool `json:"allowCapture"` // let screenshots / remote viewers see the window
	KeepHistory  bool `json:"keepHistory"`  // old setting, replaced by Startup
	// languages
	Lang         string   `json:"lang"`         // page / translation language ("" = English)
	NoTransOffer bool     `json:"noTransOffer"` // don't offer to translate
	TransAuto    bool     `json:"transAuto"`    // translate foreign pages automatically
	AlwaysLangs  []string `json:"alwaysLangs"`  // always translate these languages
	NeverLangs   []string `json:"neverLangs"`   // never offer for these languages
	NoGoogleFix  bool     `json:"noGoogleFix"`  // allow country Google
	Created      int64    `json:"created"`
	LastUsed     int64    `json:"lastUsed"`
}

type brTest struct {
	OK      bool   `json:"ok"`
	Ms      int    `json:"ms"`
	IP      string `json:"ip"`
	Country string `json:"country"`
	Hidden  bool   `json:"hidden"`
	Err     string `json:"error,omitempty"`
	At      int64  `json:"at"`
	direct  string // this PC's real IP seen during the test (never sent to the UI)
}

type brProxy struct {
	ID    string  `json:"id"`
	Name  string  `json:"name"`
	Link  string  `json:"link"`
	Port  int     `json:"port"`
	Test  *brTest `json:"test,omitempty"`
	Added int64   `json:"added"`
}

type brConfig struct {
	Profiles []*brProfile `json:"profiles"`
	Proxies  []*brProxy   `json:"proxies"`
	Default  string       `json:"default"`
}

var (
	brMu     sync.Mutex
	brCfg    *brConfig
	sizeMu   sync.Mutex
	sizeMemo = map[string][2]int64{} // id -> {bytes, unix time}
)

func dataDir() string {
	d := filepath.Join(appDataRoot(), "Browser")
	os.MkdirAll(d, 0700)
	return d
}
func profileDir(id string) string { return filepath.Join(dataDir(), "Profiles", id) }
func engineDir() string {
	d := filepath.Join(appDataRoot(), "engine")
	os.MkdirAll(d, 0700)
	return d
}

func brLoad() *brConfig {
	if brCfg != nil {
		return brCfg
	}
	brCfg = &brConfig{}
	b, err := os.ReadFile(filepath.Join(dataDir(), "config.dat"))
	if err == nil {
		if plain, err := unprotect(b); err == nil {
			_ = json.Unmarshal(plain, brCfg)
		} else {
			os.Rename(filepath.Join(dataDir(), "config.dat"), filepath.Join(dataDir(), fmt.Sprintf("config.unreadable-%d.dat", time.Now().Unix())))
		}
	}
	return brCfg
}

func brSave() {
	b, _ := json.Marshal(brCfg)
	enc, err := protect(b)
	if err != nil {
		logLine("!", "Could not encrypt browser settings: "+err.Error())
		return
	}
	p := filepath.Join(dataDir(), "config.dat")
	_ = os.WriteFile(p+".tmp", enc, 0600)
	_ = os.Rename(p+".tmp", p)
}

func newID() string { return randToken()[:12] }

func (c *brConfig) profile(id string) *brProfile {
	for _, p := range c.Profiles {
		if p.ID == id {
			return p
		}
	}
	return nil
}
func (c *brConfig) proxy(id string) *brProxy {
	for _, p := range c.Proxies {
		if p.ID == id {
			return p
		}
	}
	return nil
}

// proxyFor resolves the proxy a profile uses (nil = direct).
// startMode is what the profile does when it closes and opens again. Data is kept unless
// the user picked "clear everything when closed".
func (p *brProfile) startMode() string {
	switch p.Startup {
	case "newtab", "page", "clear":
		return p.Startup
	}
	return "restore"
}

// setStartup stores the start/close choice; a page needs an address.
func (p *brProfile) setStartup(mode, page string) {
	page = strings.TrimSpace(page)
	switch mode {
	case "newtab", "clear", "restore":
		p.Startup = mode
	case "page":
		if page == "" {
			p.Startup = "newtab"
			return
		}
		p.Startup, p.StartURL = "page", normalizeInput(page, p.Search)
	}
}

// newProxy turns a pasted link into a saved-proxy entry; the name comes from the link when
// none is given.
func newProxy(name, link string) (*brProxy, error) {
	link = strings.TrimSpace(link)
	_, kind, autoName, err := parseProxy(link)
	if err != nil {
		return nil, err
	}
	name = strings.TrimSpace(name)
	if name == "" {
		name = autoName
	}
	if name == "" {
		name = strings.ToUpper(kind)
	}
	if len([]rune(name)) > 40 {
		name = string([]rune(name)[:40])
	}
	return &brProxy{ID: newID(), Name: name, Link: link, Added: time.Now().Unix()}, nil
}

func (c *brConfig) proxyFor(p *brProfile) *brProxy {
	switch p.Proxy {
	case "":
		return nil
	case "default":
		return c.proxy(c.Default)
	default:
		return c.proxy(p.Proxy)
	}
}

// ---------------------------------------------------------------- proxy links -> Xray outbound

var hostPortRe = regexp.MustCompile(`^([A-Za-z0-9.\-\[\]:]+):(\d{1,5})(?::([^:]*):(.*))?$`)

func atoiPort(s string) (int, error) {
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 || n > 65535 {
		return 0, errors.New("invalid port")
	}
	return n, nil
}

func b64decode(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.NewReplacer("-", "+", "_", "/").Replace(s)
	if m := len(s) % 4; m != 0 {
		s += strings.Repeat("=", 4-m)
	}
	return base64.StdEncoding.DecodeString(s)
}

func streamSettings(network, security, host string, q func(string) string) map[string]any {
	if network == "" {
		network = "tcp"
	}
	s := map[string]any{"network": network}
	switch network {
	case "ws":
		path := q("path")
		if path == "" {
			path = "/"
		}
		ws := map[string]any{"path": path}
		if h := q("host"); h != "" {
			ws["headers"] = map[string]string{"Host": h}
		}
		s["wsSettings"] = ws
	case "grpc":
		s["grpcSettings"] = map[string]any{"serviceName": q("serviceName")}
	case "xhttp", "splithttp":
		s["network"] = "xhttp"
		mode := q("mode")
		if mode == "" {
			mode = "auto"
		}
		s["xhttpSettings"] = map[string]any{"path": q("path"), "host": q("host"), "mode": mode}
	case "httpupgrade":
		s["httpupgradeSettings"] = map[string]any{"path": q("path"), "host": q("host")}
	}
	fp := q("fp")
	switch security {
	case "reality":
		if fp == "" {
			fp = "chrome"
		}
		s["security"] = "reality"
		s["realitySettings"] = map[string]any{"serverName": q("sni"), "fingerprint": fp, "publicKey": q("pbk"), "shortId": q("sid"), "spiderX": q("spx")}
	case "tls":
		sni := q("sni")
		if sni == "" {
			sni = q("host")
		}
		if sni == "" {
			sni = host
		}
		t := map[string]any{"serverName": sni, "allowInsecure": q("allowInsecure") == "1" || q("insecure") == "1"}
		if fp != "" {
			t["fingerprint"] = fp
		}
		if a := q("alpn"); a != "" {
			t["alpn"] = strings.Split(a, ",")
		}
		s["security"] = "tls"
		s["tlsSettings"] = t
	}
	return s
}

// parseProxy turns a share link into an Xray outbound and a human label (no secrets in the label).
func parseProxy(link string) (map[string]any, string, string, error) {
	link = strings.TrimSpace(link)
	if link == "" {
		return nil, "", "", errors.New("empty link")
	}
	if !strings.Contains(link, "://") {
		m := hostPortRe.FindStringSubmatch(link)
		if m == nil {
			return nil, "", "", errors.New("unrecognised proxy format")
		}
		if m[3] != "" {
			link = "socks5://" + url.QueryEscape(m[3]) + ":" + url.QueryEscape(m[4]) + "@" + m[1] + ":" + m[2]
		} else {
			link = "socks5://" + m[1] + ":" + m[2]
		}
	}
	scheme := strings.ToLower(link[:strings.Index(link, "://")])
	name := ""
	if i := strings.LastIndex(link, "#"); i >= 0 {
		name, _ = url.QueryUnescape(link[i+1:])
	}

	if scheme == "vmess" {
		raw := strings.TrimPrefix(link[8:], "")
		if i := strings.Index(raw, "#"); i >= 0 {
			raw = raw[:i]
		}
		js, err := b64decode(raw)
		if err != nil {
			return nil, "", "", errors.New("invalid vmess link")
		}
		var v map[string]any
		if json.Unmarshal(js, &v) != nil {
			return nil, "", "", errors.New("invalid vmess data")
		}
		str := func(k string) string {
			if x, ok := v[k]; ok && x != nil {
				return strings.TrimSpace(fmt.Sprint(x))
			}
			return ""
		}
		port, err := atoiPort(str("port"))
		if err != nil || str("add") == "" || str("id") == "" {
			return nil, "", "", errors.New("vmess link is missing server, port or id")
		}
		aid, _ := strconv.Atoi(str("aid"))
		scy := str("scy")
		if scy == "" {
			scy = "auto"
		}
		q := func(k string) string {
			switch k {
			case "path":
				return str("path")
			case "host":
				return str("host")
			case "sni":
				return str("sni")
			case "serviceName":
				return str("path")
			case "fp":
				return str("fp")
			case "alpn":
				return str("alpn")
			}
			return ""
		}
		sec := str("tls")
		if sec == "none" {
			sec = ""
		}
		out := map[string]any{"protocol": "vmess", "settings": map[string]any{"vnext": []any{map[string]any{"address": str("add"), "port": port,
			"users": []any{map[string]any{"id": str("id"), "alterId": aid, "security": scy}}}}},
			"streamSettings": streamSettings(str("net"), sec, str("add"), q)}
		if name == "" {
			name = str("ps")
		}
		return out, "VMess" + secLabel(sec), name, nil
	}

	u, err := url.Parse(link)
	if err != nil {
		return nil, "", "", errors.New("invalid link")
	}
	host := u.Hostname()
	q := func(k string) string { return u.Query().Get(k) }

	if scheme == "ss" {
		method, pass := "", ""
		if u.User != nil {
			if p, ok := u.User.Password(); ok {
				method, pass = u.User.Username(), p
			} else if d, err := b64decode(u.User.Username()); err == nil {
				parts := strings.SplitN(string(d), ":", 2)
				if len(parts) == 2 {
					method, pass = parts[0], parts[1]
				}
			}
		}
		if u.User == nil || host == "" { // legacy ss://BASE64(method:pass@host:port)
			raw := strings.TrimPrefix(link, "ss://")
			if i := strings.IndexAny(raw, "#?"); i >= 0 {
				raw = raw[:i]
			}
			d, err := b64decode(raw)
			if err != nil {
				return nil, "", "", errors.New("invalid shadowsocks link")
			}
			uu, err := url.Parse("ss://" + string(d))
			if err != nil {
				return nil, "", "", errors.New("invalid shadowsocks link")
			}
			host = uu.Hostname()
			u.Host = uu.Host
			method = uu.User.Username()
			pass, _ = uu.User.Password()
		}
		port, err := atoiPort(u.Port())
		if err != nil || host == "" || method == "" {
			return nil, "", "", errors.New("shadowsocks link is missing server, port or method")
		}
		return map[string]any{"protocol": "shadowsocks", "settings": map[string]any{"servers": []any{map[string]any{"address": host, "port": port, "method": method, "password": pass}}}},
			"Shadowsocks", name, nil
	}

	port, err := atoiPort(u.Port())
	if err != nil || host == "" {
		return nil, "", "", errors.New("link is missing server or port")
	}
	switch scheme {
	case "vless":
		id := u.User.Username()
		if id == "" {
			return nil, "", "", errors.New("vless link is missing the user id")
		}
		enc := q("encryption")
		if enc == "" {
			enc = "none"
		}
		user := map[string]any{"id": id, "encryption": enc}
		if f := q("flow"); f != "" {
			user["flow"] = f
		}
		sec := q("security")
		if sec == "none" {
			sec = ""
		}
		return map[string]any{"protocol": "vless", "settings": map[string]any{"vnext": []any{map[string]any{"address": host, "port": port, "users": []any{user}}}},
			"streamSettings": streamSettings(q("type"), sec, host, q)}, "VLESS" + secLabel(sec), name, nil
	case "trojan":
		pass := u.User.Username()
		sec := q("security")
		if sec == "" {
			sec = "tls"
		}
		if sec == "none" {
			sec = ""
		}
		return map[string]any{"protocol": "trojan", "settings": map[string]any{"servers": []any{map[string]any{"address": host, "port": port, "password": pass}}},
			"streamSettings": streamSettings(q("type"), sec, host, q)}, "Trojan" + secLabel(sec), name, nil
	case "socks", "socks5", "socks5h", "socks4":
		srv := map[string]any{"address": host, "port": port}
		if u.User != nil && u.User.Username() != "" {
			p, _ := u.User.Password()
			srv["users"] = []any{map[string]any{"user": u.User.Username(), "pass": p}}
		}
		return map[string]any{"protocol": "socks", "settings": map[string]any{"servers": []any{srv}}}, "SOCKS5", name, nil
	case "http", "https":
		srv := map[string]any{"address": host, "port": port}
		if u.User != nil && u.User.Username() != "" {
			p, _ := u.User.Password()
			srv["users"] = []any{map[string]any{"user": u.User.Username(), "pass": p}}
		}
		out := map[string]any{"protocol": "http", "settings": map[string]any{"servers": []any{srv}}}
		label := "HTTP"
		if scheme == "https" {
			out["streamSettings"] = map[string]any{"security": "tls", "tlsSettings": map[string]any{"serverName": host}}
			label = "HTTPS"
		}
		return out, label, name, nil
	}
	return nil, "", "", fmt.Errorf("unsupported proxy type %q", scheme)
}

func secLabel(sec string) string {
	switch sec {
	case "reality":
		return " · Reality"
	case "tls":
		return " · TLS"
	}
	return ""
}

func xrayConfig(out map[string]any, port int) []byte {
	o := map[string]any{}
	for k, v := range out {
		o[k] = v
	}
	o["tag"] = "proxy"
	cfg := map[string]any{
		"log": map[string]any{"loglevel": "warning"},
		"inbounds": []any{
			map[string]any{"tag": "socks", "listen": "127.0.0.1", "port": port, "protocol": "socks", "settings": map[string]any{"auth": "noauth", "udp": false}},
			map[string]any{"tag": "http", "listen": "127.0.0.1", "port": port + 1, "protocol": "http", "settings": map[string]any{}},
		},
		"outbounds": []any{o, map[string]any{"tag": "direct", "protocol": "freedom"}},
	}
	if xrayBlockAds { // ad blocker with the proxy on: ad domains go nowhere
		doms := make([]string, len(adDomains))
		for i, d := range adDomains {
			doms[i] = "domain:" + d
		}
		cfg["outbounds"] = append(cfg["outbounds"].([]any), map[string]any{"tag": "block", "protocol": "blackhole"})
		cfg["routing"] = map[string]any{"domainStrategy": "AsIs", "rules": []any{map[string]any{"type": "field", "domain": doms, "outboundTag": "block"}}}
	}
	b, _ := json.MarshalIndent(cfg, "", "  ")
	return b
}

// xrayBlockAds is set by the browser window when its profile has the ad blocker on.
var xrayBlockAds bool

// ---------------------------------------------------------------- engine (Xray) manager

type engInst struct {
	cmd  *exec.Cmd
	port int
	hash string
	done chan struct{}
	errb *bytes.Buffer
}

var (
	engMu   sync.Mutex
	engines = map[string]*engInst{}
	// hooks (replaced by mocks in non-Windows test builds)
	engineEnsureHook  = engineEnsureReal
	proxyTestHook     = proxyTestReal
	engineVersionHook = engineVersionReal
	engineInstallHook = engineInstallReal
)

var errNeedEngine = errors.New("NEED_ENGINE")

func engineExe() string {
	cands := []string{}
	if exe, err := os.Executable(); err == nil {
		cands = append(cands, filepath.Join(filepath.Dir(exe), engineFile))
	}
	cands = append(cands, filepath.Join(engineDir(), engineFile))
	for _, c := range cands {
		if st, err := os.Stat(c); err == nil && !st.IsDir() && st.Size() > 1<<20 {
			return c
		}
	}
	return ""
}

func portFree(p int) bool {
	l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", p))
	if err != nil {
		return false
	}
	l.Close()
	return true
}

func pickPort() int {
	for i := 0; i < 200; i++ {
		p := 20000 + rand.Intn(19000)*2
		if portFree(p) && portFree(p+1) {
			return p
		}
	}
	return 0
}

func engineEnsure(p *brProxy) (int, error) { return engineEnsureHook(p) }

func engineEnsureReal(p *brProxy) (int, error) { return engineRun(p.ID, p, 0) }

// engineRun starts (or reuses) an Xray instance under `key`: SOCKS5 on port, HTTP on port+1.
// port 0 picks a free pair.
func engineRun(key string, p *brProxy, port int) (int, error) {
	out, _, _, err := parseProxy(p.Link)
	if err != nil {
		return 0, err
	}
	engMu.Lock()
	defer engMu.Unlock()
	sum := sha256.Sum256([]byte(p.Link))
	hash := hex.EncodeToString(sum[:])
	if in := engines[key]; in != nil {
		select {
		case <-in.done:
		default:
			if in.hash == hash && (port == 0 || port == in.port) {
				return in.port, nil
			}
			_ = in.cmd.Process.Kill()
			<-in.done
		}
		delete(engines, key)
	}
	exe := engineExe()
	if exe == "" {
		return 0, errNeedEngine
	}
	if port == 0 {
		if port = pickPort(); port == 0 {
			return 0, errors.New("no free local port")
		}
	}
	cfgPath := filepath.Join(engineDir(), fmt.Sprintf("run-%d-%s.json", os.Getpid(), strings.ReplaceAll(key, ":", "_")))
	if err := os.WriteFile(cfgPath, xrayConfig(out, port), 0600); err != nil {
		return 0, err
	}
	defer os.Remove(cfgPath)
	cmd := engineCommand(exe, "run", "-c", cfgPath)
	errb := &bytes.Buffer{}
	cmd.Stdout, cmd.Stderr = errb, errb
	if err := cmd.Start(); err != nil {
		return 0, err
	}
	bindToJob(cmd)
	in := &engInst{cmd: cmd, port: port, hash: hash, done: make(chan struct{}), errb: errb}
	go func() { _ = cmd.Wait(); close(in.done) }()
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-in.done:
			msg := strings.TrimSpace(errb.String())
			if len(msg) > 300 {
				msg = msg[len(msg)-300:]
			}
			return 0, errors.New("proxy engine stopped: " + msg)
		default:
		}
		if c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 200*time.Millisecond); err == nil {
			c.Close()
			engines[key] = in
			logLine("+", fmt.Sprintf("Proxy engine running for %s on 127.0.0.1:%d", p.Name, port))
			return port, nil
		}
		time.Sleep(120 * time.Millisecond)
	}
	_ = cmd.Process.Kill()
	return 0, errors.New("proxy engine did not start")
}

// engineDone returns a channel closed when the instance under key exits (nil if none).
func engineDone(key string) <-chan struct{} {
	engMu.Lock()
	defer engMu.Unlock()
	if in := engines[key]; in != nil {
		return in.done
	}
	return nil
}

func engineStop(id string) {
	engMu.Lock()
	defer engMu.Unlock()
	if in := engines[id]; in != nil {
		_ = in.cmd.Process.Kill()
		delete(engines, id)
	}
}

func engineStopAll() {
	engMu.Lock()
	defer engMu.Unlock()
	for id, in := range engines {
		_ = in.cmd.Process.Kill()
		delete(engines, id)
	}
}

func engineRunning(id string) bool {
	engMu.Lock()
	defer engMu.Unlock()
	in := engines[id]
	if in == nil {
		return false
	}
	select {
	case <-in.done:
		return false
	default:
		return true
	}
}

var engVer string

func engineVersionReal() string {
	exe := engineExe()
	if exe == "" {
		return ""
	}
	if engVer != "" {
		return engVer
	}
	cmd := engineCommand(exe, "version")
	out, err := cmd.Output()
	if err != nil {
		return "installed"
	}
	l := strings.SplitN(strings.TrimSpace(string(out)), "\n", 2)[0]
	if f := strings.Fields(l); len(f) >= 2 {
		engVer = f[0] + " " + f[1]
	} else {
		engVer = "installed"
	}
	return engVer
}

// engineInstallReal downloads the official Xray release from GitHub and verifies its SHA-256.
func engineInstallReal(progress func(pct int, msg string)) (string, error) {
	base := "https://github.com/XTLS/Xray-core/releases/latest/download/" + engineAsset
	cl := &http.Client{Timeout: 4 * time.Minute}
	progress(2, "Checking latest release")
	resp, err := cl.Get(base + ".dgst")
	if err != nil {
		return "", fmt.Errorf("cannot reach GitHub: %v", err)
	}
	dg, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	resp.Body.Close()
	m := regexp.MustCompile(`(?i)SHA2-256=\s*([0-9a-f]{64})`).FindSubmatch(dg)
	if resp.StatusCode != 200 || m == nil {
		return "", errors.New("could not read the release checksum")
	}
	want := strings.ToLower(string(m[1]))
	resp, err = cl.Get(base)
	if err != nil {
		return "", fmt.Errorf("download failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("download failed (HTTP %d)", resp.StatusCode)
	}
	total := resp.ContentLength
	buf := &bytes.Buffer{}
	chunk := make([]byte, 64*1024)
	for {
		n, err := resp.Body.Read(chunk)
		buf.Write(chunk[:n])
		if total > 0 {
			progress(5+int(float64(buf.Len())/float64(total)*85), fmt.Sprintf("Downloading %.1f / %.1f MB", float64(buf.Len())/1e6, float64(total)/1e6))
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", fmt.Errorf("download interrupted: %v", err)
		}
	}
	progress(92, "Verifying checksum")
	got := sha256.Sum256(buf.Bytes())
	if hex.EncodeToString(got[:]) != want {
		return "", errors.New("checksum mismatch - download rejected")
	}
	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		return "", errors.New("corrupt archive")
	}
	for _, f := range zr.File {
		if strings.EqualFold(filepath.Base(f.Name), engineFile) {
			rc, err := f.Open()
			if err != nil {
				return "", err
			}
			dst := filepath.Join(engineDir(), engineFile)
			out, err := os.OpenFile(dst+".tmp", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
			if err != nil {
				rc.Close()
				return "", err
			}
			_, err = io.Copy(out, rc)
			rc.Close()
			out.Close()
			if err != nil {
				return "", err
			}
			if err := os.Rename(dst+".tmp", dst); err != nil {
				return "", err
			}
			progress(100, "Installed")
			engVer = ""
			return engineVersionReal(), nil
		}
	}
	return "", errors.New("engine not found in the archive")
}

// ---------------------------------------------------------------- proxy test

func cfTrace(cl *http.Client) (map[string]string, int, error) {
	var last error
	for _, u := range []string{"https://www.cloudflare.com/cdn-cgi/trace", "https://1.1.1.1/cdn-cgi/trace"} {
		t0 := time.Now()
		resp, err := cl.Get(u)
		if err != nil {
			last = err
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		resp.Body.Close()
		ms := int(time.Since(t0).Milliseconds())
		kv := map[string]string{}
		for _, l := range strings.Split(string(b), "\n") {
			if i := strings.Index(l, "="); i > 0 {
				kv[l[:i]] = strings.TrimSpace(l[i+1:])
			}
		}
		if kv["ip"] != "" {
			return kv, ms, nil
		}
		last = errors.New("unexpected response")
	}
	return nil, 0, last
}

func proxyTestReal(p *brProxy, port int) brTest {
	t := brTest{At: time.Now().Unix()}
	pu, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", port+1))
	via := &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(pu), DisableKeepAlives: false}}
	var times []int
	var info map[string]string
	var err error
	for i := 0; i < 3; i++ {
		kv, ms, e := cfTrace(via)
		if e != nil {
			err = e
			continue
		}
		info = kv
		times = append(times, ms)
	}
	if info == nil {
		t.Err = "no connection through proxy"
		if err != nil {
			t.Err = shortErr(err)
		}
		return t
	}
	sort.Ints(times)
	t.OK, t.Ms, t.IP, t.Country = true, times[len(times)/2], info["ip"], info["loc"]
	direct := &http.Client{Timeout: 8 * time.Second, Transport: &http.Transport{Proxy: nil}}
	if kv, _, e := cfTrace(direct); e == nil {
		t.Hidden = kv["ip"] != t.IP
		t.direct = kv["ip"]
	} else {
		t.Hidden = true
	}
	return t
}

func shortErr(err error) string {
	s := err.Error()
	if i := strings.LastIndex(s, ": "); i > 0 && len(s)-i < 90 {
		s = s[i+2:]
	}
	if len(s) > 140 {
		s = s[:140]
	}
	return s
}

func maskIP(ip string) string {
	if strings.Count(ip, ".") == 3 {
		p := strings.Split(ip, ".")
		return p[0] + ".•••.•••." + p[3]
	}
	if len(ip) > 8 {
		return ip[:4] + "•••" + ip[len(ip)-4:]
	}
	return "•••"
}

// ---------------------------------------------------------------- profiles on disk

func dirSize(dir string) int64 {
	var n int64
	_ = filepath.Walk(dir, func(_ string, fi os.FileInfo, err error) error {
		if err == nil && !fi.IsDir() {
			n += fi.Size()
		}
		return nil
	})
	return n
}

func profileSize(id string) int64 {
	sizeMu.Lock()
	m, ok := sizeMemo[id]
	sizeMu.Unlock()
	if ok && time.Now().Unix()-m[1] < 45 {
		return m[0]
	}
	go func() {
		n := dirSize(profileDir(id))
		sizeMu.Lock()
		sizeMemo[id] = [2]int64{n, time.Now().Unix()}
		sizeMu.Unlock()
	}()
	return m[0]
}

// resetIdentity wipes a profile but keeps bookmarks (and optionally saved passwords).
func resetIdentity(id string, keepPasswords bool) error {
	dir := profileDir(id)
	var keep []string
	if keepPasswords { // WebView2 keeps its Chromium profile in <udf>\EBWebView
		for _, k := range []string{"Local State", filepath.Join("Default", "Login Data"), filepath.Join("Default", "Login Data For Account")} {
			keep = append(keep, filepath.Join("EBWebView", k))
		}
	}
	tmp := dir + ".keep"
	os.RemoveAll(tmp)
	for _, k := range keep {
		src := filepath.Join(dir, k)
		if _, err := os.Stat(src); err == nil {
			os.MkdirAll(filepath.Dir(filepath.Join(tmp, k)), 0700)
			if err := os.Rename(src, filepath.Join(tmp, k)); err != nil {
				return fmt.Errorf("could not keep %s: %v", k, err)
			}
		}
	}
	var err error
	for i := 0; i < 15; i++ {
		if err = os.RemoveAll(dir); err == nil {
			break
		}
		time.Sleep(400 * time.Millisecond)
	}
	os.MkdirAll(dir, 0700)
	for _, k := range keep {
		if _, e := os.Stat(filepath.Join(tmp, k)); e == nil {
			os.Rename(filepath.Join(tmp, k), filepath.Join(dir, k))
		}
	}
	os.RemoveAll(tmp)
	sizeMu.Lock()
	delete(sizeMemo, id)
	sizeMu.Unlock()
	if err != nil {
		return errors.New("some files were still in use; close the browser and try again")
	}
	return nil
}

// ---------------------------------------------------------------- HTTP API

func readJSON(r *http.Request, v any) error {
	return json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(v)
}
func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(v)
}
func jsonErr(w http.ResponseWriter, msg string) { writeJSON(w, map[string]any{"error": msg}) }

var _ = context.Background

func contextTimeout(d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), d)
}

func activeEngines() int {
	engMu.Lock()
	defer engMu.Unlock()
	n := 0
	for _, in := range engines {
		select {
		case <-in.done:
		default:
			n++
		}
	}
	return n
}
