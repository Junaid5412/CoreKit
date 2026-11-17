package main

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestParseProxy(t *testing.T) {
	vm, _ := json.Marshal(map[string]any{"v": "2", "ps": "VM", "add": "vm.example.com", "port": "443", "id": "11111111-2222-3333-4444-555555555555", "aid": "0", "net": "ws", "path": "/ray", "host": "vm.example.com", "tls": "tls", "sni": "vm.example.com"})
	cases := []struct{ link, kind, name string }{
		{"vless://00000000-1111-2222-3333-444444444444@203.0.113.7:443?type=tcp&encryption=none&security=reality&pbk=AAAAbbbbCCCCddddEEEEffffGGGGhhhhIIIIjjjjKKK&fp=chrome&sni=www.microsoft.com&sid=c08b5e4525&spx=%2F0ec69812d0c8bd6#MyVPN", "VLESS · Reality", "MyVPN"},
		{"vless://uuid-1@host.example:8443?security=tls&type=ws&path=%2Fws&host=cdn.example&sni=cdn.example#WS", "VLESS · TLS", "WS"},
		{"trojan://secret@tj.example.com:443?sni=tj.example.com#TJ", "Trojan · TLS", "TJ"},
		{"vmess://" + base64.StdEncoding.EncodeToString(vm), "VMess · TLS", "VM"},
		{"ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:pw")) + "@ss.example.com:8388#SS", "Shadowsocks", "SS"},
		{"ss://" + base64.StdEncoding.EncodeToString([]byte("chacha20-ietf-poly1305:pw@1.2.3.4:8389")) + "#SS2", "Shadowsocks", "SS2"},
		{"socks5://user:p%40ss@10.0.0.5:1080", "SOCKS5", ""},
		{"http://user:pass@proxy.example:3128", "HTTP", ""},
		{"https://proxy.example:443", "HTTPS", ""},
		{"45.10.20.30:1080", "SOCKS5", ""},
		{"45.10.20.30:1080:bob:secret", "SOCKS5", ""},
	}
	for _, c := range cases {
		out, kind, name, err := parseProxy(c.link)
		if err != nil {
			t.Fatalf("%s: %v", c.link, err)
		}
		if kind != c.kind || name != c.name {
			t.Errorf("%s: got kind %q name %q", c.link[:20], kind, name)
		}
		var cfg map[string]any
		if json.Unmarshal(xrayConfig(out, 31000), &cfg) != nil {
			t.Errorf("invalid config for %s", c.link[:20])
		}
	}
	// the Reality link must produce exactly the fields Xray needs
	out, _, _, _ := parseProxy(cases[0].link)
	b, _ := json.Marshal(out)
	var m struct {
		Settings struct {
			Vnext []struct {
				Address string
				Port    int
				Users   []map[string]any
			}
		}
		StreamSettings struct {
			Network, Security string
			RealitySettings   map[string]string
		}
	}
	json.Unmarshal(b, &m)
	r := m.StreamSettings.RealitySettings
	if m.Settings.Vnext[0].Address != "203.0.113.7" || m.Settings.Vnext[0].Port != 443 || m.StreamSettings.Security != "reality" || m.StreamSettings.Network != "tcp" ||
		r["serverName"] != "www.microsoft.com" || r["fingerprint"] != "chrome" || r["shortId"] != "c08b5e4525" || r["spiderX"] != "/0ec69812d0c8bd6" || r["publicKey"] == "" ||
		m.Settings.Vnext[0].Users[0]["encryption"] != "none" {
		t.Errorf("reality mapping wrong: %s", b)
	}
	for _, bad := range []string{"", "vless://@:443", "ftp://x:1", "hello", "vmess://notbase64!!"} {
		if _, _, _, err := parseProxy(bad); err == nil {
			t.Errorf("expected error for %q", bad)
		}
	}
	if maskIP("203.0.113.7") != "203.•••.•••.7" {
		t.Error("mask")
	}
}

func TestNormalizeInput(t *testing.T) {
	cases := map[string]string{
		"github.com":            "https://github.com",
		"github.com/x?y=1":      "https://github.com/x?y=1",
		"localhost:8080":        "http://localhost:8080",
		"192.168.1.1":           "http://192.168.1.1",
		"https://a.b/c":         "https://a.b/c",
		"how to fix wifi":       "https://www.google.com/search?q=how+to+fix+wifi",
		"javascript:alert(1)":   "https://www.google.com/search?q=javascript%3Aalert%281%29",
		"hello":                 "https://www.google.com/search?q=hello",
		"sub.example.co.uk:443": "https://sub.example.co.uk:443",
	}
	for in, want := range cases {
		if got := normalizeInput(in, "google"); got != want {
			t.Errorf("%q -> %q, want %q", in, got, want)
		}
	}
	if got := normalizeInput("x y", "duckduckgo"); got != "https://duckduckgo.com/?q=x+y" {
		t.Errorf("ddg: %s", got)
	}
	if b := bypassArg("bank.com, https://intranet.local/x ; bad$host"); b != "bank.com;*.bank.com;intranet.local;*.intranet.local" {
		t.Errorf("bypass: %s", b)
	}
	if a := browserArgs(30000, "bank.com", false); !strings.Contains(a, "socks5://127.0.0.1:30000") || !strings.Contains(a, `--proxy-bypass-list="bank.com;*.bank.com"`) {
		t.Errorf("args: %s", a)
	}
}

func TestHardening(t *testing.T) {
	a := browserArgs(30000, "bank.com", false)
	for _, want := range []string{"--disable-quic", "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
		`--host-resolver-rules="MAP * ~NOTFOUND, EXCLUDE localhost, EXCLUDE 127.0.0.1, EXCLUDE bank.com, EXCLUDE *.bank.com"`} {
		if !strings.Contains(a, want) {
			t.Errorf("missing %s in %s", want, a)
		}
	}
	if d := browserArgs(0, "", false); strings.Contains(d, "proxy") || strings.Contains(d, "resolver") {
		t.Errorf("direct args: %s", d)
	}
	for tz, ok := range map[string]bool{"Europe/Berlin": true, "America/Argentina/Buenos_Aires": true, "UTC": true, `x"};alert(1)`: false, "": false} {
		if validTZ(tz) != ok {
			t.Errorf("validTZ(%q) != %v", tz, ok)
		}
	}
	for _, tz := range countryTZ {
		if !validTZ(tz) {
			t.Errorf("bad table tz %s", tz)
		}
	}
}
