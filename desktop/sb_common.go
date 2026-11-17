package main

// CoreKit Browser — platform-independent parts: sessions, address-bar logic,
// the local page server for the browser's own UI and new-tab page, logging.

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Junaid5412/corekit/ui"
)

var (
	sbChromeHTML = ui.Browser
	sbStartHTML  = ui.Start
	sbPickerHTML = ui.Picker
)

// ---------------------------------------------------------------- logging

var sbLogMu sync.Mutex

func sbLogPath() string { return filepath.Join(appDataRoot(), "browser.log") }

func sbLog(format string, a ...any) {
	sbLogMu.Lock()
	defer sbLogMu.Unlock()
	p := sbLogPath()
	if st, err := os.Stat(p); err == nil && st.Size() > 1<<20 {
		os.Rename(p, p+".old")
	}
	f, err := os.OpenFile(p, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "%s [%d] %s\n", time.Now().Format("2006-01-02 15:04:05.000"), os.Getpid(), fmt.Sprintf(format, a...))
}

// ---------------------------------------------------------------- search engines

type searchEngine struct{ ID, Name, URL string }

var searchEngines = []searchEngine{
	{"google", "Google", "https://www.google.com/search"},
	{"duckduckgo", "DuckDuckGo", "https://duckduckgo.com/"},
	{"bing", "Bing", "https://www.bing.com/search"},
	{"brave", "Brave Search", "https://search.brave.com/search"},
}

func engineByID(id string) searchEngine {
	for _, e := range searchEngines {
		if e.ID == id {
			return e
		}
	}
	return searchEngines[0]
}

var (
	domainRe = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}\.?(:\d{1,5})?$`)
	schemeRe = regexp.MustCompile(`^(?i)(https?|file|ftp|about|view-source|edge|chrome):`)
)

// normalizeInput turns address-bar text into a URL (or a search).
func normalizeInput(s, engine string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	low := strings.ToLower(s)
	if schemeRe.MatchString(s) {
		if strings.HasPrefix(low, "http") || strings.HasPrefix(low, "file:") || strings.HasPrefix(low, "ftp:") || low == "about:blank" {
			return s
		}
	} else if !strings.ContainsAny(s, " \t") {
		host := low
		if i := strings.IndexAny(host, "/?#"); i >= 0 {
			host = host[:i]
		}
		if at := strings.LastIndex(host, "@"); at >= 0 {
			host = host[at+1:]
		}
		h := host
		if hh, _, err := net.SplitHostPort(host); err == nil {
			h = hh
		}
		switch {
		case h == "localhost", net.ParseIP(strings.Trim(h, "[]")) != nil && host != "":
			return "http://" + s
		case domainRe.MatchString(host):
			return "https://" + s
		}
	}
	e := engineByID(engine)
	return e.URL + "?q=" + url.QueryEscape(s)
}

// ---------------------------------------------------------------- session (encrypted, per profile)

type sbTabRec struct {
	URL   string `json:"u"`
	Title string `json:"t"`
}

type sbWin struct {
	X, Y, W, H int
	Max        bool
}

type sbSession struct {
	Tabs      []sbTabRec `json:"tabs"`
	Active    int        `json:"active"`
	Closed    []sbTabRec `json:"closed,omitempty"`
	Win       *sbWin     `json:"win,omitempty"`
	Collapsed bool       `json:"collapsed,omitempty"`
}

func sessionPath(id string) string { return filepath.Join(profileDir(id), "session.dat") }

func loadSession(id string) *sbSession {
	s := &sbSession{}
	b, err := os.ReadFile(sessionPath(id))
	if err != nil {
		return s
	}
	plain, err := unprotect(b)
	if err != nil {
		return s
	}
	_ = json.Unmarshal(plain, s)
	if s.Active < 0 || s.Active >= len(s.Tabs) {
		s.Active = 0
	}
	return s
}

var sessMu sync.Mutex

func saveSession(id string, s *sbSession) {
	sessMu.Lock()
	defer sessMu.Unlock()
	b, _ := json.Marshal(s)
	enc, err := protect(b)
	if err != nil {
		return
	}
	os.MkdirAll(profileDir(id), 0700)
	p := sessionPath(id)
	if os.WriteFile(p+".tmp", enc, 0600) == nil {
		os.Rename(p+".tmp", p)
	}
}

// ---------------------------------------------------------------- profiles

var profileColors = []string{"#2dd4bf", "#60a5fa", "#a78bfa", "#f472b6", "#fb923c", "#facc15", "#4ade80", "#f87171"}

// brMutate reloads the shared config from disk, applies fn and saves (several browser
// windows - separate processes - may change it).
func brMutate(fn func(c *brConfig)) {
	brMu.Lock()
	defer brMu.Unlock()
	brCfg = nil
	brLoad()
	fn(brCfg)
	brSave()
}

// pickProfile returns the requested profile, the last used one, or creates "Personal".
func pickProfile(id string) *brProfile {
	var out *brProfile
	brMutate(func(c *brConfig) {
		if p := c.profile(id); p != nil {
			out = p
		} else {
			for _, p := range c.Profiles {
				if out == nil || p.LastUsed > out.LastUsed {
					out = p
				}
			}
		}
		if out == nil {
			out = &brProfile{ID: newID(), Name: "Personal", Color: profileColors[0], Created: time.Now().Unix()}
			c.Profiles = append(c.Profiles, out)
		}
		out.LastUsed = time.Now().Unix()
		if out.Search == "" {
			out.Search = "google"
		}
	})
	return out
}

// bypassArg converts "site.com, other.org" into a Chromium proxy bypass list.
func bypassArg(s string) string {
	var out []string
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ';' || r == ' ' || r == '\n' }) {
		f = strings.ToLower(strings.TrimSpace(f))
		f = strings.TrimPrefix(strings.TrimPrefix(f, "https://"), "http://")
		f = strings.TrimPrefix(f, "*.")
		if i := strings.IndexAny(f, "/?#"); i >= 0 {
			f = f[:i]
		}
		if f == "" || !regexp.MustCompile(`^[a-z0-9.\-:\[\]]+$`).MatchString(f) {
			continue
		}
		out = append(out, f, "*."+f)
	}
	return strings.Join(out, ";")
}

// browserArgs builds the engine command line for a profile. With a proxy, everything is
// forced through the tunnel: hostnames are resolved by the proxy (local DNS is disabled),
// WebRTC may not send UDP outside the proxy, QUIC and background services are off.
func browserArgs(port int, bypass string) string {
	a := []string{"--no-first-run", "--disable-features=msSmartScreenProtection"}
	if port > 0 {
		a = append(a, fmt.Sprintf("--proxy-server=socks5://127.0.0.1:%d", port),
			"--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
			"--webrtc-ip-handling-policy=disable_non_proxied_udp",
			"--disable-quic", "--disable-background-networking", "--disable-component-update",
			"--disable-domain-reliability", "--no-pings", "--dns-prefetch-disable")
		rules := []string{"MAP * ~NOTFOUND", "EXCLUDE localhost", "EXCLUDE 127.0.0.1"}
		if b := bypassArg(bypass); b != "" {
			a = append(a, `--proxy-bypass-list="`+b+`"`)
			for _, h := range strings.Split(b, ";") {
				rules = append(rules, "EXCLUDE "+h)
			}
		}
		a = append(a, `--host-resolver-rules="`+strings.Join(rules, ", ")+`"`)
	}
	return strings.Join(a, " ")
}

// ---------------------------------------------------------------- location of the proxy exit

type geoInfo struct {
	TZ       string
	Lat, Lon float64
	HasLoc   bool
	Country  string
}

// geoLookup asks public IP-info services *through the tunnel* (HTTP inbound on port+1)
// for the time zone and approximate location of the proxy's exit IP.
func geoLookup(port int, country string) geoInfo {
	pu, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", port+1))
	cl := &http.Client{Timeout: 7 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(pu)}}
	type src struct {
		u                    string
		tz, loc, lat, lon, c string
	}
	for _, s := range []src{
		{u: "https://ipinfo.io/json", tz: "timezone", loc: "loc", c: "country"},
		{u: "https://ipapi.co/json/", tz: "timezone", lat: "latitude", lon: "longitude", c: "country_code"},
		{u: "https://ipwho.is/", tz: "timezone.id", lat: "latitude", lon: "longitude", c: "country_code"},
		{u: "http://ip-api.com/json/?fields=timezone,lat,lon,countryCode", tz: "timezone", lat: "lat", lon: "lon", c: "countryCode"},
	} {
		resp, err := cl.Get(s.u)
		if err != nil {
			continue
		}
		var m map[string]any
		err = json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&m)
		resp.Body.Close()
		if err != nil || resp.StatusCode != 200 {
			continue
		}
		get := func(k string) any {
			var v any = m
			for _, part := range strings.Split(k, ".") {
				mm, ok := v.(map[string]any)
				if !ok {
					return nil
				}
				v = mm[part]
			}
			return v
		}
		tz, _ := get(s.tz).(string)
		if !validTZ(tz) {
			continue
		}
		g := geoInfo{TZ: tz}
		if c, _ := get(s.c).(string); c != "" {
			g.Country = strings.ToUpper(c)
		}
		if s.loc != "" {
			if l, _ := get(s.loc).(string); l != "" {
				if _, err := fmt.Sscanf(strings.Replace(l, ",", " ", 1), "%f %f", &g.Lat, &g.Lon); err == nil {
					g.HasLoc = true
				}
			}
		} else {
			la, ok1 := get(s.lat).(float64)
			lo, ok2 := get(s.lon).(float64)
			if ok1 && ok2 {
				g.Lat, g.Lon, g.HasLoc = la, lo, true
			}
		}
		return g
	}
	if tz := countryTZ[strings.ToUpper(country)]; tz != "" {
		return geoInfo{TZ: tz, Country: strings.ToUpper(country)}
	}
	return geoInfo{Country: strings.ToUpper(country)}
}

var tzRe = regexp.MustCompile(`^[A-Za-z]+(/[A-Za-z0-9_+\-]+){1,2}$|^UTC$`)

func validTZ(tz string) bool { return tz != "" && len(tz) < 64 && tzRe.MatchString(tz) }

// main time zone per country - used if every lookup service is unreachable
var countryTZ = map[string]string{
	"DE": "Europe/Berlin", "NL": "Europe/Amsterdam", "FR": "Europe/Paris", "GB": "Europe/London", "IE": "Europe/Dublin",
	"ES": "Europe/Madrid", "IT": "Europe/Rome", "PL": "Europe/Warsaw", "SE": "Europe/Stockholm", "FI": "Europe/Helsinki",
	"NO": "Europe/Oslo", "DK": "Europe/Copenhagen", "CH": "Europe/Zurich", "AT": "Europe/Vienna", "BE": "Europe/Brussels",
	"CZ": "Europe/Prague", "LT": "Europe/Vilnius", "LV": "Europe/Riga", "EE": "Europe/Tallinn", "RO": "Europe/Bucharest",
	"BG": "Europe/Sofia", "GR": "Europe/Athens", "PT": "Europe/Lisbon", "UA": "Europe/Kyiv", "RU": "Europe/Moscow",
	"TR": "Europe/Istanbul", "US": "America/New_York", "CA": "America/Toronto", "BR": "America/Sao_Paulo", "MX": "America/Mexico_City",
	"AE": "Asia/Dubai", "QA": "Asia/Qatar", "SA": "Asia/Riyadh", "KW": "Asia/Kuwait", "BH": "Asia/Bahrain", "OM": "Asia/Muscat",
	"PK": "Asia/Karachi", "IN": "Asia/Kolkata", "SG": "Asia/Singapore", "MY": "Asia/Kuala_Lumpur", "HK": "Asia/Hong_Kong",
	"JP": "Asia/Tokyo", "KR": "Asia/Seoul", "ID": "Asia/Jakarta", "TH": "Asia/Bangkok", "VN": "Asia/Ho_Chi_Minh",
	"AU": "Australia/Sydney", "NZ": "Pacific/Auckland", "ZA": "Africa/Johannesburg", "EG": "Africa/Cairo", "IL": "Asia/Jerusalem",
}

// ---------------------------------------------------------------- privacy scripts / traces

// privacyScript runs in every page before the site's own scripts.
const privacyScript = `(()=>{try{const d=(o,k,v)=>Object.defineProperty(o,k,{get:()=>v,configurable:true});d(Navigator.prototype,'doNotTrack','1');d(Navigator.prototype,'globalPrivacyControl',true);try{d(window,'doNotTrack','1')}catch(e){}}catch(e){}})();`

// traceFiles are removed from a profile on close in "leave no trace" mode
// (logins, cookies and saved passwords are kept).
var traceFiles = []string{
	"History", "History-journal", "Visited Links", "Top Sites", "Top Sites-journal", "Shortcuts", "Shortcuts-journal",
	"Network Action Predictor", "Network Action Predictor-journal", "Favicons", "Favicons-journal", "DIPS", "DIPS-journal",
	"Cache", "Code Cache", "GPUCache", "DawnGraphiteCache", "DawnWebGPUCache", "Sessions", "Current Session", "Current Tabs",
	"Last Session", "Last Tabs", "Session Storage", "Media History", "Media History-journal", "Download Service",
	"Platform Notifications", "Reporting and NEL", "Reporting and NEL-journal", "Network Persistent State", "TransportSecurity",
	"Trust Tokens", "Trust Tokens-journal",
}

// wipeTraces removes browsing traces of a (closed) profile.
func wipeTraces(id string) {
	base := filepath.Join(profileDir(id), "EBWebView")
	for _, f := range traceFiles {
		os.RemoveAll(filepath.Join(base, "Default", f))
		os.RemoveAll(filepath.Join(base, "Default", "Network", f))
	}
	for _, f := range []string{"Crashpad", "BrowserMetrics", "ShaderCache", "GrShaderCache", "GraphiteDawnCache", "Last Browser", "Last Version"} {
		os.RemoveAll(filepath.Join(base, f))
	}
	os.Remove(sessionPath(id))
	os.Remove(historyPath(id))
}

// ---------------------------------------------------------------- local page server

type sbServer struct {
	Base   string // http://127.0.0.1:port/token/
	engine func() string
	lang   func() string // Google interface language ("" = leave as Google decides)
}

func (s *sbServer) UIURL() string     { return s.Base + "ui" }
func (s *sbServer) StartURL() string  { return s.Base + "start" }
func (s *sbServer) PickerURL() string { return s.Base + "picker" }
func (s *sbServer) IsStart(u string) bool {
	return u == "" || u == "about:blank" || strings.HasPrefix(u, s.Base+"start")
}

// Display hides our own new-tab page address from the address bar.
func (s *sbServer) Display(u string) string {
	if s.IsStart(u) {
		return ""
	}
	return u
}

func startSBServer(engine func() string) (*sbServer, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	tok := randToken()
	s := &sbServer{Base: fmt.Sprintf("http://127.0.0.1:%d/%s/", ln.Addr().(*net.TCPAddr).Port, tok), engine: engine}
	mux := http.NewServeMux()
	page := func(w http.ResponseWriter, b []byte) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Write(b)
	}
	mux.HandleFunc("/"+tok+"/ui", func(w http.ResponseWriter, r *http.Request) { page(w, sbChromeHTML) })
	mux.HandleFunc("/"+tok+"/picker", func(w http.ResponseWriter, r *http.Request) { page(w, sbPickerHTML) })
	mux.HandleFunc("/"+tok+"/start", func(w http.ResponseWriter, r *http.Request) {
		e := engineByID(s.engine())
		hl := ""
		if e.ID == "google" && s.lang != nil {
			if l := s.lang(); l != "" {
				hl = `<input type="hidden" name="hl" value="` + strings.ReplaceAll(gCode(l), `"`, "") + `">`
			}
		}
		b := strings.NewReplacer("{{ENGINE_URL}}", e.URL, "{{ENGINE_NAME}}", e.Name, "{{HLINPUT}}", hl).Replace(string(sbStartHTML))
		page(w, []byte(b))
	})
	go http.Serve(ln, mux)
	return s, nil
}

var colorRe = regexp.MustCompile(`^#[0-9a-fA-F]{6}$`)

// leakyCandidate reports whether an ICE candidate carries a real (non-mDNS) address
// other than the proxy's exit address.
func leakyCandidate(c, exitIP string) bool {
	f := strings.Fields(c)
	if len(f) < 5 {
		return false
	}
	addr := f[4]
	if strings.HasSuffix(addr, ".local") || addr == exitIP {
		return false
	}
	ip := net.ParseIP(addr)
	if ip == nil {
		return false
	}
	return true // any raw address (private or public) is identifying
}

// pickerState lists profiles for the start-up picker (proxy names only, never links).
func pickerState(running func(id string) bool) map[string]any {
	brMu.Lock()
	defer brMu.Unlock()
	brCfg = nil
	c := brLoad()
	list := []map[string]any{}
	for _, p := range c.Profiles {
		px := ""
		if x := c.proxyFor(p); x != nil {
			px = x.Name
		}
		list = append(list, map[string]any{"id": p.ID, "name": p.Name, "color": p.Color, "proxy": px, "lastUsed": p.LastUsed, "running": running(p.ID)})
	}
	return map[string]any{"t": "state", "profiles": list, "colors": profileColors}
}
