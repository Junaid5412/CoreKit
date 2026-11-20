package main

// Security › reverse view.
//
// inspectFile answers, for one file: where it came from, who made it, what is inside it, which
// servers it talks to and what it can do to you. It only READS the file (it never runs it, never
// contacts the servers). The same code runs on Windows and inside the Android app
// (`corekit --inspect <file>`), so both platforms show identical fields.

import (
	"archive/zip"
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"debug/pe"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"path"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"
)

type inKV struct {
	K    string `json:"k"`
	V    string `json:"v"`
	Link string `json:"link,omitempty"`
}

type inEntry struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
	Flag string `json:"flag,omitempty"`
}

type inServer struct {
	Host  string   `json:"host"`
	Kind  string   `json:"kind"` // ip | domain
	Count int      `json:"count"`
	Why   string   `json:"why"`
	Sev   string   `json:"sev"` // high | med | low | info
	URLs  []string `json:"urls,omitempty"`
	Link  string   `json:"link"`
}

type inCap struct {
	T   string `json:"t"`   // what it can do, plain English
	Why string `json:"why"` // why that matters to you
	Ev  string `json:"ev"`  // the evidence found in the file
	Sev string `json:"sev"`
}

type inReport struct {
	Exists   bool       `json:"exists"`
	Path     string     `json:"path"`
	Inner    string     `json:"inner,omitempty"`
	Kind     string     `json:"kind"` // program | archive | android | script | document | other
	KindText string     `json:"kindText"`
	Size     int64      `json:"size"`
	MD5      string     `json:"md5,omitempty"`
	SHA1     string     `json:"sha1,omitempty"`
	SHA256   string     `json:"sha256,omitempty"`
	Created  int64      `json:"created,omitempty"`
	Modified int64      `json:"modified,omitempty"`
	Accessed int64      `json:"accessed,omitempty"`
	Source   []inKV     `json:"source"`  // who brought it here, from where, when
	Creator  []inKV     `json:"creator"` // who made it
	Contents []inEntry  `json:"contents,omitempty"`
	Servers  []inServer `json:"servers"`
	Caps     []inCap    `json:"caps"`
	Bad      []string   `json:"bad"` // why it is not good for you
	Notes    []string   `json:"notes,omitempty"`
	Risk     string     `json:"risk"` // high | med | low | none
	Summary  string     `json:"summary"`
}

// inPlat is what the operating system records about a file (filled by the platform code).
type inPlat struct {
	Owner    string   `json:"owner"`
	Created  int64    `json:"created"`
	Modified int64    `json:"modified"`
	Accessed int64    `json:"accessed"`
	Streams  []string `json:"streams"`
	Zone     []string `json:"zone"`
	Ver      *struct {
		Company, Product, Desc, Version, Orig, Internal, Copyright string
	} `json:"ver"`
	Sig *struct {
		Status, Subject, Issuer, Thumb, Stamped string
		From, To                                int64
	} `json:"sig"`
	// extra facts the caller knows (Defender, installer…)
	Extra []inKV `json:"-"`
}

const (
	inMaxRead   = 64 << 20  // bytes of one file analysed in memory
	inMaxBudget = 160 << 20 // bytes scanned across an archive
	inMaxNested = 100 << 20
)

// ---------------------------------------------------------------- entry point

func inspectFile(p string, plat inPlat) *inReport {
	r := &inReport{Path: p, Risk: "none"}
	st, err := os.Stat(p)
	if err != nil || st.IsDir() {
		r.Summary = "The file is not there any more (deleted, moved or removed by Windows Defender). Only the detection record is left."
		return r
	}
	r.Exists = true
	r.Size = st.Size()
	r.Modified = st.ModTime().Unix()
	if plat.Created > 0 {
		r.Created = plat.Created
	}
	if plat.Modified > 0 {
		r.Modified = plat.Modified
	}
	r.Accessed = plat.Accessed

	f, err := os.Open(p)
	if err != nil {
		r.Notes = append(r.Notes, "Could not open the file: "+err.Error())
		return r
	}
	defer f.Close()
	h1, h2, h3 := md5.New(), sha1.New(), sha256.New()
	var buf bytes.Buffer
	lim := io.LimitReader(f, inMaxRead)
	if _, err := io.Copy(io.MultiWriter(h1, h2, h3, &buf), lim); err != nil {
		r.Notes = append(r.Notes, "Could not read all of the file: "+err.Error())
	}
	if r.Size > inMaxRead {
		// hash the rest too, analyse only the first part
		if _, err := io.Copy(io.MultiWriter(h1, h2, h3), f); err == nil {
			r.Notes = append(r.Notes, fmt.Sprintf("Large file: the first %d MB were analysed in detail.", inMaxRead>>20))
		}
	}
	r.MD5, r.SHA1, r.SHA256 = hex.EncodeToString(h1.Sum(nil)), hex.EncodeToString(h2.Sum(nil)), hex.EncodeToString(h3.Sum(nil))
	data := buf.Bytes()

	a := &analysis{r: r, urls: map[string]int{}, hosts: map[string]*inServer{}, caps: map[string]inCap{}, budget: inMaxBudget}
	a.name = path.Base(strings.ReplaceAll(p, `\`, "/"))
	switch {
	case len(data) > 4 && string(data[:2]) == "MZ":
		a.pe(data, plat)
	case len(data) > 4 && string(data[:4]) == "PK\x03\x04", len(data) > 4 && string(data[:4]) == "PK\x05\x06":
		a.zip(p, r.Size)
	case len(data) > 4 && string(data[:4]) == "\x7fELF":
		r.Kind, r.KindText = "program", "Linux/Android native program (ELF)"
		a.text(data, "program")
	case len(data) > 8 && bytes.HasPrefix(data, []byte{0xd0, 0xcf, 0x11, 0xe0}):
		r.Kind, r.KindText = "document", "Old-style Office document"
		a.text(data, "document")
		if bytes.Contains(data, []byte("VBA")) || bytes.Contains(data, []byte("Macros")) {
			a.cap("high", "Can run hidden macro code when opened", "Macros are the classic way an email attachment installs malware.", "VBA / Macros stream")
		}
	case bytes.HasPrefix(data, []byte("%PDF")):
		r.Kind, r.KindText = "document", "PDF document"
		a.text(data, "document")
		for _, k := range []string{"/JavaScript", "/JS", "/Launch", "/OpenAction", "/EmbeddedFile"} {
			if bytes.Contains(data, []byte(k)) {
				a.cap("med", "The PDF contains active content ("+k+")", "PDFs normally need none; attackers use it to run code or open links.", k)
			}
		}
	default:
		ext := strings.ToLower(path.Ext(a.name))
		switch ext {
		case ".ps1", ".bat", ".cmd", ".vbs", ".js", ".jse", ".wsf", ".hta", ".sh", ".py":
			r.Kind, r.KindText = "script", "Script ("+ext+")"
		case ".lnk":
			r.Kind, r.KindText = "script", "Shortcut (can start any program)"
		default:
			r.Kind, r.KindText = "other", "File ("+strings.TrimPrefix(ext, ".")+")"
		}
		a.text(data, r.Kind)
		a.scriptCaps(data)
	}
	a.finish(plat)
	return r
}

// ---------------------------------------------------------------- analysis state

type analysis struct {
	r         *inReport
	name      string
	urls      map[string]int
	hosts     map[string]*inServer
	caps      map[string]inCap
	budget    int64
	notes     map[string]bool
	apk       bool
	nestedAPK bool
	signed    bool
	dotnet    bool
	packed    bool
	verified  bool // Windows verified the publisher\'s signature
}

func (a *analysis) note(s string) {
	if a.notes == nil {
		a.notes = map[string]bool{}
	}
	if !a.notes[s] {
		a.notes[s] = true
		a.r.Notes = append(a.r.Notes, s)
	}
}

func (a *analysis) cap(sev, t, why, ev string) {
	if _, ok := a.caps[t]; ok {
		return
	}
	a.caps[t] = inCap{T: t, Why: why, Ev: ev, Sev: sev}
}

func (a *analysis) creator(k, v string) {
	if strings.TrimSpace(v) != "" {
		a.r.Creator = append(a.r.Creator, inKV{K: k, V: v})
	}
}

// ---------------------------------------------------------------- strings

var (
	reURL   = regexp.MustCompile(`(?i)\b(?:https?|ftp|wss?)://[a-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{4,220}`)
	reIP    = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b`)
	reDom   = regexp.MustCompile(`(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|ru|cn|xyz|top|info|biz|me|cc|tk|ml|ga|cf|gq|co|app|dev|online|site|club|shop|live|pw|ws|su|to|in|pk|ir|onion|ly|gl|link|click|cloud|space|store|tech|icu|vip|work|buzz|rest|fun)\b`)
	reMail  = regexp.MustCompile(`(?i)\b[a-z0-9._%+-]{2,40}@(?:[a-z0-9-]+\.)+[a-z]{2,10}\b`)
	rePerm  = regexp.MustCompile(`android\.permission\.[A-Z_]+|com\.android\.[a-z.]*permission\.[A-Z_]+`)
	reDebug = regexp.MustCompile(`(?i)([a-z]:\\[^\x00\r\n"|<>]{3,160}\.pdb)`)
)

// stringsOf pulls readable text (ASCII and UTF-16) out of binary data.
func stringsOf(b []byte, min int, max int) []string {
	var out []string
	var cur []byte
	flush := func() {
		if len(cur) >= min {
			out = append(out, string(cur))
		}
		cur = cur[:0]
	}
	for _, c := range b {
		if c >= 0x20 && c < 0x7f || c == '\t' {
			cur = append(cur, c)
		} else {
			flush()
			if len(out) >= max {
				return out
			}
		}
	}
	flush()
	// UTF-16LE: ascii byte followed by 0
	cur = cur[:0]
	for i := 0; i+1 < len(b); i += 2 {
		if b[i+1] == 0 && (b[i] >= 0x20 && b[i] < 0x7f) {
			cur = append(cur, b[i])
		} else {
			if len(cur) >= min {
				out = append(out, string(cur))
			}
			cur = cur[:0]
			if len(out) >= max {
				return out
			}
			if b[i+1] != 0 { // misaligned: shift one byte
				i--
			}
		}
	}
	if len(cur) >= min {
		out = append(out, string(cur))
	}
	return out
}

// text scans data for addresses, mail addresses and known-bad phrases.
func (a *analysis) text(data []byte, kind string) {
	ss := stringsOf(data, 6, 300000)
	joined := strings.Join(ss, "\n")
	a.harvest(joined)
	if kind == "program" || kind == "android" {
		a.apiCaps(joined)
	}
}

func (a *analysis) harvest(joined string) {
	for _, u := range reURL.FindAllString(joined, 400) {
		u = strings.TrimRight(u, ".,;)'\"]")
		a.urls[u]++
		a.addHost(hostOf(u), u)
	}
	for _, ip := range reIP.FindAllString(joined, 400) {
		a.addHost(ip, "")
	}
	for _, d := range reDom.FindAllString(joined, 600) {
		a.addHost(strings.ToLower(d), "")
	}
	for _, m := range reMail.FindAllString(joined, 20) {
		lm := strings.ToLower(m)
		if !noiseDomain(lm[strings.Index(lm, "@")+1:]) {
			a.urls["mailto:"+lm]++
		}
	}
}

var noiseDomains = []string{
	"w3.org", "schemas.microsoft.com", "schemas.openxmlformats.org", "purl.org", "apache.org", "xmlsoap.org", "xml.org", "microsoft.com",
	"android.com", "googleapis.com", "gstatic.com", "google.com", "schemas.android.com", "mozilla.org", "oracle.com", "sun.com", "java.com", "eclipse.org",
	"jetbrains.com", "kotlinlang.org", "github.com/android", "digicert.com", "verisign.com", "symantec.com", "globalsign.com", "sectigo.com", "letsencrypt.org",
	"openssl.org", "gnu.org", "ietf.org", "unicode.org", "iana.org", "example.com", "example.org", "localhost", "adobe.com", "xmlpull.org", "slf4j.org",
	"qos.ch", "json.org", "square.github.io", "squareup.com", "fasterxml.com", "bouncycastle.org", "mspec.org", "windowsupdate.com", "msocsp.com",
	"nuget.org", "newtonsoft.com", "dotnetfoundation.org", "visualstudio.com", "windows.com", "live.com", "msftconnecttest.com", "bing.com", "office.com",
}

func noiseDomain(h string) bool {
	h = strings.ToLower(h)
	for _, n := range noiseDomains {
		if h == n || strings.HasSuffix(h, "."+n) {
			return true
		}
	}
	return false
}

func (a *analysis) addHost(h, url string) {
	h = strings.ToLower(strings.TrimSpace(h))
	if i := strings.LastIndex(h, ":"); i > 0 && !strings.Contains(h, "]") {
		h = h[:i]
	}
	if h == "" || strings.Count(h, ".") < 1 {
		return
	}
	isIP := net.ParseIP(h) != nil
	if isIP {
		ip := net.ParseIP(h)
		o := strings.Split(h, ".")
		// version numbers (4.0.30319.0, 1.0.0.0) look like addresses: skip the obvious ones
		if ip.IsLoopback() || ip.IsUnspecified() || len(o) != 4 || o[0] <= "4" && len(o[0]) == 1 || o[1] == "0" && o[2] == "0" || o[2] == "0" && o[3] == "0" || strings.HasPrefix(h, "255.") {
			return
		}
	} else if noiseDomain(h) {
		return
	}
	s := a.hosts[h]
	if s == nil {
		s = &inServer{Host: h, Kind: "domain"}
		if isIP {
			s.Kind = "ip"
		}
		a.hosts[h] = s
	}
	s.Count++
	if url != "" && len(s.URLs) < 4 {
		dup := false
		for _, x := range s.URLs {
			dup = dup || x == url
		}
		if !dup {
			s.URLs = append(s.URLs, url)
		}
	}
}

// classify says in plain words what kind of server a host is.
func classify(s *inServer) {
	h := s.Host
	switch {
	case s.Kind == "ip":
		ip := net.ParseIP(h)
		if ip != nil && ip.IsPrivate() {
			s.Why, s.Sev = "An address on a home or office network", "low"
		} else {
			s.Why, s.Sev = "A bare internet address with no website name. Normal programs use names; hidden control servers often use bare addresses", "med"
		}
		s.Link = "https://www.virustotal.com/gui/ip-address/" + h
		return
	case h == "api.telegram.org" || strings.HasSuffix(h, ".telegram.org") || h == "t.me":
		s.Why, s.Sev = "Telegram: spyware and stealers use Telegram bots to send out stolen data and receive commands", "high"
	case strings.Contains(h, "discord.com") || strings.Contains(h, "discordapp.com"):
		s.Why, s.Sev = "Discord: webhooks are a common way for stealers to upload stolen passwords and files", "high"
	case strings.Contains(h, "pastebin.") || strings.Contains(h, "hastebin") || strings.Contains(h, "paste.ee") || strings.Contains(h, "ghostbin") || h == "raw.githubusercontent.com" || strings.Contains(h, "gist.github"):
		s.Why, s.Sev = "Text-sharing site: often used to fetch new commands or settings that can be changed at any time", "med"
	case strings.Contains(h, "ngrok") || strings.Contains(h, "serveo.net") || strings.Contains(h, "localtunnel") || strings.Contains(h, "trycloudflare") || strings.Contains(h, "loca.lt"):
		s.Why, s.Sev = "Tunnel service: lets someone reach a computer hidden behind a router (typical for remote-control tools)", "high"
	case strings.Contains(h, "duckdns") || strings.Contains(h, "no-ip") || strings.Contains(h, "ddns") || strings.Contains(h, "hopto.org") || strings.Contains(h, "zapto.org") || strings.Contains(h, "myftp") || strings.Contains(h, "sytes.net") || strings.Contains(h, "servebeer"):
		s.Why, s.Sev = "Free changing-address (dynamic DNS) name: favoured by attackers who move their server often", "high"
	case strings.Contains(h, "firebaseio.com") || strings.Contains(h, "firebaseapp.com") || strings.Contains(h, "firebase"):
		s.Why, s.Sev = "Firebase database: many Android spy apps store their victims' data here", "med"
	case h == "bit.ly" || h == "tinyurl.com" || h == "t.co" || h == "goo.gl" || h == "is.gd" || h == "cutt.ly" || h == "rebrand.ly":
		s.Why, s.Sev = "Link shortener: hides where the link really goes", "med"
	case strings.HasSuffix(h, ".onion"):
		s.Why, s.Sev = "Tor hidden service: used to hide who runs the server", "high"
	case strings.Contains(h, "transfer.sh") || strings.Contains(h, "anonfiles") || strings.Contains(h, "gofile.io") || strings.Contains(h, "mega.nz") || strings.Contains(h, "file.io") || strings.Contains(h, "catbox.moe"):
		s.Why, s.Sev = "Anonymous file hosting: used to hand out payloads or collect stolen files", "med"
	case h == "ipify.org" || strings.HasSuffix(h, ".ipify.org") || h == "ifconfig.me" || h == "icanhazip.com" || strings.Contains(h, "ip-api.com") || strings.Contains(h, "ipinfo.io") || h == "checkip.amazonaws.com" || strings.Contains(h, "myexternalip"):
		s.Why, s.Sev = "Finds out your public internet address (often the first thing a spy tool reports home)", "med"
	case h == "github.com" || strings.HasSuffix(h, ".github.com") || strings.HasSuffix(h, "github.io") || strings.HasSuffix(h, "githubusercontent.com"):
		s.Why, s.Sev = "GitHub: where the code or files may have been published. Check the repository", "low"
	case strings.HasSuffix(h, ".tk") || strings.HasSuffix(h, ".ml") || strings.HasSuffix(h, ".ga") || strings.HasSuffix(h, ".cf") || strings.HasSuffix(h, ".gq") || strings.HasSuffix(h, ".xyz") || strings.HasSuffix(h, ".top") || strings.HasSuffix(h, ".icu") || strings.HasSuffix(h, ".pw") || strings.HasSuffix(h, ".click"):
		s.Why, s.Sev = "A free or very cheap web address ending that criminals favour. Unknown owner", "med"
	default:
		s.Why, s.Sev = "A server named in the file. Who runs it is unknown until you look it up", "low"
	}
	s.Link = "https://www.virustotal.com/gui/domain/" + h
}

// ---------------------------------------------------------------- Windows programs (PE)

var peAPIs = []struct {
	api, sev, t, why string
}{
	{"SetWindowsHookEx", "high", "Can watch what you type (keylogger)", "Passwords, bank logins and private messages can be recorded."},
	{"GetAsyncKeyState", "high", "Can read every key you press", "Passwords, bank logins and private messages can be recorded."},
	{"GetKeyboardState", "med", "Can read the keyboard state", "Used by keyloggers, but also by normal programs."},
	{"WriteProcessMemory", "high", "Can write code into other programs", "A way to hide inside a trusted program (process injection)."},
	{"CreateRemoteThread", "high", "Can start code inside other programs", "A way to hide inside a trusted program (process injection)."},
	{"NtUnmapViewOfSection", "high", "Can hollow out another program and replace it", "Process hollowing hides malware inside a normal-looking program."},
	{"VirtualAllocEx", "med", "Can reserve memory in other programs", "Often the first step of injecting code."},
	{"URLDownloadToFile", "high", "Can download and save files from the internet", "A downloader fetches the real malware after you run it."},
	{"InternetOpenUrl", "med", "Can open internet addresses", "Used to download things or talk to a server."},
	{"WinHttpSendRequest", "low", "Can talk to web servers", "Normal for many programs; check the servers it names."},
	{"BitBlt", "med", "Can take screenshots", "Spyware watches your screen."},
	{"GetClipboardData", "med", "Can read what you copy", "Crypto stealers swap wallet addresses you copy."},
	{"CryptEncrypt", "med", "Can encrypt data", "Ransomware locks your files this way (also normal for secure programs)."},
	{"BCryptEncrypt", "med", "Can encrypt data", "Ransomware locks your files this way (also normal for secure programs)."},
	{"IsDebuggerPresent", "low", "Checks whether it is being analysed", "Malware hides from researchers this way."},
	{"CheckRemoteDebuggerPresent", "med", "Checks whether it is being analysed", "Malware hides from researchers this way."},
	{"AdjustTokenPrivileges", "med", "Can ask for powerful system rights", "Needed to tamper with the system."},
	{"RegSetValueEx", "low", "Can change registry settings", "Used to start with Windows; normal for installers."},
	{"CreateServiceA", "med", "Can install a Windows service", "A way to start with Windows with high rights."},
	{"CreateServiceW", "med", "Can install a Windows service", "A way to start with Windows with high rights."},
	{"OpenProcessToken", "low", "Reads its own rights", "Normal for many programs."},
	{"LsaRetrievePrivateData", "high", "Can read stored secrets from Windows", "Password stealing."},
	{"CredEnumerate", "high", "Can list saved Windows passwords", "Password stealing."},
	{"CryptUnprotectData", "high", "Can unlock browser/Windows saved passwords", "This is how password stealers read your saved logins."},
	{"mouse_event", "med", "Can click for you", "Used by remote-control tools and click fraud."},
	{"SendInput", "med", "Can type and click for you", "Used by remote-control tools."},
	{"NetUserAdd", "high", "Can create user accounts", "A way to keep access to the computer."},
	{"WSAStartup", "low", "Uses the network", "Normal for many programs."},
	{"InternetReadFile", "low", "Downloads data from the internet", "Normal for many programs."},
	{"ShellExecute", "low", "Can start other programs", "Normal for many programs."},
	{"WinExec", "med", "Can run commands", "Old way to start other programs."},
}

var packerSections = []string{"upx0", "upx1", ".themida", ".vmp0", ".vmp1", ".aspack", ".adata", ".petite", ".enigma1", ".mpress1", ".nsp0", "pec1", ".winlice", "kkrunchy", ".boom"}

func (a *analysis) pe(data []byte, plat inPlat) {
	r := a.r
	r.Kind, r.KindText = "program", "Windows program"
	f, err := pe.NewFile(bytes.NewReader(data))
	if err != nil {
		r.KindText = "Windows program (damaged or unusual header)"
		a.note("The program header could not be read normally. Malware often corrupts it to confuse tools.")
		a.text(data, "program")
		return
	}
	defer f.Close()
	if f.Characteristics&0x2000 != 0 {
		r.KindText = "Windows library (DLL): code that other programs load"
	} else if f.Characteristics&0x2 != 0 {
		r.KindText = "Windows program (.exe)"
	}
	switch f.Machine {
	case 0x14c:
		r.KindText += ", 32-bit"
	case 0x8664:
		r.KindText += ", 64-bit"
	case 0xaa64:
		r.KindText += ", ARM64"
	}
	// creator facts
	if ts := int64(f.TimeDateStamp); ts > 0 {
		t := time.Unix(ts, 0).UTC()
		switch {
		case t.Year() < 1996 || t.After(time.Now().Add(48*time.Hour)):
			// Windows itself is built "reproducibly": the field holds a code, not a date
			a.creator("Build time (in the file)", "Not a real date (reproducible builds store a code here; some malware also fakes it)")
		default:
			a.creator("Built on", t.Format("2 Jan 2006 15:04")+" UTC (written by the builder; can be faked)")
		}
	} else {
		a.creator("Build time", "Blank. Some build tools do this on purpose; malware also does it to hide its age.")
	}
	// version info from Windows
	if v := plat.Ver; v != nil {
		a.creator("Company", v.Company)
		a.creator("Product", v.Product)
		a.creator("Description", v.Desc)
		a.creator("Version", v.Version)
		a.creator("Original file name", v.Orig)
		a.creator("Copyright", v.Copyright)
		if v.Company == "" && v.Product == "" && v.Desc == "" {
			a.note("It has no company, product or description. Honest programs almost always fill these in.")
		}
	}
	if s := plat.Sig; s != nil {
		a.signature(s.Status, s.Subject, s.Issuer, s.Thumb, s.Stamped, s.From, s.To)
	}
	// sections: packers, entropy, overlay
	var maxEnd int64
	var packedBy []string
	highEnt := 0
	for _, s := range f.Sections {
		end := int64(s.Offset) + int64(s.Size)
		if end > maxEnd {
			maxEnd = end
		}
		nm := strings.ToLower(strings.TrimRight(s.Name, "\x00"))
		for _, ps := range packerSections {
			if nm == ps {
				packedBy = append(packedBy, s.Name)
			}
		}
		if d, err := s.Data(); err == nil && len(d) > 2048 {
			if e := shannon(d); e > 7.2 && s.Characteristics&0x20 != 0 { // high-entropy CODE section
				highEnt++
			}
		}
	}
	if len(packedBy) > 0 {
		a.packed = true
		a.cap("high", "Is wrapped in a packer to hide its real code", "Packing stops antivirus from reading the program. Honest software rarely needs it.", "sections "+strings.Join(packedBy, ", "))
	} else if highEnt > 0 {
		a.packed = true
		a.cap("med", "Its code is scrambled (very high randomness)", "Encrypted or packed code is how malware hides from scanners.", "high-entropy code section")
	}
	if maxEnd > 0 && int64(len(data)) > maxEnd+4096 {
		a.note(fmt.Sprintf("%s of extra data is attached after the program ends. Installers do this, but so do droppers carrying a hidden payload.", fmtSize(int64(len(data))-maxEnd)))
	}
	// .NET?
	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader64:
		if len(oh.DataDirectory) > 14 && oh.DataDirectory[14].VirtualAddress != 0 {
			a.dotnet = true
		}
		a.pdb(data, f, oh.DataDirectory[:])
	case *pe.OptionalHeader32:
		if len(oh.DataDirectory) > 14 && oh.DataDirectory[14].VirtualAddress != 0 {
			a.dotnet = true
		}
		a.pdb(data, f, oh.DataDirectory[:])
	}
	if a.dotnet {
		a.note("Built with .NET. The original source can usually be read back with a free tool such as ILSpy.")
	}
	// imports
	syms, _ := f.ImportedSymbols()
	libs, _ := f.ImportedLibraries()
	if len(libs) > 0 {
		sort.Strings(libs)
		a.creator("Uses system libraries", strings.Join(firstN(libs, 12), ", "))
	}
	have := map[string]bool{}
	for _, s := range syms {
		if i := strings.Index(s, ":"); i > 0 {
			s = s[:i]
		}
		have[s] = true
	}
	if len(syms) < 4 && !a.dotnet && len(data) > 20000 {
		a.cap("med", "Hides which system features it uses", "Almost no visible imports: it loads them secretly at run time, a common malware trick.", fmt.Sprintf("%d imports", len(syms)))
	}
	for _, x := range peAPIs {
		for s := range have {
			if strings.HasPrefix(s, x.api) {
				a.cap(x.sev, x.t, x.why, s)
				break
			}
		}
	}
	// a second program inside the first
	if n := bytes.Count(data, []byte("This program cannot be run in DOS mode")); n > 1 {
		a.cap("high", fmt.Sprintf("Contains %d more program(s) inside it", n-1), "A program carrying another program is how droppers deliver their payload.", "embedded program headers")
	}
	a.text(data, "program")
	if a.dotnet && len(a.hosts) == 0 {
		a.note("No server names found in plain text. In .NET programs they are often stored encrypted or inside resources.")
	}
}

func (a *analysis) pdb(data []byte, f *pe.File, dd []pe.DataDirectory) {
	if len(dd) < 7 || dd[6].VirtualAddress == 0 || dd[6].Size < 28 {
		// fall back to a scan: the build path often survives as text
		if m := reDebug.FindString(string(data)); m != "" {
			a.creator("Build path left in the file", m)
		}
		return
	}
	off := rvaToOff(f, dd[6].VirtualAddress)
	for i := uint32(0); i+28 <= dd[6].Size && off >= 0 && int(off)+int(i)+28 <= len(data); i += 28 {
		e := data[int(off)+int(i):]
		typ := binary.LittleEndian.Uint32(e[12:])
		ptr := binary.LittleEndian.Uint32(e[24:])
		if typ == 2 && int(ptr)+24 < len(data) && string(data[ptr:ptr+4]) == "RSDS" {
			s := data[ptr+24:]
			if z := bytes.IndexByte(s, 0); z > 0 {
				a.creator("Build path left in the file", string(s[:z]))
				if u := userFromPath(string(s[:z])); u != "" {
					a.creator("Builder's Windows user name", u)
				}
			}
		}
	}
}

func userFromPath(p string) string {
	l := strings.ToLower(p)
	if i := strings.Index(l, `\users\`); i >= 0 {
		rest := p[i+7:]
		if j := strings.IndexByte(rest, '\\'); j > 0 {
			return rest[:j]
		}
	}
	return ""
}

func rvaToOff(f *pe.File, rva uint32) int64 {
	for _, s := range f.Sections {
		if rva >= s.VirtualAddress && rva < s.VirtualAddress+maxU32(s.VirtualSize, s.Size) {
			return int64(rva-s.VirtualAddress) + int64(s.Offset)
		}
	}
	return -1
}

func maxU32(a, b uint32) uint32 {
	if a > b {
		return a
	}
	return b
}

func (a *analysis) signature(status, subject, issuer, thumb, stamped string, from, to int64) {
	switch strings.ToLower(status) {
	case "valid":
		a.signed, a.verified = true, true
		a.creator("Signed by", cnOf(subject)+" (verified by Windows)")
	case "notsigned":
		a.creator("Signature", "None. Nobody vouches for who made this.")
		return
	case "":
		return
	default:
		a.creator("Signature", status+" (Windows does not trust it)")
	}
	if subject != "" {
		a.creator("Signer details", subject)
	}
	if issuer != "" {
		a.creator("Certificate issued by", cnOf(issuer))
	}
	if from > 0 {
		a.creator("Certificate valid", time.Unix(from, 0).UTC().Format("2 Jan 2006")+" to "+time.Unix(to, 0).UTC().Format("2 Jan 2006"))
	}
	if stamped != "" {
		a.creator("Time-stamped by", cnOf(stamped))
	}
	if thumb != "" {
		a.creator("Certificate fingerprint", thumb)
	}
}

func cnOf(dn string) string {
	for _, part := range strings.Split(dn, ", ") {
		if strings.HasPrefix(part, "CN=") {
			return strings.Trim(strings.TrimPrefix(part, "CN="), `"`)
		}
	}
	for _, part := range strings.Split(dn, ", ") {
		if strings.HasPrefix(part, "O=") {
			return strings.Trim(strings.TrimPrefix(part, "O="), `"`)
		}
	}
	return dn
}

func shannon(b []byte) float64 {
	var c [256]int
	for _, x := range b {
		c[x]++
	}
	var e float64
	n := float64(len(b))
	for _, v := range c {
		if v > 0 {
			p := float64(v) / n
			e -= p * math.Log2(p)
		}
	}
	return e
}

// ---------------------------------------------------------------- scripts

func (a *analysis) scriptCaps(data []byte) {
	l := strings.ToLower(string(data))
	for _, x := range []struct{ k, sev, t, why string }{
		{"-encodedcommand", "high", "Runs hidden (encoded) PowerShell", "Encoding is used to hide what the command does."},
		{"frombase64string", "med", "Decodes hidden text and runs it", "Scrambled code is how scripts avoid detection."},
		{"invoke-expression", "med", "Runs text as a command", "Lets downloaded or decoded text run as code."},
		{"iex(", "med", "Runs text as a command", "Lets downloaded or decoded text run as code."},
		{"downloadstring", "high", "Downloads code from the internet and runs it", "The real malware is fetched after you open the script."},
		{"downloadfile", "high", "Downloads a file from the internet", "The real malware is fetched after you open the script."},
		{"bitsadmin", "med", "Uses a Windows tool to download files quietly", "A way to avoid browser download warnings."},
		{"certutil", "med", "Uses a Windows tool to download or decode files", "A trick to avoid antivirus."},
		{"wscript.shell", "med", "Can run programs", "Script that starts other programs."},
		{"-windowstyle hidden", "med", "Hides its window", "Honest tools rarely hide themselves."},
		{"set-mppreference", "high", "Changes Windows Defender settings", "Malware switches protection off before doing harm."},
		{"vssadmin delete shadows", "high", "Deletes your Windows backups (shadow copies)", "Ransomware does this so you cannot recover files."},
		{"reg add", "low", "Changes the registry", "Often used to start with Windows."},
		{"schtasks", "low", "Creates scheduled tasks", "A way to start with Windows."},
	} {
		if strings.Contains(l, x.k) {
			a.cap(x.sev, x.t, x.why, x.k)
		}
	}
}

// ---------------------------------------------------------------- archives and Android apps

var execExt = map[string]bool{".exe": true, ".dll": true, ".scr": true, ".msi": true, ".bat": true, ".cmd": true, ".ps1": true, ".vbs": true, ".js": true, ".jse": true, ".hta": true, ".lnk": true, ".jar": true, ".apk": true, ".dex": true, ".so": true, ".sh": true, ".com": true, ".cpl": true, ".wsf": true}
var textExt = map[string]bool{".txt": true, ".md": true, ".py": true, ".js": true, ".ps1": true, ".bat": true, ".cmd": true, ".sh": true, ".java": true, ".kt": true, ".json": true, ".xml": true, ".yml": true, ".yaml": true, ".php": true, ".html": true, ".htm": true, ".cfg": true, ".ini": true, ".gradle": true, ".properties": true, ".vbs": true, ".cs": true, ".go": true, ".c": true, ".cpp": true, ".h": true}

func (a *analysis) zip(p string, size int64) {
	zr, err := zip.OpenReader(p)
	if err != nil {
		a.r.Kind, a.r.KindText = "archive", "Archive (could not be opened)"
		a.note("The archive is damaged or uses a format CoreKit cannot open: " + err.Error())
		return
	}
	defer zr.Close()
	a.zipReader(&zr.Reader, "", 0)
	a.r.Kind = "archive"
	switch {
	case a.apk:
		a.r.Kind, a.r.KindText = "android", "Android app (APK)"
	case a.nestedAPK:
		a.r.KindText = "ZIP archive with an Android app inside"
	default:
		a.r.KindText = "ZIP archive"
	}
}

func (a *analysis) zipReader(zr *zip.Reader, prefix string, depth int) {
	hasManifest, hasDex := false, 0
	var enc, execs int
	for _, zf := range zr.File {
		n := zf.Name
		l := strings.ToLower(n)
		if l == "androidmanifest.xml" {
			hasManifest = true
		}
		if strings.HasPrefix(l, "classes") && strings.HasSuffix(l, ".dex") && !strings.Contains(l, "/") {
			hasDex++
		}
	}
	isAPK := hasManifest && hasDex > 0
	if depth == 0 {
		if c := strings.TrimSpace(zr.Comment); len(c) == 40 && isHex(c) {
			a.creator("Packed from GitHub commit", c)
			a.creator("Packed by", "GitHub's automatic 'Download ZIP' (so it is a copy of a public GitHub project)")
		}
	}
	if isAPK {
		if depth == 0 {
			a.apk = true
		} else {
			a.nestedAPK = true
		}
		a.apkInfo(zr, prefix)
	}
	for i, zf := range zr.File {
		if zf.FileInfo().IsDir() {
			continue
		}
		n := zf.Name
		ext := strings.ToLower(path.Ext(n))
		flag := ""
		if zf.Flags&1 != 0 {
			enc++
			flag = "password protected"
		}
		if execExt[ext] {
			execs++
			if flag == "" {
				flag = "program or script"
			}
		}
		if depth == 0 && len(a.r.Contents) < 200 && (i < 60 || execExt[ext]) {
			a.r.Contents = append(a.r.Contents, inEntry{Name: prefix + n, Size: int64(zf.UncompressedSize64), Flag: flag})
		}
		if zf.Flags&1 != 0 || a.budget <= 0 {
			continue
		}
		sz := int64(zf.UncompressedSize64)
		switch {
		case (ext == ".apk" || ext == ".jar" || ext == ".zip") && depth < 3 && sz <= inMaxNested:
			if b, err := readZipEntry(zf, sz); err == nil {
				a.budget -= sz
				if inner, err := zip.NewReader(bytes.NewReader(b), int64(len(b))); err == nil {
					if depth == 0 {
						a.r.Contents = append(a.r.Contents, inEntry{Name: n + " (opened)", Size: sz, Flag: "inside the archive"})
					}
					a.zipReader(inner, prefix+n+" › ", depth+1)
				}
			}
		case ext == ".exe" || ext == ".dll" || ext == ".scr":
			if sz <= 32<<20 {
				if b, err := readZipEntry(zf, sz); err == nil {
					a.budget -= sz
					a.text(b, "program")
					a.cap("med", "Contains a Windows program ("+path.Base(n)+")", "Programs hidden in archives skip some antivirus checks until you open them.", n)
				}
			}
		case ext == ".dex":
			// handled by apkInfo
		case textExt[ext] && sz <= 1<<20:
			if b, err := readZipEntry(zf, sz); err == nil {
				a.budget -= sz
				a.harvest(string(b))
				a.scriptCaps(b)
			}
		case ext == ".so" && sz <= 20<<20:
			if b, err := readZipEntry(zf, sz); err == nil {
				a.budget -= sz
				a.harvest(strings.Join(stringsOf(b, 8, 60000), "\n"))
			}
		}
		if a.budget <= 0 {
			a.note("The archive is very large: only the first part was searched.")
		}
		if depth == 0 && i > 20000 {
			a.note("The archive has more than 20,000 files: only the first ones were checked.")
			break
		}
	}
	if depth == 0 {
		if enc > 0 {
			a.cap("med", fmt.Sprintf("%d file(s) are password protected", enc), "A password hides the contents from antivirus. Malware emails use this on purpose.", "encrypted entries")
		}
		if len(zr.File) > 0 && execs > 0 && !a.apk {
			a.note(fmt.Sprintf("%d of the files inside are programs or scripts.", execs))
		}
		a.creator("Files inside", fmt.Sprintf("%d", len(zr.File)))
		var newest, oldest time.Time
		for _, zf := range zr.File {
			t := zf.Modified
			if t.IsZero() {
				continue
			}
			if newest.IsZero() || t.After(newest) {
				newest = t
			}
			if oldest.IsZero() || t.Before(oldest) {
				oldest = t
			}
		}
		if !newest.IsZero() {
			a.creator("Files inside were last changed", newest.Format("2 Jan 2006 15:04"))
		}
		if len(zr.File) > 0 {
			root := strings.SplitN(zr.File[0].Name, "/", 2)[0]
			if root != "" && strings.Contains(zr.File[0].Name, "/") {
				a.creator("Top folder name (project name)", root)
			}
		}
	}
}

func isHex(s string) bool {
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

func readZipEntry(zf *zip.File, size int64) ([]byte, error) {
	rc, err := zf.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(io.LimitReader(rc, size+1024))
}

var androidPerms = map[string]inCap{
	"READ_SMS":                           {"Can read your text messages", "Including one-time codes for your bank and accounts.", "", "high"},
	"RECEIVE_SMS":                        {"Can intercept incoming text messages", "Including one-time codes for your bank and accounts.", "", "high"},
	"SEND_SMS":                           {"Can send text messages", "It can send paid messages or spread itself to your contacts.", "", "high"},
	"READ_CALL_LOG":                      {"Can read who you called", "Your private call history.", "", "high"},
	"RECORD_AUDIO":                       {"Can record through the microphone", "It can listen to you and your surroundings.", "", "high"},
	"CAMERA":                             {"Can use the camera", "It can take photos or video without you looking.", "", "med"},
	"ACCESS_FINE_LOCATION":               {"Can see exactly where you are", "It can track your movements.", "", "med"},
	"ACCESS_BACKGROUND_LOCATION":         {"Can track your location when the app is closed", "It can follow you all day.", "", "high"},
	"READ_CONTACTS":                      {"Can read your contacts", "Your friends' and family's numbers.", "", "med"},
	"READ_EXTERNAL_STORAGE":              {"Can read your files and photos", "Anything in your storage.", "", "low"},
	"MANAGE_EXTERNAL_STORAGE":            {"Can access all your files", "Every photo, document and download.", "", "med"},
	"BIND_ACCESSIBILITY_SERVICE":         {"Can read the screen and tap for you (Accessibility)", "The strongest trick on Android: it can see passwords you type and approve things for itself.", "", "high"},
	"BIND_DEVICE_ADMIN":                  {"Can become a device administrator", "It becomes very hard to uninstall.", "", "high"},
	"SYSTEM_ALERT_WINDOW":                {"Can draw over other apps", "Fake login screens can be placed on top of your bank app.", "", "high"},
	"REQUEST_INSTALL_PACKAGES":           {"Can install other apps", "It can bring more malware.", "", "med"},
	"REQUEST_DELETE_PACKAGES":            {"Can uninstall apps", "It can remove security apps.", "", "low"},
	"QUERY_ALL_PACKAGES":                 {"Can list every app you have", "It can see which bank or security apps you use.", "", "low"},
	"RECEIVE_BOOT_COMPLETED":             {"Starts by itself when the phone starts", "It is always running without you opening it.", "", "low"},
	"READ_PHONE_STATE":                   {"Can read your phone number and device IDs", "Used to identify your phone.", "", "low"},
	"PROCESS_OUTGOING_CALLS":             {"Can see and change the numbers you dial", "It can redirect calls.", "", "high"},
	"WRITE_SETTINGS":                     {"Can change system settings", "It can alter how your phone behaves.", "", "low"},
	"BIND_NOTIFICATION_LISTENER_SERVICE": {"Can read all your notifications", "Including codes and private messages.", "", "high"},
	"ACCESS_NOTIFICATION_POLICY":         {"Can change Do Not Disturb", "It can silence alerts.", "", "low"},
	"WAKE_LOCK":                          {"Keeps the phone awake", "Drains battery; used by always-on apps.", "", "info"},
}

var dexAPIs = []struct{ k, sev, t, why string }{
	{"Ldalvik/system/DexClassLoader;", "high", "Loads hidden code while running", "The real behaviour can be downloaded later and was not visible when scanned."},
	{"Ldalvik/system/InMemoryDexClassLoader;", "high", "Loads hidden code while running", "The real behaviour can be downloaded later and was not visible when scanned."},
	{"Landroid/telephony/SmsManager;", "high", "Contains code that sends text messages", "Can send messages without you knowing."},
	{"Landroid/accessibilityservice/AccessibilityService;", "high", "Contains an Accessibility service", "Can watch the screen and press buttons."},
	{"Landroid/media/MediaRecorder;", "med", "Contains audio/video recording code", "Can record you."},
	{"Landroid/media/AudioRecord;", "med", "Contains audio recording code", "Can record you."},
	{"Landroid/app/admin/DevicePolicyManager;", "med", "Contains device-administrator code", "Can lock the phone or block uninstall."},
	{"Ljava/lang/Runtime;->exec", "med", "Can run system commands", "Runs commands outside the app's normal limits."},
	{"Landroid/webkit/WebView;->addJavascriptInterface", "low", "Mixes web pages with app code", "A web page may be able to call into the app."},
	{"Landroid/content/pm/PackageInstaller;", "med", "Can install apps", "Could install more malware."},
	{"getInstalledPackages", "low", "Lists your installed apps", "Profiles your phone."},
	{"Landroid/location/LocationManager;", "low", "Reads your location", "Can track you."},
	{"Landroid/provider/Telephony$Sms", "med", "Reads the text-message database", "Can read all your texts."},
	{"Landroid/provider/CallLog", "med", "Reads the call log", "Can read your call history."},
	{"Landroid/provider/ContactsContract", "low", "Reads contacts", "Can copy your contact list."},
	{"Ljavax/crypto/Cipher;", "info", "Uses encryption", "Normal for secure apps; ransomware also uses it."},
}

func (a *analysis) apkInfo(zr *zip.Reader, prefix string) {
	var manifest []byte
	var dexStr []string
	var abis = map[string]bool{}
	for _, zf := range zr.File {
		l := strings.ToLower(zf.Name)
		sz := int64(zf.UncompressedSize64)
		switch {
		case l == "androidmanifest.xml" && sz < 4<<20:
			manifest, _ = readZipEntry(zf, sz)
		case strings.HasPrefix(l, "classes") && strings.HasSuffix(l, ".dex") && !strings.Contains(l, "/") && sz < 80<<20 && a.budget > 0:
			if b, err := readZipEntry(zf, sz); err == nil {
				a.budget -= sz
				dexStr = append(dexStr, stringsOf(b, 6, 200000)...)
			}
		case strings.HasPrefix(l, "lib/") && strings.HasSuffix(l, ".so"):
			if p := strings.Split(l, "/"); len(p) > 2 {
				abis[p[1]] = true
			}
		case strings.HasPrefix(l, "meta-inf/") && (strings.HasSuffix(l, ".rsa") || strings.HasSuffix(l, ".dsa") || strings.HasSuffix(l, ".ec")) && sz < 1<<20:
			if b, err := readZipEntry(zf, sz); err == nil {
				a.apkCert(b)
			}
		}
	}
	// permissions and package name live in the binary manifest
	perms := map[string]bool{}
	if manifest != nil {
		ms := strings.Join(stringsOf(manifest, 4, 5000), "\n")
		for _, p := range rePerm.FindAllString(ms, 200) {
			perms[p] = true
		}
		if pkg := guessPackage(stringsOf(manifest, 6, 5000)); pkg != "" {
			a.creator("App package name", pkg)
		}
		if !strings.Contains(ms, "android.intent.category.LAUNCHER") {
			a.cap("med", "Has no icon to tap (it can hide)", "An app with no launcher entry does its work out of sight.", "no LAUNCHER activity")
		}
	}
	for p := range perms {
		short := p[strings.LastIndex(p, ".")+1:]
		if c, ok := androidPerms[short]; ok && c.Sev != "info" {
			c.Ev = p
			a.cap(c.Sev, c.T, c.Why, p)
		}
	}
	joined := strings.Join(dexStr, "\n")
	a.harvest(joined)
	for _, x := range dexAPIs {
		if strings.Contains(joined, x.k) && x.sev != "info" {
			a.cap(x.sev, x.t, x.why, strings.TrimPrefix(strings.Split(x.k, ";")[0], "L"))
		}
	}
	if len(abis) > 0 {
		var l []string
		for k := range abis {
			l = append(l, k)
		}
		sort.Strings(l)
		a.creator("Native code for", strings.Join(l, ", "))
	}
	if len(perms) > 0 {
		var l []string
		for k := range perms {
			l = append(l, strings.TrimPrefix(k, "android.permission."))
		}
		sort.Strings(l)
		a.creator("Permissions it asks for", fmt.Sprintf("%d: %s", len(l), strings.Join(firstN(l, 14), ", ")))
	}
	// obfuscation: many one-letter class names
	short := 0
	for _, s := range dexStr {
		if len(s) <= 4 && strings.HasPrefix(s, "L") && strings.HasSuffix(s, ";") {
			short++
		}
	}
	if short > 400 {
		a.note("Its class names were scrambled to single letters (obfuscation). That makes it harder to read, and is common in malware but also in many honest apps.")
	}
}

func guessPackage(ss []string) string {
	re := regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*){2,}$`)
	for _, s := range ss {
		if re.MatchString(s) && !strings.HasPrefix(s, "android.") && !strings.HasPrefix(s, "com.android.") && !strings.HasPrefix(s, "java.") && !strings.Contains(s, "permission") && !strings.HasPrefix(s, "androidx.") {
			return s
		}
	}
	return ""
}

// apkCert reads the signing certificate out of META-INF/*.RSA (a PKCS#7 file) by locating the
// embedded X.509 certificate.
func (a *analysis) apkCert(b []byte) {
	for i := 0; i+4 < len(b); i++ {
		if b[i] != 0x30 || b[i+1] != 0x82 {
			continue
		}
		l := int(b[i+2])<<8 | int(b[i+3])
		if l < 200 || i+4+l > len(b) {
			continue
		}
		c, err := x509.ParseCertificate(b[i : i+4+l])
		if err != nil {
			continue
		}
		sum := sha256.Sum256(c.Raw)
		sub := c.Subject.String()
		a.creator("App signed by", firstNonEmpty(c.Subject.CommonName, sub)+" "+orgOf(c.Subject.Organization))
		a.creator("Signing certificate", sub)
		a.creator("Certificate valid", c.NotBefore.Format("2 Jan 2006")+" to "+c.NotAfter.Format("2 Jan 2006"))
		a.creator("Certificate fingerprint (SHA-256)", hex.EncodeToString(sum[:]))
		if strings.Contains(strings.ToLower(sub), "android debug") {
			a.cap("med", "Signed with a throw-away developer key", "Not a real publisher: anyone can sign this way and nobody is accountable.", "CN=Android Debug")
		}
		if c.Subject.String() == c.Issuer.String() {
			a.note("The signing certificate is self-signed: the author vouches for themselves, no authority checked who they are.")
		}
		a.signed = true
		return
	}
}

func orgOf(o []string) string {
	if len(o) == 0 {
		return ""
	}
	return "(" + strings.Join(o, ", ") + ")"
}

func (a *analysis) apiCaps(joined string) {
	l := joined
	for _, x := range []struct{ k, sev, t, why string }{
		{"api.telegram.org/bot", "high", "Talks to a Telegram bot", "Used to send out stolen data and receive commands."},
		{"discord.com/api/webhooks", "high", "Sends data to a Discord webhook", "Used to upload stolen passwords and files."},
		{"Login Data", "high", "Looks for browser saved passwords", "The file where Chrome/Edge keep saved logins."},
		{"\\Local State", "med", "Looks at browser secret keys", "Needed to decrypt saved passwords."},
		{"wallet.dat", "high", "Looks for crypto wallets", "Cryptocurrency stealers target this file."},
		{"Software\\Microsoft\\Windows\\CurrentVersion\\Run", "med", "Can start with Windows", "A way to stay on your computer."},
		{"schtasks", "low", "Can create scheduled tasks", "A way to start with Windows."},
		{"vssadmin", "high", "Mentions deleting Windows backups", "Ransomware deletes shadow copies."},
		{"Your files have been encrypted", "high", "Contains a ransom note", "Ransomware."},
	} {
		if strings.Contains(l, x.k) {
			a.cap(x.sev, x.t, x.why, x.k)
		}
	}
}

// ---------------------------------------------------------------- finishing

func (a *analysis) finish(plat inPlat) {
	r := a.r
	// servers
	var servers []*inServer
	for _, s := range a.hosts {
		classify(s)
		servers = append(servers, s)
	}
	rank := map[string]int{"high": 0, "med": 1, "low": 2, "info": 3}
	sort.Slice(servers, func(i, j int) bool {
		if rank[servers[i].Sev] != rank[servers[j].Sev] {
			return rank[servers[i].Sev] < rank[servers[j].Sev]
		}
		return servers[i].Count > servers[j].Count
	})
	if len(servers) > 40 {
		servers = servers[:40]
	}
	for _, s := range servers {
		r.Servers = append(r.Servers, *s)
	}
	// capabilities, worst first
	for _, c := range a.caps {
		r.Caps = append(r.Caps, c)
	}
	sort.Slice(r.Caps, func(i, j int) bool {
		if rank[r.Caps[i].Sev] != rank[r.Caps[j].Sev] {
			return rank[r.Caps[i].Sev] < rank[r.Caps[j].Sev]
		}
		return r.Caps[i].T < r.Caps[j].T
	})

	// where it came from
	a.source(plat)

	// why it is not good for you
	hi, me := 0, 0
	for _, c := range r.Caps {
		switch c.Sev {
		case "high":
			hi++
		case "med":
			me++
		}
	}
	shi := 0
	for _, s := range r.Servers {
		if s.Sev == "high" {
			shi++
		}
	}
	for _, c := range r.Caps {
		if c.Sev == "high" {
			r.Bad = append(r.Bad, c.T+". "+c.Why)
		}
	}
	for _, s := range r.Servers {
		if s.Sev == "high" || (s.Sev == "med" && s.Kind == "ip") {
			r.Bad = append(r.Bad, "It names "+s.Host+": "+s.Why+".")
		}
	}
	if !a.signed && (r.Kind == "program" || r.Kind == "android") {
		r.Bad = append(r.Bad, "Nobody vouches for who made it: it has no verified publisher.")
	}
	if a.packed {
		r.Bad = append(r.Bad, "Its code is hidden on purpose, so antivirus programs cannot read it.")
	}
	if len(r.Bad) > 10 {
		r.Bad = r.Bad[:10]
	}
	score := hi*3 + me + shi*3
	switch {
	case score >= 9:
		r.Risk = "high"
	case score >= 4:
		r.Risk = "med"
	case score >= 1:
		r.Risk = "low"
	}
	switch r.Risk {
	case "high":
		r.Summary = "This looks dangerous: it can do several things that only spyware or malware does."
	case "med":
		r.Summary = "Some of what it can do is risky. Check where it came from before you trust it."
	case "low":
		r.Summary = "Nothing clearly dangerous was found inside, but a clean read does not prove a file is safe."
	default:
		r.Summary = "Nothing risky was found inside. This only looks at the file's contents; it can't see what it downloads later."
	}
	if a.verified && (r.Risk == "high" || r.Risk == "med") {
		if r.Risk == "high" {
			r.Risk = "med"
		} else {
			r.Risk = "low"
		}
		r.Summary += " It is signed by a verified publisher, so abilities like these are usually normal for that program."
	}
	if len(r.Servers) == 0 && len(r.Caps) == 0 {
		r.Notes = append(r.Notes, "No server addresses or risky abilities were found in plain view. Hidden or downloaded parts cannot be seen without running it, which CoreKit never does.")
	}
	if r.Source == nil {
		r.Source = []inKV{}
	}
	if r.Creator == nil {
		r.Creator = []inKV{}
	}
	if r.Servers == nil {
		r.Servers = []inServer{}
	}
	if r.Caps == nil {
		r.Caps = []inCap{}
	}
	if r.Bad == nil {
		r.Bad = []string{}
	}
}

// source puts together who brought the file here, from where and when.
func (a *analysis) source(plat inPlat) {
	r := a.r
	zone := map[string]string{}
	for _, l := range plat.Zone {
		if i := strings.Index(l, "="); i > 0 {
			zone[strings.TrimSpace(l[:i])] = strings.TrimSpace(l[i+1:])
		}
	}
	add := func(k, v, link string) {
		if strings.TrimSpace(v) != "" {
			r.Source = append(r.Source, inKV{K: k, V: v, Link: link})
		}
	}
	for _, e := range plat.Extra {
		add(e.K, e.V, e.Link)
	}
	if z := zone["ZoneId"]; z != "" {
		txt := map[string]string{"0": "this computer", "1": "your local network", "2": "a trusted site", "3": "the internet", "4": "an untrusted site"}[z]
		if txt == "" {
			txt = "zone " + z
		}
		add("Windows marked it as from", txt+" (the Mark of the Web)", "")
	} else if len(plat.Zone) == 0 && plat.Created > 0 && runtime.GOOS == "windows" {
		add("Internet mark", "None. It was not downloaded by a browser that marks files, or the mark was removed. Files copied from a USB stick, unpacked from an archive or created here have none.", "")
	}
	if u := zone["HostUrl"]; u != "" {
		add("Downloaded from", u, "")
		if g := githubRepo(u); g != "" {
			add("GitHub project", g, "https://github.com/"+g)
		}
		add("Website", hostOf(u), "")
	}
	if u := zone["ReferrerUrl"]; u != "" {
		add("Link was clicked on page", u, "")
	}
	if p := zone["LastWriterPackageFamilyName"]; p != "" {
		add("Saved by app", p, "")
	}
	if v := viaPath(r.Path); v != "" {
		add("It arrived by", v, "")
	}
	if plat.Owner != "" {
		add("Owner account", plat.Owner, "")
	}
	if r.Created > 0 {
		add("Appeared on this computer", time.Unix(r.Created, 0).Format("2 Jan 2006 15:04"), "")
	}
	if r.Modified > 0 && r.Modified != r.Created {
		add("Last changed", time.Unix(r.Modified, 0).Format("2 Jan 2006 15:04"), "")
	}
	if len(plat.Streams) > 0 {
		add("Hidden data streams", strings.Join(plat.Streams, ", "), "")
	}
	if runtime.GOOS == "windows" {
		if len(r.Source) == 0 {
			add("Origin", "Not recorded. Windows only records a download address for files saved by a browser.", "")
		}
		r.Source = append(r.Source, inKV{K: "About the sender", V: "Windows does not keep the name of the person who sent a file. If it came by email or chat, the sender is in that app's history around the time shown above."})
	} else {
		r.Source = append(r.Source, inKV{K: "About the sender", V: "Android records which app installed this one (shown above), not the person who sent it to you. If it came by chat or email, look in that app around the install time."})
	}
}

func viaPath(p string) string {
	l := strings.ToLower(p)
	switch {
	case strings.Contains(l, `\content.outlook\`):
		return "an Outlook email attachment"
	case strings.Contains(l, `\telegram desktop\`):
		return "Telegram"
	case strings.Contains(l, `\whatsapp`):
		return "WhatsApp"
	case strings.Contains(l, `\downloads\`) || strings.Contains(l, "/download"):
		return "a download (saved in Downloads)"
	case strings.Contains(l, `\temp\`):
		return "a temporary folder (unpacked by another program)"
	case strings.Contains(l, `\documents\`):
		return "saved in Documents"
	}
	return ""
}

var reGH = regexp.MustCompile(`(?i)(?:codeload\.github\.com|github\.com)/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)`)

func githubRepo(u string) string {
	if m := reGH.FindStringSubmatch(u); m != nil && m[1] != "login" {
		return m[1] + "/" + strings.TrimSuffix(m[2], ".git")
	}
	return ""
}

func firstN(s []string, n int) []string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func fmtSize(n int64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%d KB", n>>10)
	}
	return fmt.Sprintf("%d bytes", n)
}

// inspectJSON is what `corekit --inspect <file>` prints (used by the Android app).
func inspectJSON(p string) []byte {
	b, _ := json.Marshal(inspectFile(p, inPlat{}))
	return b
}
