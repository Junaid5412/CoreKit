package main

// Security module, Windows analysis. security.ps1 collects raw facts (processes, signatures,
// auto-start places, connections, Defender state ...); this file turns them into scored
// findings with plain-English reasons. It has no Windows calls so it is unit-tested anywhere.
//
// The result schema (secResult) is shared with Android: see docs/ARCHITECTURE.md.

import (
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"
	"time"
)

// ---------------------------------------------------------------- raw input (security.ps1)

type rawSec struct {
	Admin     bool                `json:"admin"`
	Self      int                 `json:"self"`       // the collector's own PID
	SelfPar   int                 `json:"selfParent"` // CoreKit.exe
	SelfPath  string              `json:"selfPath"`
	OS        string              `json:"os"`
	Host      string              `json:"host"`
	Defender  rawDefender         `json:"defender"`
	Firewall  []rawFirewall       `json:"fw"`
	UAC       int                 `json:"uac"`         // EnableLUA (1 on, 0 off, -1 unknown)
	Smart     string              `json:"smartscreen"` // Off | Warn | RequireAdmin | Block | ""
	SAC       int                 `json:"sac"`         // Smart App Control: 0 off, 1 on, 2 evaluation, -1 n/a
	Procs     []rawProc           `json:"procs"`
	Sigs      map[string]rawSig   `json:"sigs"`
	Files     map[string]rawFile  `json:"files"`
	Autoruns  []rawAutorun        `json:"autoruns"`
	Conns     []rawConn           `json:"conns"`
	Threats   []rawThreat         `json:"threats"`
	Hosts     []string            `json:"hosts"`
	HostsN    int                 `json:"hostsN"`
	Proxy     rawProxy            `json:"proxy"`
	Roots     []rawRoot           `json:"roots"`
	Policies  []rawPolicy         `json:"policies"`
	Appx      []rawApp            `json:"appx"`
	Programs  []rawApp            `json:"programs"`
	Downloads []string            `json:"downloads"`
	Notes     []string            `json:"notes"`
	Extra     map[string]any      `json:"extra,omitempty"`
	byPID     map[int]*rawProc    `json:"-"`
	childrenN map[int]int         `json:"-"`
	connsBy   map[int][]rawConn   `json:"-"`
	runningAt map[string][]int    `json:"-"`
	trusted   func(string) bool   `json:"-"`
	intel     map[string]secIntel `json:"-"`
	seenPaths map[string]struct{} `json:"-"`
}

type rawDefender struct {
	Present  bool              `json:"present"`
	RTP      bool              `json:"rtp"`
	AV       bool              `json:"av"`
	Tamper   bool              `json:"tamper"`
	SigAge   int               `json:"sigAge"` // days
	Passive  bool              `json:"passive"`
	Other    []string          `json:"otherAV"`
	ExclPath []string          `json:"exclPath"`
	ExclProc []string          `json:"exclProc"`
	ExclExt  []string          `json:"exclExt"`
	PUA      int               `json:"pua"`
	NetProt  int               `json:"netProt"`
	CFA      int               `json:"cfa"`
	Cloud    int               `json:"cloud"` // MAPSReporting
	ASR      map[string]string `json:"asr"`   // GUID (lower) -> Disabled | Enabled | AuditMode | Warn
	Readable bool              `json:"readable"`
}

type rawFirewall struct {
	Profile string `json:"profile"`
	Enabled bool   `json:"enabled"`
}

type rawProc struct {
	PID    int    `json:"pid"`
	PPID   int    `json:"ppid"`
	Name   string `json:"name"`
	Path   string `json:"path"`
	Cmd    string `json:"cmd"`
	Start  int64  `json:"start"`
	Exists bool   `json:"exists"`
	User   string `json:"user"`
}

type rawSig struct {
	Status string `json:"st"` // Valid | NotSigned | HashMismatch | NotTrusted | UnknownError ...
	Signer string `json:"signer"`
	MS     bool   `json:"ms"` // signed by Microsoft (Windows or Microsoft Corporation)
}

type rawFile struct {
	Size   int64  `json:"size"`
	Ctime  int64  `json:"ctime"`
	Mtime  int64  `json:"mtime"`
	Hidden bool   `json:"hidden"`
	Zone   int    `json:"zone"` // Mark of the Web zone, -1 none
	HostU  string `json:"host"` // download URL (HostUrl)
	Ref    string `json:"ref"`  // page that linked to it (ReferrerUrl)
	SHA    string `json:"sha256"`
	Desc   string `json:"desc"`
	Comp   string `json:"company"`
	Orig   string `json:"orig"` // OriginalFilename from the version resource
}

type rawAutorun struct {
	Kind   string `json:"kind"` // run | startup | task | service | wmi | ifeo | winlogon | appinit | lsa | policy
	Where  string `json:"where"`
	Name   string `json:"name"`
	Value  string `json:"value"`
	Target string `json:"target"`
	Exists bool   `json:"exists"`
	Hidden bool   `json:"hidden"`
	Author string `json:"author"`
	Key    string `json:"key"` // what the fixer needs to remove it (registry path, task path, service name ...)
	Off    bool   `json:"off"` // already disabled (StartupApproved / disabled task / disabled service)
}

type rawConn struct {
	PID    int    `json:"pid"`
	Remote string `json:"raddr"`
	RPort  int    `json:"rport"`
	LPort  int    `json:"lport"`
	State  string `json:"state"`
}

type rawThreat struct {
	Name   string `json:"name"`
	Path   string `json:"path"`
	Time   int64  `json:"t"`
	Action string `json:"action"`
	Status string `json:"status"`
	Sev    string `json:"sev"`
	ID     string `json:"id"`
}

type rawProxy struct {
	On     bool   `json:"on"`
	Server string `json:"server"`
	PAC    string `json:"pac"`
}

type rawRoot struct {
	Subject string `json:"subject"`
	Thumb   string `json:"thumb"`
	From    int64  `json:"from"`
	Store   string `json:"store"`
}

type rawPolicy struct {
	Browser string `json:"browser"`
	Name    string `json:"name"`
	Value   string `json:"value"`
	Key     string `json:"key"`
}

type rawApp struct {
	Name      string `json:"name"`
	ID        string `json:"id"`
	Publisher string `json:"publisher"`
	Size      int64  `json:"size"`
	Uninstall string `json:"uninstall"`
	Removable bool   `json:"removable"`
	Version   string `json:"version"`
	Date      string `json:"date"` // yyyymmdd (programs)
}

// secApp is one row of the "All apps" list (every installed program or app).
type secApp struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Pkg       string   `json:"pkg,omitempty"`
	Publisher string   `json:"publisher,omitempty"`
	Kind      string   `json:"kind"`   // program | store (Windows) · user | system (Android)
	Source    string   `json:"source"` // where it came from, in words
	Side      bool     `json:"side,omitempty"`
	Version   string   `json:"version,omitempty"`
	Size      int64    `json:"size,omitempty"`
	First     int64    `json:"first,omitempty"`
	Last      int64    `json:"last,omitempty"`
	Sev       string   `json:"sev,omitempty"`   // from a finding about this app
	Score     int      `json:"score,omitempty"` // from a finding about this app
	FID       string   `json:"fid,omitempty"`   // that finding's id
	Rating    string   `json:"rating,omitempty"`
	Flags     []string `json:"flags,omitempty"`
	CanRemove bool     `json:"canRemove"`
	Enabled   bool     `json:"enabled"`
	Key       string   `json:"-"`
}

// ---------------------------------------------------------------- shared result schema

type secResult struct {
	Platform   string       `json:"platform"`
	Time       int64        `json:"t"`
	Host       string       `json:"host"`
	OS         string       `json:"os"`
	Admin      bool         `json:"admin"`
	Score      int          `json:"score"`   // 0-100, higher is safer
	Verdict    string       `json:"verdict"` // clean | attention | danger
	Counts     secCounts    `json:"counts"`
	Scanned    secScanned   `json:"scanned"`
	Protection []secProt    `json:"protection"`
	Findings   []secFinding `json:"findings"`
	Bloat      []secBloat   `json:"bloat"`
	Apps       []secApp     `json:"apps"`
	Notes      []string     `json:"notes"`
	Intel      string       `json:"intel"` // "on" | "off" | "error: ..."
	Ms         int64        `json:"ms"`
}

type secCounts struct {
	High int `json:"high"`
	Med  int `json:"med"`
	Low  int `json:"low"`
	Info int `json:"info"`
}

type secScanned struct {
	Processes   int `json:"processes"`
	Autoruns    int `json:"autoruns"`
	Files       int `json:"files"`
	Connections int `json:"connections"`
	Apps        int `json:"apps"`
	Lookups     int `json:"lookups"`
}

type secProt struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	State  string `json:"state"` // on | off | warn | unknown
	Detail string `json:"detail"`
	Fix    string `json:"fix,omitempty"` // hardening action id
}

type secReason struct {
	Text string `json:"t"`
	W    int    `json:"w"`
}

type secStep struct {
	PID  int    `json:"pid,omitempty"`
	Name string `json:"name"`
	Path string `json:"path,omitempty"`
	Cmd  string `json:"cmd,omitempty"`
	T    int64  `json:"t,omitempty"`
	Sig  string `json:"sig,omitempty"`
}

type secOrigin struct {
	URL  string `json:"url,omitempty"`
	Ref  string `json:"ref,omitempty"`
	Zone int    `json:"zone"`
	Via  string `json:"via,omitempty"`
	Text string `json:"text"`
}

type secPersist struct {
	Kind  string `json:"kind"`
	Where string `json:"where"`
	Value string `json:"value"`
}

type secNet struct {
	Remote string `json:"remote"`
	Port   int    `json:"port"`
	State  string `json:"state"`
}

type secIntel struct {
	Source  string   `json:"source"`
	Verdict string   `json:"verdict"` // malicious | unknown
	Family  string   `json:"family,omitempty"`
	Tags    []string `json:"tags,omitempty"`
	Link    string   `json:"link,omitempty"`
	First   string   `json:"first,omitempty"`
}

type secAction struct {
	ID    string `json:"id"` // kill | quarantine | remove | disable | trust | uninstall | appinfo | settings | harden | restore-setting
	Label string `json:"label"`
	Main  bool   `json:"main,omitempty"`
}

type secFinding struct {
	ID      string       `json:"id"`
	Kind    string       `json:"kind"` // process | autorun | file | setting | app | network | threat
	Sev     string       `json:"sev"`  // high | med | low | info
	Score   int          `json:"score"`
	Title   string       `json:"title"`
	Sub     string       `json:"sub"`
	Summary string       `json:"summary"`
	Reasons []secReason  `json:"reasons"`
	Path    string       `json:"path,omitempty"`
	SHA     string       `json:"sha256,omitempty"`
	Size    int64        `json:"size,omitempty"`
	Signer  string       `json:"signer,omitempty"`
	Signed  string       `json:"signed,omitempty"` // valid | unsigned | invalid | unknown
	Company string       `json:"company,omitempty"`
	Origin  *secOrigin   `json:"origin,omitempty"`
	Chain   []secStep    `json:"chain,omitempty"`
	Persist []secPersist `json:"persist,omitempty"`
	Net     []secNet     `json:"net,omitempty"`
	First   int64        `json:"first,omitempty"`
	Last    int64        `json:"last,omitempty"`
	Intel   []secIntel   `json:"intel,omitempty"`
	Actions []secAction  `json:"actions"`
	Advice  string       `json:"advice,omitempty"`
	MITRE   []string     `json:"mitre,omitempty"`
	PIDs    []int        `json:"pids,omitempty"`
	Pkg     string       `json:"pkg,omitempty"` // Android package
	FixKey  string       `json:"-"`
	Auto    []autoRef    `json:"-"`
}

// autoRef is what the fixer needs to remove (and later restore) one auto-start entry.
type autoRef struct {
	Kind  string `json:"kind"`
	Key   string `json:"key"`
	Name  string `json:"name"`
	Value string `json:"value"`
}

type secBloat struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Publisher string `json:"publisher"`
	Kind      string `json:"kind"`   // store | program | startup | system
	Rating    string `json:"rating"` // remove | optional | keep
	Why       string `json:"why"`
	Size      int64  `json:"size,omitempty"`
	Action    string `json:"action"` // remove | uninstall | disable | appinfo
	On        bool   `json:"on"`     // still installed/enabled
	Key       string `json:"-"`
}

// ---------------------------------------------------------------- helpers

func lc(s string) string { return strings.ToLower(s) }

// Windows paths are analysed the same way on every OS (tests run on Linux).
func winBase(p string) string {
	if i := strings.LastIndexAny(p, `\/`); i >= 0 {
		return p[i+1:]
	}
	return p
}

func winDir(p string) string {
	if i := strings.LastIndexAny(p, `\/`); i >= 0 {
		return p[:i]
	}
	return "."
}

func winExt(p string) string {
	b := winBase(p)
	if i := strings.LastIndex(b, "."); i >= 0 {
		return b[i:]
	}
	return ""
}

func normPath(p string) string {
	p = strings.TrimSpace(strings.Trim(strings.TrimSpace(p), `"`))
	if (len(p) >= 2 && p[1] == ':') || strings.Contains(p, `\`) {
		p = strings.ReplaceAll(p, "/", `\`)
	}
	if strings.HasPrefix(p, `\??\`) {
		p = p[4:]
	}
	return p
}

// sysDirs lists where real Windows programs live.
var sysRoot = `c:\windows`

func sysDir(p string) bool {
	q := lc(normPath(p))
	return strings.HasPrefix(q, sysRoot+`\system32\`) || strings.HasPrefix(q, sysRoot+`\syswow64\`) ||
		strings.HasPrefix(q, sysRoot+`\winsxs\`) || strings.HasPrefix(q, sysRoot+`\systemapps\`) ||
		strings.HasPrefix(q, sysRoot+`\immersivecontrolpanel\`) || winDir(q) == sysRoot ||
		strings.HasPrefix(q, sysRoot+`\microsoft.net\`) || strings.HasPrefix(q, sysRoot+`\servicing\`)
}

// userWritable reports places any program (or a download) can drop a file without admin rights.
func userWritable(p string) (bool, string) {
	q := lc(normPath(p))
	switch {
	case q == "":
		return false, ""
	case strings.Contains(q, `\appdata\local\temp\`) || strings.HasPrefix(q, sysRoot+`\temp\`):
		return true, "a temporary folder"
	case strings.Contains(q, `\$recycle.bin\`):
		return true, "the Recycle Bin"
	case strings.Contains(q, `\downloads\`):
		return true, "the Downloads folder"
	case strings.Contains(q, `\users\public\`):
		return true, "the shared Public folder"
	case strings.Contains(q, `\appdata\roaming\`):
		return true, "AppData\\Roaming"
	case strings.Contains(q, `\appdata\locallow\`):
		return true, "AppData\\LocalLow"
	case strings.Contains(q, `\appdata\local\`) && !strings.Contains(q, `\appdata\local\programs\`) && !strings.Contains(q, `\appdata\local\microsoft\`):
		return true, "AppData\\Local"
	case strings.HasPrefix(q, `c:\programdata\`) && strings.Count(q, `\`) <= 3:
		return true, "ProgramData"
	case strings.Contains(q, `\desktop\`) || strings.Contains(q, `\documents\`) || strings.Contains(q, `\pictures\`) || strings.Contains(q, `\music\`) || strings.Contains(q, `\videos\`):
		return true, "a personal folder"
	case strings.HasPrefix(q, sysRoot+`\tasks\`) || strings.HasPrefix(q, sysRoot+`\tracing\`) || strings.HasPrefix(q, sysRoot+`\debug\`) || strings.HasPrefix(q, sysRoot+`\fonts\`):
		return true, "a writable Windows sub-folder"
	}
	return false, ""
}

var exeExt = map[string]bool{".exe": true, ".scr": true, ".com": true, ".pif": true, ".cpl": true, ".dll": true, ".msi": true, ".bat": true, ".cmd": true, ".vbs": true, ".vbe": true, ".js": true, ".jse": true, ".wsf": true, ".wsh": true, ".hta": true, ".ps1": true, ".lnk": true, ".jar": true}
var lureExt = map[string]bool{".pdf": true, ".doc": true, ".docx": true, ".xls": true, ".xlsx": true, ".jpg": true, ".jpeg": true, ".png": true, ".txt": true, ".mp4": true, ".mp3": true, ".zip": true, ".rar": true, ".ppt": true, ".pptx": true}

func doubleExt(p string) bool {
	b := lc(winBase(normPath(p)))
	e := winExt(b)
	if !exeExt[e] {
		return false
	}
	return lureExt[winExt(strings.TrimSuffix(b, e))]
}

// names of core Windows programs and the only folders they may run from
var sysNames = map[string][]string{
	"svchost.exe": {`\system32\`, `\syswow64\`}, "lsass.exe": {`\system32\`}, "csrss.exe": {`\system32\`},
	"smss.exe": {`\system32\`}, "wininit.exe": {`\system32\`}, "winlogon.exe": {`\system32\`},
	"services.exe": {`\system32\`}, "spoolsv.exe": {`\system32\`}, "explorer.exe": {`c:\windows\explorer.exe`, `\syswow64\`},
	"taskhostw.exe": {`\system32\`}, "dllhost.exe": {`\system32\`, `\syswow64\`}, "conhost.exe": {`\system32\`},
	"rundll32.exe": {`\system32\`, `\syswow64\`}, "regsvr32.exe": {`\system32\`, `\syswow64\`}, "lsm.exe": {`\system32\`},
	"sihost.exe": {`\system32\`}, "ctfmon.exe": {`\system32\`, `\syswow64\`}, "dwm.exe": {`\system32\`},
	"searchindexer.exe": {`\system32\`}, "wmiprvse.exe": {`\system32\wbem\`, `\syswow64\wbem\`}, "audiodg.exe": {`\system32\`},
	"fontdrvhost.exe": {`\system32\`}, "runtimebroker.exe": {`\system32\`}, "taskmgr.exe": {`\system32\`, `\syswow64\`},
	"cmd.exe": {`\system32\`, `\syswow64\`}, "powershell.exe": {`\windowspowershell\v1.0\`}, "msmpeng.exe": {`\windows defender\`, `\microsoft\windows defender\platform\`},
}

func expectedSysPath(name, path string) bool {
	dirs := sysNames[lc(name)]
	q := lc(normPath(path))
	for _, d := range dirs {
		if strings.Contains(q, d) && (strings.HasPrefix(q, sysRoot) || strings.Contains(q, `\windows defender\`) || strings.Contains(q, `windows defender\platform`)) {
			return true
		}
	}
	return false
}

func editDistance(a, b string) int {
	if a == b {
		return 0
	}
	prev := make([]int, len(b)+1)
	cur := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			c := 1
			if a[i-1] == b[j-1] {
				c = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+c)
		}
		prev, cur = cur, prev
	}
	return prev[len(b)]
}

// real Windows / .NET programs whose names happen to be close to a core Windows name
var legitNames = map[string]bool{"smsvchost.exe": true, "svchost.exe": true, "sihost.exe": true, "lsaiso.exe": true, "csrss.exe": true, "conhost.exe": true, "dashost.exe": true, "dllhost.exe": true, "taskhost.exe": true, "taskhostw.exe": true, "searchhost.exe": true, "wmiprvse.exe": true}

// lookalike returns the Windows name a file name imitates (svch0st.exe -> svchost.exe).
func lookalike(name string) string {
	n := lc(name)
	if _, ok := sysNames[n]; ok || len(n) < 9 {
		return ""
	}
	if !strings.HasSuffix(n, ".exe") {
		return ""
	}
	names := make([]string, 0, len(sysNames))
	for k := range sysNames {
		names = append(names, k)
	}
	sort.Strings(names)
	best, bestD, bestAna := "", 3, false
	for _, real := range names {
		if real == "cmd.exe" || real == "lsm.exe" || real == "dwm.exe" {
			continue
		}
		d := editDistance(n, real)
		ana := sortedLetters(n) == sortedLetters(real) // swapped letters: scvhost -> svchost
		if d >= 1 && d <= 2 && (d < bestD || (d == bestD && ana && !bestAna)) {
			best, bestD, bestAna = real, d, ana
		}
	}
	return best
}

func sortedLetters(s string) string {
	b := []byte(s)
	sort.Slice(b, func(i, j int) bool { return b[i] < b[j] })
	return string(b)
}

var pathInCmd = regexp.MustCompile(`(?i)[a-z]:\\[^"'*?<>|\r\n]+?\.(exe|dll|scr|vbs|vbe|js|jse|wsf|hta|ps1|bat|cmd|jar)\b`)

// ---------------------------------------------------------------- command-line rules (living off the land)

type cmdRule struct {
	re     *regexp.Regexp
	w      int
	text   string
	mitre  string
	bin    string // only for this program (base name), "" = any
	strong bool
}

var cmdRules = []cmdRule{
	{regexp.MustCompile(`(?i)\s-(e|en|enc|enco|encod|encode|encoded|encodedc|encodedcommand)\s+[a-z0-9+/=]{24,}`), 45, "Runs a hidden, encoded PowerShell command", "T1027", "", true},
	{regexp.MustCompile(`(?i)(-w|-windowstyle)\s+(h|hid|hidden)\b`), 20, "Starts PowerShell with a hidden window", "T1564.003", "", false},
	{regexp.MustCompile(`(?i)\b(iex|invoke-expression)\b`), 25, "Runs code it builds on the fly (Invoke-Expression)", "T1059.001", "", false},
	{regexp.MustCompile(`(?i)(downloadstring|downloadfile|downloaddata|net\.webclient|invoke-webrequest|\biwr\b|invoke-restmethod|\birm\b|start-bitstransfer)`), 30, "Downloads something from the internet", "T1105", "", false},
	{regexp.MustCompile(`(?i)frombase64string`), 20, "Decodes hidden (Base64) data", "T1140", "", false},
	{regexp.MustCompile(`(?i)-(ep|exec|executionpolicy)\s+(bypass|unrestricted)`), 10, "Turns off PowerShell's script safety check", "T1059.001", "", false},
	{regexp.MustCompile(`(?i)(add-mppreference|set-mppreference).*(exclusion|disable)`), 60, "Changes Windows Defender to ignore or switch off protection", "T1562.001", "", true},
	{regexp.MustCompile(`(?i)certutil.*(-urlcache|-verifyctl|-decode|-decodehex)`), 50, "Misuses certutil to download or decode a file", "T1105", "", true},
	{regexp.MustCompile(`(?i)bitsadmin.*/(transfer|addfile|create)`), 40, "Misuses bitsadmin to download a file", "T1197", "", true},
	{regexp.MustCompile(`(?i)mshta(\.exe)?["']?\s+.*(https?:|javascript:|vbscript:)`), 55, "Runs a script from the web with mshta", "T1218.005", "", true},
	{regexp.MustCompile(`(?i)rundll32(\.exe)?["']?\s+.*(javascript:|https?:|\\\\[a-z0-9])`), 50, "Uses rundll32 to run a script or a remote file", "T1218.011", "", true},
	{regexp.MustCompile(`(?i)regsvr32(\.exe)?["']?\s+.*(/i:\s*https?|scrobj)`), 55, "Uses regsvr32 to run a script from the web", "T1218.010", "", true},
	{regexp.MustCompile(`(?i)wmic(\.exe)?["']?\s+.*(process\s+call\s+create|/node:)`), 40, "Uses WMIC to start programs", "T1047", "", true},
	{regexp.MustCompile(`(?i)vssadmin(\.exe)?["']?\s+.*delete\s+shadows|wmic.*shadowcopy\s+delete|wbadmin.*delete\s+(catalog|systemstatebackup)`), 70, "Deletes Windows backups (a ransomware step)", "T1490", "", true},
	{regexp.MustCompile(`(?i)bcdedit.*(recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures)`), 60, "Disables Windows recovery (a ransomware step)", "T1490", "", true},
	{regexp.MustCompile(`(?i)wevtutil(\.exe)?["']?\s+(cl|clear-log)\b|clear-eventlog`), 55, "Erases Windows event logs (hides tracks)", "T1070.001", "", true},
	{regexp.MustCompile(`(?i)net1?(\.exe)?["']?\s+(user\s+\S+\s+\S+\s+/add|localgroup\s+administrators\s+\S+\s+/add)`), 45, "Creates a user or makes one an administrator", "T1136.001", "", true},
	{regexp.MustCompile(`(?i)reg(\.exe)?["']?\s+add\s+.*\\currentversion\\(run|runonce)\b`), 35, "Adds itself to start with Windows", "T1547.001", "", false},
	{regexp.MustCompile(`(?i)schtasks(\.exe)?["']?\s+/create`), 25, "Creates a scheduled task", "T1053.005", "", false},
	{regexp.MustCompile(`(?i)(curl|wget)(\.exe)?["']?\s+.*https?://.*(-o|--output|>)`), 25, "Downloads a file from the command line", "T1105", "", false},
	{regexp.MustCompile(`(?i)\b(msbuild|installutil|regasm|regsvcs)(\.exe)?["']?\s+.*\\(appdata|temp|users\\public|downloads)\\`), 50, "Uses a developer tool to run code from a user folder", "T1127", "", true},
	{regexp.MustCompile(`(?i)(wscript|cscript)(\.exe)?["']?\s+.*\\(appdata|temp|users\\public|downloads)\\.*\.(js|jse|vbs|vbe|wsf)`), 40, "Runs a script file from a user folder", "T1059.005", "", true},
	{regexp.MustCompile(`(?i)\bcmd(\.exe)?["']?\s+/[ck]\s+.*(powershell|mshta|certutil|bitsadmin)`), 20, "A command window launches another scripting tool", "T1059.003", "", false},
	{regexp.MustCompile(`(?i)\s(-nop|-noprofile)\b.*\s(-noni|-noninteractive)\b`), 10, "Runs PowerShell silently", "T1059.001", "", false},
	{regexp.MustCompile(`(?i)(stratum\+tcp|stratum\+ssl|--donate-level|cryptonight|randomx|xmrig|nicehash)`), 70, "Looks like a crypto-currency miner", "T1496", "", true},
	{regexp.MustCompile(`(?i)(mimikatz|sekurlsa|lsadump|procdump.*lsass|comsvcs(\.dll)?["']?,\s*#?minidump)`), 90, "Tries to steal saved passwords from memory", "T1003.001", "", true},
}

func cmdReasons(cmd string) ([]secReason, []string, bool) {
	var rs []secReason
	var mitre []string
	strong := false
	for _, r := range cmdRules {
		if r.re.MatchString(cmd) {
			rs = append(rs, secReason{r.text, r.w})
			mitre = append(mitre, r.mitre)
			strong = strong || r.strong
		}
	}
	return rs, mitre, strong
}

var officeApps = map[string]bool{"winword.exe": true, "excel.exe": true, "powerpnt.exe": true, "outlook.exe": true, "onenote.exe": true, "msaccess.exe": true, "mspub.exe": true, "visio.exe": true, "acrord32.exe": true, "acrobat.exe": true, "foxitpdfreader.exe": true, "wps.exe": true, "et.exe": true, "wpp.exe": true}
var shellTools = map[string]bool{"cmd.exe": true, "powershell.exe": true, "pwsh.exe": true, "wscript.exe": true, "cscript.exe": true, "mshta.exe": true, "rundll32.exe": true, "regsvr32.exe": true, "certutil.exe": true, "bitsadmin.exe": true, "msbuild.exe": true, "installutil.exe": true, "wmic.exe": true, "schtasks.exe": true, "curl.exe": true, "hh.exe": true, "forfiles.exe": true}

// Windows' own tools that attackers misuse: their Microsoft signature proves nothing.
var lolbins = map[string]bool{"vssadmin.exe": true, "wbadmin.exe": true, "bcdedit.exe": true, "wevtutil.exe": true, "net.exe": true, "net1.exe": true, "reg.exe": true, "cmstp.exe": true, "odbcconf.exe": true, "regasm.exe": true, "regsvcs.exe": true, "pcalua.exe": true, "mavinject.exe": true, "msiexec.exe": true, "sc.exe": true, "netsh.exe": true, "taskkill.exe": true, "cipher.exe": true, "esentutl.exe": true, "expand.exe": true, "extrac32.exe": true, "findstr.exe": true, "makecab.exe": true, "ntdsutil.exe": true, "msdt.exe": true, "control.exe": true, "comsvcs.dll": true}

func isTool(name string) bool { n := lc(name); return shellTools[n] || scriptHosts[n] || lolbins[n] }

var scriptHosts = map[string]bool{"wscript.exe": true, "cscript.exe": true, "mshta.exe": true}
var badPorts = map[int]string{4444: "a port used by hacking tools", 1337: "a port used by hacking tools", 31337: "a port used by hacking tools", 6666: "an IRC (botnet) port", 6667: "an IRC (botnet) port", 3333: "a crypto-mining port", 5555: "a crypto-mining / remote-debug port", 7777: "a crypto-mining port", 14444: "a crypto-mining port", 45700: "a crypto-mining port", 9050: "the Tor network", 9001: "the Tor network"}

func publicIP(s string) bool {
	ip := net.ParseIP(s)
	return ip != nil && !ip.IsLoopback() && !ip.IsPrivate() && !ip.IsLinkLocalUnicast() && !ip.IsUnspecified() && !ip.IsMulticast()
}

func sigState(s rawSig, ok bool) string {
	switch {
	case !ok:
		return "unknown"
	case s.Status == "Valid":
		return "valid"
	case s.Status == "NotSigned":
		return "unsigned"
	case s.Status == "HashMismatch" || s.Status == "NotTrusted" || s.Status == "Incompatible":
		return "invalid"
	}
	return "unknown"
}

func when(t int64) string {
	if t <= 0 {
		return ""
	}
	return time.Unix(t, 0).Format("2 Jan 2006, 15:04")
}

func ago(t int64, now int64) string {
	d := now - t
	switch {
	case t <= 0:
		return ""
	case d < 3600:
		return "less than an hour ago"
	case d < 86400:
		return fmt.Sprintf("%d hours ago", d/3600)
	case d < 86400*60:
		return fmt.Sprintf("%d days ago", d/86400)
	}
	return when(t)
}

// ---------------------------------------------------------------- origin (Mark of the Web)

func originOf(f rawFile, path string) *secOrigin {
	if f.Zone < 3 && f.HostU == "" && f.Ref == "" {
		return nil
	}
	o := &secOrigin{URL: f.HostU, Ref: f.Ref, Zone: f.Zone}
	switch {
	case f.HostU != "":
		o.Text = "Downloaded from " + hostOf(f.HostU)
		if f.Ref != "" && hostOf(f.Ref) != hostOf(f.HostU) {
			o.Text += ", linked from " + hostOf(f.Ref)
		}
	case f.Zone == 3:
		o.Text = "Came from the internet (download, email or chat)"
	case f.Zone == 4:
		o.Text = "Came from a website Windows marks as untrusted"
	default:
		o.Text = "Came from another computer on the network"
	}
	b := lc(winBase(path))
	switch {
	case strings.Contains(lc(path), `\content.outlook\`) || strings.Contains(lc(path), `\inetcache\`):
		o.Via = "Outlook email attachment"
	case strings.Contains(lc(path), `\telegram desktop\`):
		o.Via = "Telegram"
	case strings.Contains(lc(path), `\whatsapp`):
		o.Via = "WhatsApp"
	case strings.Contains(lc(path), `\downloads\`):
		o.Via = "a browser download"
	case strings.HasSuffix(b, ".tmp") || strings.Contains(lc(path), `\temp\`):
		o.Via = "unpacked into a temporary folder"
	}
	return o
}

func hostOf(u string) string {
	s := u
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if s == "" || s == "about:internet" {
		return "the internet"
	}
	return s
}

// ---------------------------------------------------------------- the analysis

func (r *rawSec) index() {
	r.byPID = map[int]*rawProc{}
	r.childrenN = map[int]int{}
	r.connsBy = map[int][]rawConn{}
	r.runningAt = map[string][]int{}
	for i := range r.Procs {
		p := &r.Procs[i]
		p.Path = normPath(p.Path)
		r.byPID[p.PID] = p
		if p.Path != "" {
			r.runningAt[lc(p.Path)] = append(r.runningAt[lc(p.Path)], p.PID)
		}
	}
	for _, p := range r.Procs {
		r.childrenN[p.PPID]++
	}
	for _, c := range r.Conns {
		r.connsBy[c.PID] = append(r.connsBy[c.PID], c)
	}
	if r.Sigs == nil {
		r.Sigs = map[string]rawSig{}
	}
	if r.Files == nil {
		r.Files = map[string]rawFile{}
	}
	lsig := map[string]rawSig{}
	for k, v := range r.Sigs {
		lsig[lc(normPath(k))] = v
	}
	r.Sigs = lsig
	lf := map[string]rawFile{}
	for k, v := range r.Files {
		lf[lc(normPath(k))] = v
	}
	r.Files = lf
}

func (r *rawSec) sig(path string) (rawSig, bool) {
	s, ok := r.Sigs[lc(normPath(path))]
	return s, ok
}

func (r *rawSec) file(path string) rawFile {
	f, ok := r.Files[lc(normPath(path))]
	if !ok {
		f.Zone = -1
	}
	return f
}

// chain walks parents (stopping at a recycled PID: a parent must start before its child).
func (r *rawSec) chain(p *rawProc) []secStep {
	out := []secStep{}
	cur := p
	seen := map[int]bool{}
	for i := 0; cur != nil && i < 8 && !seen[cur.PID]; i++ {
		seen[cur.PID] = true
		st := secStep{PID: cur.PID, Name: cur.Name, Path: cur.Path, Cmd: trimCmd(cur.Cmd), T: cur.Start}
		if s, ok := r.sig(cur.Path); ok {
			st.Sig = sigState(s, ok)
			if s.Signer != "" {
				st.Sig += ": " + s.Signer
			}
		}
		out = append([]secStep{st}, out...)
		par := r.byPID[cur.PPID]
		if par == nil || cur.PPID == cur.PID || (par.Start > 0 && cur.Start > 0 && par.Start > cur.Start) {
			break
		}
		cur = par
	}
	return out
}

func trimCmd(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 600 {
		return s[:600] + " …"
	}
	return s
}

func (r *rawSec) parentName(p *rawProc) string {
	par := r.byPID[p.PPID]
	if par == nil || (par.Start > 0 && p.Start > 0 && par.Start > p.Start) {
		return ""
	}
	return lc(par.Name)
}

// fileFacts adds reasons about one file (signature, folder, look-alike name, origin, age).
func (r *rawSec) fileFacts(f *secFinding, path, name string, now int64) (unsignedWritable bool) {
	if path == "" {
		return false
	}
	f.Path = path
	sg, ok := r.sig(path)
	f.Signed = sigState(sg, ok)
	f.Signer = sg.Signer
	fi := r.file(path)
	f.SHA = fi.SHA
	f.Size = fi.Size
	f.Company = fi.Comp
	if fi.Ctime > 0 {
		f.First = fi.Ctime
	}
	if o := originOf(fi, path); o != nil {
		f.Origin = o
	}
	uw, where := userWritable(path)
	base := name
	if base == "" {
		base = winBase(path)
	}
	tool := isTool(base) // a signature says nothing about how a tool is used
	switch f.Signed {
	case "unsigned":
		if uw && f.Kind == "file" {
			f.Reasons = append(f.Reasons, secReason{"Unsigned program saved in " + where, 20})
			unsignedWritable = true
		} else if uw {
			f.Reasons = append(f.Reasons, secReason{"Unsigned program running from " + where, 35})
			unsignedWritable = true
		} else if !sysDir(path) {
			f.Reasons = append(f.Reasons, secReason{"Not digitally signed (no verified publisher)", 12})
		}
	case "invalid":
		f.Reasons = append(f.Reasons, secReason{"Its digital signature is broken or forged (" + sg.Status + ")", 55})
	case "valid":
		if tool {
			f.Reasons = append(f.Reasons, secReason{"A Windows tool (signed by Microsoft); what matters is how it is used", 0})
		} else if sg.MS {
			f.Reasons = append(f.Reasons, secReason{"Signed by Microsoft", -30})
		} else {
			f.Reasons = append(f.Reasons, secReason{"Signed by " + sg.Signer, -15})
		}
	}
	if uw && f.Signed != "unsigned" && f.Signed != "valid" {
		f.Reasons = append(f.Reasons, secReason{"Runs from " + where, 15})
	}
	if _, isSys := sysNames[lc(base)]; isSys && !expectedSysPath(base, path) {
		f.Reasons = append(f.Reasons, secReason{"Uses the name of a Windows program (" + base + ") but runs from the wrong folder", 70})
		f.MITRE = append(f.MITRE, "T1036.005")
	} else if real := lookalike(base); real != "" && f.Signed != "valid" && !sysDir(path) && !legitNames[lc(base)] {
		f.Reasons = append(f.Reasons, secReason{"Name imitates the Windows program " + real, 45})
		f.MITRE = append(f.MITRE, "T1036.005")
	}
	if fi.Orig != "" && !strings.EqualFold(strings.TrimSuffix(fi.Orig, ".MUI"), base) && sysNames[lc(fi.Orig)] != nil && !sysDir(path) {
		f.Reasons = append(f.Reasons, secReason{"Is really " + fi.Orig + " copied and renamed", 45})
		f.MITRE = append(f.MITRE, "T1036.003")
	}
	if doubleExt(path) {
		f.Reasons = append(f.Reasons, secReason{"Disguised with a double extension (" + winBase(path) + ")", 50})
		f.MITRE = append(f.MITRE, "T1036.007")
	}
	if fi.Hidden && !sysDir(path) {
		f.Reasons = append(f.Reasons, secReason{"The file is hidden", 15})
	}
	if f.Origin != nil && f.Signed != "valid" {
		f.Reasons = append(f.Reasons, secReason{f.Origin.Text, 10})
	}
	if fi.Ctime > 0 && now-fi.Ctime < 3*86400 && f.Signed != "valid" {
		f.Reasons = append(f.Reasons, secReason{"Appeared on this PC " + ago(fi.Ctime, now), 10})
	}
	if it, ok := r.intel[lc(fi.SHA)]; ok && fi.SHA != "" && it.Verdict == "malicious" {
		fam := it.Family
		if fam == "" {
			fam = "a known malware sample"
		}
		f.Reasons = append(f.Reasons, secReason{"Known malware: " + fam + " (" + it.Source + ")", 100})
		f.Intel = append(f.Intel, it)
	}
	if r.trusted != nil && (r.trusted(lc(path)) || (fi.SHA != "" && r.trusted(lc(fi.SHA)))) {
		f.Reasons = append(f.Reasons, secReason{"You marked it as trusted", -200})
	}
	return unsignedWritable
}

func sevOf(score int) string {
	switch {
	case score >= 70:
		return "high"
	case score >= 40:
		return "med"
	case score >= 20:
		return "low"
	}
	return "info"
}

func total(rs []secReason) int {
	t := 0
	for _, x := range rs {
		t += x.W
	}
	if t > 100 {
		t = 100
	}
	if t < 0 {
		t = 0
	}
	return t
}

// analyzeSec builds the full Windows result. trusted reports allow-listed paths/hashes (lower case).
func analyzeSec(r *rawSec, now int64, trusted func(string) bool, intel map[string]secIntel) *secResult {
	r.trusted = trusted
	r.intel = intel
	r.index()
	res := &secResult{Platform: "windows", Time: now, Host: r.Host, OS: r.OS, Admin: r.Admin, Notes: append([]string{}, r.Notes...)}
	res.Scanned = secScanned{Processes: len(r.Procs), Autoruns: len(r.Autoruns), Files: len(r.Sigs), Connections: len(r.Conns), Apps: len(r.Appx) + len(r.Programs)}
	res.Protection = protectionOf(r)
	var fs []secFinding

	// ---- running programs
	for i := range r.Procs {
		p := &r.Procs[i]
		if p.PID <= 4 || p.Name == "" || p.PID == r.Self || (r.SelfPar > 0 && p.PID == r.SelfPar) || (r.SelfPath != "" && strings.EqualFold(normPath(p.Path), normPath(r.SelfPath))) {
			continue
		}
		if r.Self > 0 && p.PPID == r.Self { // programs the collector itself started
			continue
		}
		f := secFinding{Kind: "process", Title: p.Name, Sub: p.Path, PIDs: []int{p.PID}, Last: now}
		if p.Path == "" {
			f.Sub = "(location hidden)"
		}
		r.fileFacts(&f, p.Path, p.Name, now)
		if p.Start > 0 {
			f.First = min(nz(f.First, p.Start), p.Start)
		}
		pn := r.parentName(p)
		me := lc(p.Name)
		if officeApps[pn] && shellTools[me] {
			f.Reasons = append(f.Reasons, secReason{"Started by " + pn + " (documents should never start " + p.Name + ")", 60})
			f.MITRE = append(f.MITRE, "T1204.002")
		}
		if scriptHosts[pn] && (me == "powershell.exe" || me == "cmd.exe" || me == "pwsh.exe") {
			f.Reasons = append(f.Reasons, secReason{"Started by the script host " + pn, 30})
		}
		if me == "svchost.exe" && pn != "" && pn != "services.exe" && pn != "svchost.exe" {
			f.Reasons = append(f.Reasons, secReason{"A Windows service host started by " + pn + " instead of the Service Control Manager", 50})
		}
		if me == "lsass.exe" && pn != "" && pn != "wininit.exe" {
			f.Reasons = append(f.Reasons, secReason{"A copy of lsass.exe not started by Windows", 70})
		}
		if p.Path != "" && !p.Exists {
			f.Reasons = append(f.Reasons, secReason{"Its program file was deleted while it keeps running (hides from scanners)", 45})
			f.MITRE = append(f.MITRE, "T1070.004")
		}
		cr, cm, _ := cmdReasons(p.Cmd)
		f.Reasons = append(f.Reasons, cr...)
		f.MITRE = append(f.MITRE, cm...)
		// network
		pub := 0
		for _, c := range r.connsBy[p.PID] {
			if c.State != "Established" && c.State != "SynSent" {
				continue
			}
			if !publicIP(c.Remote) {
				continue
			}
			pub++
			if len(f.Net) < 12 {
				f.Net = append(f.Net, secNet{Remote: c.Remote, Port: c.RPort, State: c.State})
			}
			if why, bad := badPorts[c.RPort]; bad {
				f.Reasons = append(f.Reasons, secReason{fmt.Sprintf("Connected to %s:%d (%s)", c.Remote, c.RPort, why), 30})
			}
		}
		if pub > 0 && (f.Signed == "unsigned" || f.Signed == "invalid") {
			f.Reasons = append(f.Reasons, secReason{fmt.Sprintf("Unsigned program talking to %d internet address(es)", pub), 15})
		}
		if r.childrenN[p.PID] > 25 && f.Signed != "valid" {
			f.Reasons = append(f.Reasons, secReason{fmt.Sprintf("Started %d other programs", r.childrenN[p.PID]), 10})
		}
		f.Chain = r.chain(p)
		fs = append(fs, f)
	}

	// ---- auto-start places
	for _, a := range r.Autoruns {
		f := secFinding{Kind: "autorun", Title: autorunTitle(a), Sub: a.Where, Auto: []autoRef{{a.Kind, a.Key, a.Name, a.Value}}}
		f.Persist = []secPersist{{Kind: a.Kind, Where: a.Where, Value: a.Value}}
		tgt := normPath(a.Target)
		if tgt != "" {
			r.fileFacts(&f, tgt, winBase(tgt), now)
			if pids := r.runningAt[lc(tgt)]; len(pids) > 0 {
				f.PIDs = pids
			}
		}
		if a.Off {
			f.Reasons = append(f.Reasons, secReason{"Already turned off", -25})
		}
		// the command may start another file (cmd /c start x.exe, powershell -File x.ps1 ...)
		for _, m := range pathInCmd.FindAllString(a.Value, 4) {
			if strings.EqualFold(normPath(m), tgt) {
				continue
			}
			if uw, where := userWritable(m); uw {
				f.Reasons = append(f.Reasons, secReason{"Starts " + winBase(m) + " from " + where, 30})
				if f.Path == "" || isTool(winBase(f.Path)) {
					f.Path = normPath(m)
				}
			}
		}
		cr, cm, _ := cmdReasons(a.Value)
		f.Reasons = append(f.Reasons, cr...)
		f.MITRE = append(f.MITRE, cm...)
		switch a.Kind {
		case "wmi":
			f.Reasons = append(f.Reasons, secReason{"Hidden WMI trigger that runs a command (rarely used by normal software)", 55})
			f.MITRE = append(f.MITRE, "T1546.003")
		case "ifeo":
			acc := map[string]bool{"sethc.exe": true, "utilman.exe": true, "osk.exe": true, "magnify.exe": true, "narrator.exe": true, "displayswitch.exe": true, "atbroker.exe": true}
			if acc[lc(a.Name)] {
				f.Reasons = append(f.Reasons, secReason{"Replaces the " + a.Name + " accessibility tool: a known back door at the sign-in screen", 85})
			} else {
				f.Reasons = append(f.Reasons, secReason{"Hijacks " + a.Name + " so another program runs instead", 45})
			}
			f.MITRE = append(f.MITRE, "T1546.012")
		case "winlogon":
			f.Reasons = append(f.Reasons, secReason{"Changes what Windows runs at sign-in (" + a.Name + ")", 70})
			f.MITRE = append(f.MITRE, "T1547.004")
		case "appinit":
			f.Reasons = append(f.Reasons, secReason{"Loads a DLL into every program (AppInit_DLLs)", 60})
			f.MITRE = append(f.MITRE, "T1546.010")
		case "lsa":
			f.Reasons = append(f.Reasons, secReason{"A non-standard package loaded by the Windows sign-in system (LSA)", 35})
			f.MITRE = append(f.MITRE, "T1547.002")
		case "task":
			f.MITRE = append(f.MITRE, "T1053.005")
			if a.Hidden && f.Signed != "valid" && !strings.HasPrefix(lc(tgt), `c:\program files`) {
				f.Reasons = append(f.Reasons, secReason{"Scheduled task is marked hidden", 20})
			}
		case "service":
			f.MITRE = append(f.MITRE, "T1543.003")
		case "run", "startup":
			f.MITRE = append(f.MITRE, "T1547.001")
			ext := lc(winExt(tgt))
			if ext == ".vbs" || ext == ".js" || ext == ".jse" || ext == ".vbe" || ext == ".hta" || ext == ".wsf" || ext == ".ps1" || ext == ".bat" || ext == ".cmd" {
				f.Reasons = append(f.Reasons, secReason{"Starts a script file (" + ext + ") with Windows", 25})
			}
		}
		if tgt != "" && !a.Exists && a.Kind != "wmi" {
			f.Reasons = append(f.Reasons, secReason{"Points to a file that no longer exists (left-over entry)", 20})
			f.Advice = "Safe to remove: the program it starts is gone."
		}
		fs = append(fs, f)
	}

	// ---- program files waiting in Downloads (caught before they are ever opened)
	for _, d := range r.Downloads {
		d = normPath(d)
		if len(r.runningAt[lc(d)]) > 0 || (r.SelfPath != "" && strings.EqualFold(d, normPath(r.SelfPath))) {
			continue
		}
		f := secFinding{Kind: "file", Title: winBase(d), Sub: winDir(d)}
		r.fileFacts(&f, d, winBase(d), now)
		if f.Signed == "unsigned" {
			f.Reasons = append(f.Reasons, secReason{"Not opened yet: checked before it can run", 0})
		}
		fs = append(fs, f)
	}

	// ---- Defender's own findings
	for _, t := range r.Threats {
		f := secFinding{Kind: "threat", Title: t.Name, Sub: "Found by Windows Defender " + ago(t.Time, now), Path: normPath(t.Path), First: t.Time, FixKey: t.ID}
		st := lc(t.Status + " " + t.Action)
		f.Intel = []secIntel{{Source: "Windows Defender", Verdict: "malicious", Family: t.Name}}
		switch {
		case strings.Contains(st, "allow"):
			f.Reasons = append(f.Reasons, secReason{"Defender detected it but it was ALLOWED to stay", 85})
		case strings.Contains(st, "fail") || strings.Contains(st, "error") || strings.Contains(st, "active"):
			f.Reasons = append(f.Reasons, secReason{"Defender could not fully remove it (" + strings.TrimSpace(t.Status+" "+t.Action) + ")", 80})
		default:
			f.Reasons = append(f.Reasons, secReason{"Defender already dealt with it (" + strings.TrimSpace(t.Status+" "+t.Action) + ")", 5})
			f.Advice = "Nothing to do. Shown so you know what was blocked."
		}
		fs = append(fs, f)
	}

	// ---- Defender exclusions (malware adds itself here)
	for _, e := range r.Defender.ExclPath {
		w, why := 15, "Defender skips this folder"
		q := lc(normPath(e))
		if uw, where := userWritable(q + `\`); uw {
			w, why = 55, "Defender is told to skip "+where+", where malware usually hides"
		}
		if len(q) <= 3 || q == `c:\windows` || q == `c:\users` || q == `c:\programdata` {
			w, why = 80, "Defender is told to skip a whole drive or system folder"
		}
		fs = append(fs, secFinding{Kind: "setting", Title: "Defender exclusion: " + e, Sub: "Windows Defender settings", FixKey: "exclpath|" + e, Reasons: []secReason{{why, w}}, MITRE: []string{"T1562.001"}})
	}
	for _, e := range r.Defender.ExclProc {
		fs = append(fs, secFinding{Kind: "setting", Title: "Defender exclusion (program): " + e, Sub: "Windows Defender settings", FixKey: "exclproc|" + e, Reasons: []secReason{{"Defender is told to ignore everything this program does", 45}}, MITRE: []string{"T1562.001"}})
	}
	for _, e := range r.Defender.ExclExt {
		w := 20
		if exeExt["."+strings.TrimPrefix(lc(e), ".")] {
			w = 75
		}
		fs = append(fs, secFinding{Kind: "setting", Title: "Defender exclusion (file type): " + e, Sub: "Windows Defender settings", FixKey: "exclext|" + e, Reasons: []secReason{{"Defender is told to skip every ." + strings.TrimPrefix(e, ".") + " file", w}}, MITRE: []string{"T1562.001"}})
	}

	// ---- hosts file, proxy, root certificates, browser policies
	for _, h := range r.Hosts {
		hn := h
		if f := strings.Fields(h); len(f) >= 2 {
			hn = f[1]
		}
		fs = append(fs, secFinding{Kind: "setting", Title: "Hosts file redirect: " + hn, Sub: h, FixKey: "hosts|" + h, Reasons: []secReason{{"Redirects a security, update or popular website (blocks updates or sends you to a fake site)", 60}}, MITRE: []string{"T1565.001"}})
	}
	if r.Proxy.PAC != "" {
		fs = append(fs, secFinding{Kind: "setting", Title: "Automatic proxy script", Sub: r.Proxy.PAC, FixKey: "pac", Reasons: []secReason{{"All web traffic is routed by a script from " + hostOf(r.Proxy.PAC) + " (adware and bank-stealers use this)", 40}}, MITRE: []string{"T1090"}})
	}
	if r.Proxy.On && r.Proxy.Server != "" {
		fs = append(fs, secFinding{Kind: "setting", Title: "Proxy is on: " + r.Proxy.Server, Sub: "Windows internet settings", FixKey: "proxy", Reasons: []secReason{{"Web traffic goes through " + r.Proxy.Server + ". Fine if you set up a VPN or proxy yourself", 20}}, Advice: "Leave it if it's your own VPN or proxy tool."})
	}
	for _, c := range r.Roots {
		w := 35
		if now-c.From < 30*86400 {
			w = 45
		}
		fs = append(fs, secFinding{Kind: "setting", Title: "Extra trusted certificate: " + c.Subject, Sub: c.Store + " · added " + ago(c.From, now), FixKey: "root|" + c.Store + "|" + c.Thumb, Reasons: []secReason{{"A non-Microsoft root certificate lets its owner read or fake secure (https) websites", w}}, MITRE: []string{"T1553.004"}, Advice: "Keep it if your company, antivirus or a developer tool installed it."})
	}
	for _, p := range r.Policies {
		w, why := 35, "Changes "+p.Browser+" through a policy (users can't undo it in settings)"
		if strings.Contains(lc(p.Name), "extensioninstallforcelist") {
			w, why = 55, p.Browser+" is forced to install an extension you can't remove"
		}
		fs = append(fs, secFinding{Kind: "setting", Title: p.Browser + " policy: " + p.Name, Sub: p.Value, FixKey: "policy|" + p.Key + "|" + p.Name, Reasons: []secReason{{why, w}}, MITRE: []string{"T1176"}, Advice: "Keep it only if this is a work PC managed by your company."})
	}

	// ---- protection that is off becomes a finding too
	for _, p := range res.Protection {
		if p.State != "off" {
			continue
		}
		w := 30
		switch p.ID {
		case "rtp", "uac":
			w = 70
		case "av", "firewall":
			w = 55
		case "tamper", "sigs":
			w = 35
		case "smartscreen", "pua", "sac", "netprot", "cfa":
			w = 0 // shown on the protection panel only
		}
		if w == 0 {
			continue
		}
		fs = append(fs, secFinding{Kind: "setting", Title: p.Name + ": off", Sub: p.Detail, FixKey: "prot|" + p.ID, Reasons: []secReason{{p.Detail, w}}})
	}

	// ---- score, merge, actions
	out := []secFinding{}
	seen := map[string]int{}
	for _, f := range fs {
		f.Score = total(f.Reasons)
		f.Sev = sevOf(f.Score)
		if f.Sev == "info" && f.Kind != "threat" {
			continue
		}
		// one finding per file: a running program and its start-up entry are one story
		key := f.Kind + "|" + lc(f.Title) + "|" + lc(f.Sub)
		if f.Path != "" && (f.Kind == "process" || f.Kind == "autorun") && !isTool(winBase(f.Path)) && !sysDir(f.Path) {
			key = "file|" + lc(f.Path)
		}
		if i, ok := seen[key]; ok {
			out[i] = mergeFinding(out[i], f)
			continue
		}
		seen[key] = len(out)
		out = append(out, f)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Score > out[j].Score })
	for i := range out {
		f := &out[i]
		f.ID = fmt.Sprintf("w%d", i+1)
		f.Reasons = dedupeReasons(f.Reasons)
		f.MITRE = dedupe(f.MITRE)
		f.Actions = actionsFor(f)
		f.Summary = summaryOf(f)
		switch f.Sev {
		case "high":
			res.Counts.High++
		case "med":
			res.Counts.Med++
		case "low":
			res.Counts.Low++
		default:
			res.Counts.Info++
		}
	}
	res.Findings = out
	res.Bloat = bloatOf(r)
	res.Apps = appsOf(r, res.Bloat)
	res.Score, res.Verdict = overall(res)
	return res
}

func nz(a, b int64) int64 {
	if a == 0 {
		return b
	}
	return a
}

func mergeFinding(a, b secFinding) secFinding {
	if b.Score > a.Score {
		a, b = b, a
	}
	have := map[string]bool{}
	for _, r := range a.Reasons {
		have[r.Text] = true
	}
	for _, r := range b.Reasons {
		if !have[r.Text] && r.W > 0 {
			a.Reasons = append(a.Reasons, r)
		}
	}
	a.Persist = append(a.Persist, b.Persist...)
	a.PIDs = append(a.PIDs, b.PIDs...)
	if len(a.Chain) == 0 {
		a.Chain = b.Chain
	}
	a.Net = append(a.Net, b.Net...)
	a.MITRE = append(a.MITRE, b.MITRE...)
	a.Auto = append(a.Auto, b.Auto...)
	if a.FixKey == "" {
		a.FixKey = b.FixKey
	}
	if a.Kind == "autorun" && b.Kind == "process" {
		a.Kind = "process"
	}
	a.Score = total(a.Reasons)
	a.Sev = sevOf(a.Score)
	return a
}

func dedupe(s []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, x := range s {
		if x != "" && !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}

func dedupeReasons(rs []secReason) []secReason {
	seen := map[string]bool{}
	out := []secReason{}
	for _, r := range rs {
		if !seen[r.Text] {
			seen[r.Text] = true
			out = append(out, r)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].W > out[j].W })
	return out
}

func autorunTitle(a rawAutorun) string {
	n := a.Name
	if n == "" {
		n = winBase(normPath(a.Target))
	}
	switch a.Kind {
	case "task":
		return "Scheduled task: " + n
	case "service":
		return "Service: " + n
	case "wmi":
		return "WMI trigger: " + n
	case "ifeo":
		return "Program hijack: " + n
	case "winlogon":
		return "Sign-in hook: " + n
	case "appinit":
		return "DLL loaded into every program"
	case "lsa":
		return "Sign-in package: " + n
	case "startup":
		return "Startup folder: " + n
	}
	return "Starts with Windows: " + n
}

func actionsFor(f *secFinding) []secAction {
	var a []secAction
	switch f.Kind {
	case "process":
		if f.Path != "" && !sysDir(f.Path) {
			a = append(a, secAction{"quarantine", "Stop & quarantine", true})
		}
		a = append(a, secAction{"kill", "Stop it only", f.Path == "" || sysDir(f.Path)})
		if len(f.Auto) > 0 {
			a = append(a, secAction{"remove", "Remove from start-up", false})
		}
	case "file":
		a = append(a, secAction{"quarantine", "Quarantine file", true})
	case "autorun":
		if len(f.Auto) > 0 && f.Auto[0].Kind == "service" {
			a = append(a, secAction{"remove", "Disable service", true})
		} else {
			a = append(a, secAction{"remove", "Remove from start-up", true})
		}
		if f.Path != "" && f.Signed != "valid" {
			a = append(a, secAction{"quarantine", "Remove & quarantine file", false})
		}
	case "threat":
		if f.Score >= 40 {
			a = append(a, secAction{"defender", "Let Defender remove it", true})
		}
	case "setting":
		a = append(a, secAction{"fixsetting", settingLabel(f.FixKey), true})
	}
	if f.Path != "" || f.SHA != "" {
		a = append(a, secAction{"trust", "Trust it", false})
	}
	return a
}

func settingLabel(k string) string {
	switch {
	case strings.HasPrefix(k, "excl"):
		return "Remove exclusion"
	case strings.HasPrefix(k, "hosts"):
		return "Remove redirect"
	case k == "pac" || k == "proxy":
		return "Turn proxy off"
	case strings.HasPrefix(k, "root"):
		return "Remove certificate"
	case strings.HasPrefix(k, "policy"):
		return "Remove policy"
	}
	return "Turn on"
}

func summaryOf(f *secFinding) string {
	pos := []string{}
	for _, r := range f.Reasons {
		if r.W > 0 && len(pos) < 2 {
			pos = append(pos, r.Text)
		}
	}
	return strings.Join(pos, " · ")
}

func protectionOf(r *rawSec) []secProt {
	d := r.Defender
	var p []secProt
	onoff := func(b bool) string {
		if b {
			return "on"
		}
		return "off"
	}
	if d.Present {
		if d.Passive || (!d.AV && len(d.Other) > 0) {
			p = append(p, secProt{"av", "Antivirus", "on", "Protected by " + strings.Join(d.Other, ", ") + " (Defender is standing by)", ""})
		} else {
			p = append(p, secProt{"rtp", "Real-time protection", onoff(d.RTP), map[bool]string{true: "Windows Defender scans files as they open", false: "Windows Defender is not scanning files as they open"}[d.RTP], "rtp"})
			st := "on"
			det := "Virus definitions are up to date"
			if d.SigAge > 7 {
				st, det = "off", fmt.Sprintf("Virus definitions are %d days old", d.SigAge)
			} else if d.SigAge > 2 {
				st, det = "warn", fmt.Sprintf("Virus definitions are %d days old", d.SigAge)
			}
			p = append(p, secProt{"sigs", "Virus definitions", st, det, "sigs"})
			p = append(p, secProt{"tamper", "Tamper protection", onoff(d.Tamper), map[bool]string{true: "Malware can't switch Defender off", false: "Programs can switch Defender's settings off. Turn it on in Windows Security"}[d.Tamper], "tamper"})
			if d.Readable {
				p = append(p, secProt{"pua", "Block unwanted apps (PUA)", onoff(d.PUA == 1), "Stops adware, bundled toolbars and fake cleaners", "pua"})
				p = append(p, secProt{"netprot", "Network protection", onoff(d.NetProt == 1), "Blocks dangerous websites for every program, not just the browser", "netprot"})
				p = append(p, secProt{"cfa", "Ransomware folder guard", onoff(d.CFA == 1), "Only trusted apps can change Documents, Pictures and Desktop", "cfa"})
				on := 0
				for _, g := range asrRules {
					if v := d.ASR[g.ID]; v == "Enabled" || v == "Warn" {
						on++
					}
				}
				st := "off"
				if on >= len(asrRules)-3 {
					st = "on"
				} else if on > 0 {
					st = "warn"
				}
				p = append(p, secProt{"asr", "Attack blocking rules", st, fmt.Sprintf("%d of %d rules that stop attacks before they run", on, len(asrRules)), "asr"})
			}
		}
	} else {
		st := "unknown"
		if len(d.Other) > 0 {
			st = "on"
		}
		p = append(p, secProt{"av", "Antivirus", st, map[bool]string{true: "Protected by " + strings.Join(d.Other, ", "), false: "Could not read the antivirus status"}[len(d.Other) > 0], ""})
	}
	fwOff := []string{}
	for _, f := range r.Firewall {
		if !f.Enabled {
			fwOff = append(fwOff, f.Profile)
		}
	}
	if len(r.Firewall) > 0 {
		if len(fwOff) > 0 {
			p = append(p, secProt{"firewall", "Firewall", "off", "Off for " + strings.Join(fwOff, ", ") + " networks", "firewall"})
		} else {
			p = append(p, secProt{"firewall", "Firewall", "on", "On for all networks", ""})
		}
	}
	switch r.UAC {
	case 0:
		p = append(p, secProt{"uac", "Admin prompts (UAC)", "off", "Any program gets full control without asking", "uac"})
	case 1:
		p = append(p, secProt{"uac", "Admin prompts (UAC)", "on", "Windows asks before programs make changes", ""})
	}
	switch lc(r.Smart) {
	case "off":
		p = append(p, secProt{"smartscreen", "SmartScreen", "off", "Windows won't warn about unknown downloaded programs", "smartscreen"})
	case "":
	default:
		p = append(p, secProt{"smartscreen", "SmartScreen", "on", "Warns before unknown downloaded programs run", ""})
	}
	switch r.SAC {
	case 1:
		p = append(p, secProt{"sac", "Smart App Control", "on", "Windows blocks untrusted apps before they run", ""})
	case 2:
		p = append(p, secProt{"sac", "Smart App Control", "warn", "Learning mode: it will turn itself on or off", ""})
	case 0:
		p = append(p, secProt{"sac", "Smart App Control", "off", "Off. Windows only allows turning it on after a fresh install", ""})
	}
	return p
}

func overall(res *secResult) (int, string) {
	s := 100 - res.Counts.High*25 - res.Counts.Med*8 - res.Counts.Low*2
	for _, p := range res.Protection {
		if p.State == "off" {
			s -= 4
		}
	}
	if s < 0 {
		s = 0
	}
	v := "clean"
	if res.Counts.High > 0 {
		v = "danger"
	} else if res.Counts.Med > 0 || s < 80 {
		v = "attention"
	}
	return s, v
}

// ---------------------------------------------------------------- hardening (Attack Surface Reduction)

type asrRule struct {
	ID, Name, Mode string // Mode: the action we set (Enabled or Warn)
}

// The rules CoreKit switches on (IDs from Microsoft's ASR rules reference).
var asrRules = []asrRule{
	{"56a863a9-875e-4185-98a7-b882c64b5ce5", "Block abuse of vulnerable signed drivers", "Enabled"},
	{"9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2", "Block password stealing from the Windows sign-in system (LSASS)", "Enabled"},
	{"e6db77e5-3df2-4cf1-b95a-636979351e5b", "Block hidden start-up through WMI", "Enabled"},
	{"7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c", "Block Adobe Reader from starting programs", "Enabled"},
	{"d4f940ab-401b-4efc-aadc-ad5f3c50688a", "Block Office from starting programs", "Enabled"},
	{"be9ba2d9-53ea-4cdc-84e5-9b1eeee46550", "Block programs in email attachments", "Enabled"},
	{"01443614-cd74-433a-b99e-2ecdc07bfc25", "Warn before new, unknown programs run", "Warn"},
	{"5beb7efe-fd9a-4556-801d-275e5ffc04cc", "Block hidden (obfuscated) scripts", "Enabled"},
	{"d3e037e1-3eb8-44c8-a917-57927947596d", "Block scripts from launching downloads", "Enabled"},
	{"3b576869-a4ec-4529-8536-b80a7769e899", "Block Office from creating programs", "Enabled"},
	{"75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84", "Block Office from injecting into other programs", "Enabled"},
	{"26190899-1602-49e8-8b27-eb1d0a1ce869", "Block Outlook from starting programs", "Enabled"},
	{"d1e49aac-8f56-4280-b9ba-993a6d77406c", "Block remote program launches (PsExec / WMI)", "Warn"},
	{"33ddedf1-c6e0-47cb-833e-de6133960387", "Block forced restarts into Safe Mode", "Enabled"},
	{"b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4", "Block unsigned programs from USB drives", "Enabled"},
	{"c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb", "Block copied or renamed system tools", "Enabled"},
	{"92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b", "Block Office macros from calling Windows directly", "Enabled"},
	{"c1db55ab-c21a-4637-bb3f-a12568109d35", "Advanced ransomware protection", "Enabled"},
}

// ---------------------------------------------------------------- bloatware

type bloatRule struct {
	match  string // prefix of package family / program name (lower case)
	name   string
	rating string
	why    string
}

var winBloat = []bloatRule{
	{"microsoft.bingnews", "Microsoft News", "remove", "News feed app. The Edge news page covers it"},
	{"microsoft.bingweather", "Weather", "optional", "Keep it if you use it"},
	{"microsoft.bingsearch", "Bing Search", "remove", "Adds Bing web results to Start menu search"},
	{"microsoft.getstarted", "Tips", "remove", "Windows tips and ads"},
	{"microsoft.gethelp", "Get Help", "optional", "Microsoft support chat"},
	{"microsoft.microsoftsolitairecollection", "Solitaire Collection", "remove", "Game with ads and a paid subscription"},
	{"microsoft.microsoftofficehub", "Microsoft 365 (Office hub)", "remove", "Advert for Office subscriptions; your installed Office apps are not affected"},
	{"microsoft.skypeapp", "Skype", "remove", "Skype is retired"},
	{"microsoft.windowsfeedbackhub", "Feedback Hub", "remove", "Only needed to send feedback to Microsoft"},
	{"microsoft.mixedreality.portal", "Mixed Reality Portal", "remove", "Only for VR headsets"},
	{"microsoft.microsoft3dviewer", "3D Viewer", "remove", "Rarely used"},
	{"microsoft.3dbuilder", "3D Builder", "remove", "Rarely used"},
	{"microsoft.print3d", "Print 3D", "remove", "Rarely used"},
	{"microsoft.mspaint", "Paint 3D", "optional", "Classic Paint is separate and stays"},
	{"microsoft.oneconnect", "Mobile Plans", "remove", "Mobile data offers"},
	{"microsoft.messaging", "Messaging", "remove", "Old SMS relay app"},
	{"microsoft.people", "People", "optional", "Contacts app"},
	{"microsoft.windowsmaps", "Maps", "optional", "Offline maps"},
	{"microsoft.yourphone", "Phone Link", "optional", "Keep it if you connect your phone"},
	{"microsoft.zunemusic", "Media Player / Groove", "optional", "Music player"},
	{"microsoft.zunevideo", "Movies & TV", "optional", "Video store and player"},
	{"microsoft.todos", "Microsoft To Do", "optional", "Task lists"},
	{"microsoft.powerautomatedesktop", "Power Automate", "optional", "Automation tool for advanced users"},
	{"microsoftcorporationii.quickassist", "Quick Assist", "optional", "Remote help tool. Scammers often ask people to open it; remove it if you never use it"},
	{"microsoft.549981c3f5f10", "Cortana", "remove", "Retired assistant"},
	{"microsoft.windowscommunicationsapps", "Mail and Calendar", "optional", "Replaced by the new Outlook"},
	{"microsoft.outlookforwindows", "Outlook (new)", "optional", "Keep it if you read email here"},
	{"microsoft.copilot", "Copilot", "optional", "AI assistant"},
	{"msteams", "Microsoft Teams (personal)", "optional", "Chat app; the work version is separate"},
	{"microsoftteams", "Microsoft Teams (personal)", "optional", "Chat app; the work version is separate"},
	{"clipchamp.clipchamp", "Clipchamp", "optional", "Video editor"},
	{"microsoft.gamingapp", "Xbox app", "optional", "Needed for PC Game Pass"},
	{"microsoft.xboxgamingoverlay", "Xbox Game Bar", "optional", "Game overlay and screen recording"},
	{"microsoft.xboxapp", "Xbox Console Companion", "remove", "Retired"},
	{"microsoft.windows.devhome", "Dev Home", "remove", "Retired developer dashboard"},
	{"microsoft.bingfinance", "Money", "remove", "Retired"},
	{"microsoft.bingsports", "Sports", "remove", "Retired"},
	{"microsoft.office.onenote", "OneNote for Windows 10", "optional", "Older OneNote app"},
	{"microsoft.wallet", "Wallet", "remove", "Retired"},
	{"king.com.", "Candy Crush / King games", "remove", "Pre-installed game with ads and in-app purchases"},
	{"spotifyab.spotifymusic", "Spotify", "optional", "Pre-installed. Keep it if you use it"},
	{"disney.", "Disney+", "optional", "Pre-installed streaming app"},
	{"amazonvideo.primevideo", "Prime Video", "optional", "Pre-installed streaming app"},
	{"facebook.", "Facebook / Instagram", "optional", "Pre-installed social app"},
	{"bytedancepte.tiktok", "TikTok", "optional", "Pre-installed social app"},
	{"7eae6f10.linkedinforwindows", "LinkedIn", "remove", "Pre-installed; the website does the same"},
	{"e046963f.lenovocompanion", "Lenovo Vantage", "keep", "Lenovo drivers, BIOS and battery settings"},
	{"dellinc.dellsupportassist", "Dell SupportAssist", "keep", "Dell driver and BIOS updates"},
	{"ad2f1837.hpjumpstarts", "HP JumpStart", "remove", "HP welcome screens"},
	{"ad2f1837.myhp", "myHP", "optional", "HP support and settings"},
	{"acerincorporated.", "Acer extras", "optional", "Acer utilities"},
	{"b9ecab1e.", "Asus extras", "optional", "Asus utilities"},
	// classic programs (matched against the Add/Remove Programs name)
	{"mcafee", "McAfee", "remove", "Trial antivirus. Windows Defender already protects you, and two antivirus programs slow the PC"},
	{"norton", "Norton", "optional", "Paid antivirus. Remove it if the trial has ended; Defender takes over"},
	{"wildtangent", "WildTangent Games", "remove", "Pre-installed games with ads"},
	{"booking.com", "Booking.com", "remove", "Pre-installed shortcut"},
	{"dropbox promotion", "Dropbox offer", "remove", "Advert"},
	{"winzip", "WinZip", "optional", "Paid trial. Windows opens .zip files by itself"},
	{"expressvpn", "ExpressVPN", "optional", "Paid VPN trial"},
	{"avast secure browser", "Avast Secure Browser", "remove", "Bundled browser"},
	{"avg secure browser", "AVG Secure Browser", "remove", "Bundled browser"},
	{"ccleaner", "CCleaner", "optional", "Its free version shows ads and was once hacked to spread malware"},
	{"driver booster", "Driver Booster", "remove", "Driver updaters can install wrong drivers; use Windows Update"},
	{"driver easy", "Driver Easy", "remove", "Driver updaters can install wrong drivers; use Windows Update"},
	{"driverpack", "DriverPack", "remove", "Installs bundled extra software"},
	{"pc app store", "PC App Store", "remove", "Adware"},
	{"web companion", "Web Companion", "remove", "Changes your browser settings (adware)"},
	{"wave browser", "Wave Browser", "remove", "Browser hijacker"},
	{"onelaunch", "OneLaunch", "remove", "Adware launcher"},
	{"shift browser", "Shift Browser", "remove", "Bundled browser that changes your settings"},
	{"segurazo", "Segurazo / SAntivirus", "remove", "Fake antivirus that is hard to remove"},
	{"reimage", "Reimage Repair", "remove", "Scareware that asks you to pay to fix problems"},
	{"restoro", "Restoro", "remove", "Scareware that asks you to pay to fix problems"},
	{"pc cleaner", "PC Cleaner", "remove", "Scareware"},
	{"mypc utilities", "MyPC Utilities", "remove", "Scareware"},
	{"advanced systemcare", "Advanced SystemCare", "optional", "Bundles extra software and ads"},
	{"iobit", "IObit tools", "optional", "Bundles extra software and ads"},
	{"baidu", "Baidu software", "remove", "Bundled software that changes settings"},
	{"360 total security", "360 Total Security", "optional", "Second antivirus; slows the PC alongside Defender"},
}

func bloatOf(r *rawSec) []secBloat {
	out := []secBloat{}
	add := func(a rawApp, kind string) {
		hay := lc(a.ID)
		if kind == "program" {
			hay = lc(a.Name)
		}
		for _, b := range winBloat {
			if (kind == "store" && strings.HasPrefix(hay, b.match)) || (kind == "program" && strings.Contains(hay, b.match)) {
				action := "remove"
				if kind == "program" {
					action = "uninstall"
				}
				name := b.name
				if kind == "program" || name == "" {
					name = a.Name
				}
				out = append(out, secBloat{ID: fmt.Sprintf("b%d", len(out)+1), Name: name, Publisher: a.Publisher, Kind: kind, Rating: b.rating, Why: b.why, Size: a.Size, Action: action, On: true, Key: a.ID + "|" + a.Uninstall})
				return
			}
		}
	}
	for _, a := range r.Appx {
		if a.Removable {
			add(a, "store")
		}
	}
	for _, a := range r.Programs {
		add(a, "program")
	}
	// start-up apps (signed, harmless) are also offered to switch off for a faster boot
	for _, a := range r.Autoruns {
		if a.Kind != "run" && a.Kind != "startup" {
			continue
		}
		s, ok := r.sig(a.Target)
		if !ok || s.Status != "Valid" {
			continue
		}
		name := a.Name
		if fi := r.file(a.Target); fi.Desc != "" {
			name = fi.Desc
		}
		rating, why := "optional", "Starts with Windows and slows down start-up"
		n := lc(a.Name + " " + a.Target)
		for _, k := range []string{"securityhealth", "rtkaud", "realtek", "igfx", "nvidia", "amd", "synaptics", "elan", "bluetooth", "onedrive", "defender", "ctfmon", "dolby", "waves", "conexant"} {
			if strings.Contains(n, k) {
				rating, why = "keep", "Part of Windows, your drivers or sync. Keep it"
			}
		}
		for _, k := range []string{"spotify", "discord", "steam", "epicgames", "teams", "skype", "zoom", "adobe", "ccleaner", "itunes", "utorrent", "bittorrent", "opera", "edgeupdate", "googleupdate", "cortana", "acrobat"} {
			if strings.Contains(n, k) {
				rating, why = "optional", "Doesn't need to start with Windows. It still opens when you click it"
			}
		}
		out = append(out, secBloat{ID: fmt.Sprintf("b%d", len(out)+1), Name: name, Publisher: s.Signer, Kind: "startup", Rating: rating, Why: why, Action: "disable", On: !a.Off, Key: a.Key + "|" + a.Name})
	}
	sort.SliceStable(out, func(i, j int) bool { return rank(out[i].Rating) < rank(out[j].Rating) })
	return out
}

func rank(r string) int {
	switch r {
	case "remove":
		return 0
	case "optional":
		return 1
	}
	return 2
}

// ---------------------------------------------------------------- Live Shield (one new process at a time)

// shieldEvent is what the background watcher knows about a program the moment it starts.
type shieldEvent struct {
	Name       string
	Path       string
	Cmd        string
	Parent     string
	ParentPath string
	Signed     string // valid | unsigned | invalid | unknown
	Zone       int    // Mark of the Web zone, -1 none
	Intel      *secIntel
	Trusted    bool
}

// shieldQuick scores what is known without touching the disk (decides whether to freeze it).
func shieldQuick(ev shieldEvent) []secReason {
	var rs []secReason
	me, par := lc(ev.Name), lc(ev.Parent)
	if officeApps[par] && shellTools[me] {
		rs = append(rs, secReason{"Started by " + ev.Parent + " (documents should never start " + ev.Name + ")", 60})
	}
	if scriptHosts[par] && (me == "powershell.exe" || me == "cmd.exe" || me == "pwsh.exe") {
		rs = append(rs, secReason{"Started by the script host " + ev.Parent, 30})
	}
	if _, isSys := sysNames[me]; isSys && ev.Path != "" && !expectedSysPath(ev.Name, ev.Path) {
		rs = append(rs, secReason{"Uses the name of a Windows program (" + ev.Name + ") but runs from the wrong folder", 70})
	} else if real := lookalike(ev.Name); real != "" && !legitNames[me] && !sysDir(ev.Path) {
		rs = append(rs, secReason{"Name imitates the Windows program " + real, 35})
	}
	if doubleExt(ev.Path) {
		rs = append(rs, secReason{"Disguised with a double extension (" + winBase(ev.Path) + ")", 60})
	}
	if uw, where := userWritable(ev.Path); uw && !isTool(me) {
		rs = append(rs, secReason{"Runs from " + where, 15})
	}
	cr, _, _ := cmdReasons(ev.Cmd)
	rs = append(rs, cr...)
	return rs
}

// shieldScore adds the slower facts (signature, origin, known malware) and returns the verdict:
// "block" (stop + quarantine), "warn" (let it run, tell the user) or "" (fine).
func shieldScore(ev shieldEvent) (int, []secReason, string) {
	if ev.Trusted {
		return 0, nil, ""
	}
	rs := shieldQuick(ev)
	me := lc(ev.Name)
	uw, where := userWritable(ev.Path)
	switch ev.Signed {
	case "unsigned":
		if uw {
			rs = append(rs, secReason{"Unsigned program running from " + where, 25})
		}
	case "invalid":
		rs = append(rs, secReason{"Its digital signature is broken or forged", 55})
	case "valid":
		if !isTool(me) {
			rs = append(rs, secReason{"Digitally signed", -25})
		}
	}
	if ev.Zone >= 3 && ev.Signed != "valid" {
		rs = append(rs, secReason{"Came from the internet", 10})
	}
	if ev.Intel != nil && ev.Intel.Verdict == "malicious" {
		fam := ev.Intel.Family
		if fam == "" {
			fam = "a known malware sample"
		}
		rs = append(rs, secReason{"Known malware: " + fam + " (" + ev.Intel.Source + ")", 100})
	}
	rs = dedupeReasons(rs)
	s := total(rs)
	switch {
	case s >= 70:
		return s, rs, "block"
	case s >= 55:
		return s, rs, "warn"
	}
	return s, rs, ""
}

// appsOf lists every installed program and Store app for the "All apps" tab.
func appsOf(r *rawSec, bloat []secBloat) []secApp {
	rating := map[string]string{}
	for _, b := range bloat {
		if b.Kind != "startup" {
			rating[lc(b.Name)] = b.Rating
			rating[lc(strings.SplitN(b.Key, "|", 2)[0])] = b.Rating
		}
	}
	out := []secApp{}
	for _, a := range r.Programs {
		d := int64(0)
		if t, err := time.Parse("20060102", a.Date); err == nil {
			d = t.Unix()
		}
		out = append(out, secApp{Name: a.Name, Publisher: a.Publisher, Kind: "program", Source: "Installed program", Version: a.Version, Size: a.Size, First: d,
			Rating: firstNonEmpty(rating[lc(a.Name)], rating[lc(a.ID)]), CanRemove: a.Uninstall != "", Enabled: true, Key: a.ID + "|" + a.Uninstall})
	}
	for _, a := range r.Appx {
		name := prettyAppx(a.Name)
		for _, b := range winBloat {
			if strings.HasPrefix(lc(a.ID), b.match) {
				name = b.name
				break
			}
		}
		out = append(out, secApp{Name: name, Pkg: a.ID, Publisher: a.Publisher, Kind: "store", Source: "Microsoft Store app", Version: a.Version,
			Rating: rating[lc(a.ID)], CanRemove: a.Removable, Enabled: true, Key: a.ID + "|" + a.Uninstall})
	}
	sort.SliceStable(out, func(i, j int) bool { return lc(out[i].Name) < lc(out[j].Name) })
	for i := range out {
		out[i].ID = fmt.Sprintf("p%d", i+1)
	}
	return out
}

func firstNonEmpty(a ...string) string {
	for _, x := range a {
		if x != "" {
			return x
		}
	}
	return ""
}

// prettyAppx turns a package name into words: Microsoft.WindowsCalculator -> Windows Calculator.
func prettyAppx(n string) string {
	if i := strings.LastIndex(n, "."); i >= 0 && i < len(n)-1 {
		n = n[i+1:]
	}
	var b strings.Builder
	rs := []rune(n)
	for i, r := range rs {
		if i > 0 && r >= 'A' && r <= 'Z' && ((rs[i-1] >= 'a' && rs[i-1] <= 'z') || (i+1 < len(rs) && rs[i+1] >= 'a' && rs[i+1] <= 'z' && rs[i-1] >= 'A' && rs[i-1] <= 'Z')) {
			b.WriteRune(' ')
		}
		b.WriteRune(r)
	}
	return strings.TrimSpace(b.String())
}
