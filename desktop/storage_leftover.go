package main

// Leftovers: deciding whether a data folder still belongs to an installed program, and remembering
// what was uninstalled through CoreKit so the folders those programs left behind can be offered.
// The matching is deliberately cautious: when in doubt a folder is treated as still owned.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

var (
	// version numbers, bracketed notes and architecture words carry no identity
	reNameNoise = regexp.MustCompile(`(?i)\(.*?\)|\bv?\d+(\.\d+)+\b|\b(x64|x86|64-bit|32-bit|64bit|32bit|amd64|arm64)\b`)
	// company suffixes that would otherwise make publisher names never match
	reCorp = regexp.MustCompile(`(?i)\b(inc|llc|ltd|limited|corp|corporation|co|company|gmbh|pty|ag|bv|srl|technologies|technology|software|systems|team|the|developers|foundation|project|authors|contributors)\b\.?`)
	// endings a program adds to its own data folders ("lm-studio-updater", "Claude-Data")
	reFolderTail = regexp.MustCompile(`(?i)[-_. ]?(updater|update|setup|installer|data|cache|crashpad|crashes|crash|logs?|nightly|beta|insiders|dev|canary)$`)
)

// words too common to identify a program on their own
var genericWords = map[string]bool{
	"microsoft": true, "windows": true, "desktop": true, "update": true, "player": true, "studio": true,
	"driver": true, "drivers": true, "software": true, "system": true, "service": true, "services": true,
	"runtime": true, "tools": true, "client": true, "setup": true, "visual": true, "manager": true,
	"launcher": true, "helper": true, "support": true, "games": true, "media": true, "audio": true,
	"video": true, "control": true, "center": true, "utility": true, "utilities": true, "suite": true,
	"server": true, "browser": true, "application": true, "install": true, "installer": true,
}

// normName keeps letters and digits only, lower-cased.
func normName(s string) string {
	b := make([]byte, 0, len(s))
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b = append(b, byte(r))
		}
	}
	return string(b)
}

func cleanName(s string) string { return reNameNoise.ReplaceAllString(s, " ") }

// pathParts splits on both separators, so Windows paths work in tests on any system.
func pathParts(p string) []string {
	return strings.FieldsFunc(p, func(r rune) bool { return r == '\\' || r == '/' })
}

// folderKey is the identity of a data folder's name.
func folderKey(name string) string {
	t := name
	for i := 0; i < 2; i++ {
		t = reFolderTail.ReplaceAllString(t, "")
	}
	if k := normName(t); len(k) >= 3 {
		return k
	}
	return normName(name)
}

// installIndex is everything that proves a program is still on this PC.
type installIndex struct{ keys map[string]bool }

func newInstallIndex() *installIndex { return &installIndex{keys: map[string]bool{}} }

func (ix *installIndex) add(s string) {
	if k := normName(cleanName(s)); len(k) >= 3 {
		ix.keys[k] = true
	}
}

// containers whose names say nothing about which program lives inside
var genericDirs = map[string]bool{
	"programfiles": true, "programfilesx86": true, "programs": true, "users": true, "appdata": true,
	"local": true, "roaming": true, "locallow": true, "windowsapps": true, "commonfiles": true,
	"bin": true, "app": true, "apps": true, "games": true, "tools": true, "program": true, "software": true,
}

func (ix *installIndex) addApp(a *stApp) {
	ix.add(a.Name)
	ix.add(reCorp.ReplaceAllString(a.Pub, " "))
	if f := strings.Fields(cleanName(a.Name)); len(f) > 1 {
		if w := normName(f[0]); len(w) >= 5 && !genericWords[w] {
			ix.keys[w] = true
		}
	}
	if parts := pathParts(a.Loc); len(parts) >= 2 {
		for _, p := range parts[max(1, len(parts)-2):] {
			if k := normName(p); len(k) >= 3 && !genericDirs[k] {
				ix.keys[k] = true
			}
		}
	}
	for _, id := range []string{a.ID, a.Family} {
		for _, p := range strings.FieldsFunc(id, func(r rune) bool { return r == '.' || r == '_' }) {
			if k := normName(p); len(k) >= 5 && !genericWords[k] {
				ix.keys[k] = true
			}
		}
	}
}

// owns reports whether some installed program plausibly owns a folder with this name.
// Names it cannot judge (too short, or not in Latin letters) count as owned.
func (ix *installIndex) owns(folder string) bool {
	fn := folderKey(folder)
	if len(fn) < 3 {
		return true
	}
	for k := range ix.keys {
		if k == fn || strings.Contains(k, fn) || (len(k) >= 5 && strings.Contains(fn, k)) {
			return true
		}
	}
	return false
}

// belongsTo reports whether a folder name clearly belongs to this one program.
func belongsTo(folder string, a *stApp) bool {
	fn := folderKey(folder)
	if len(fn) < 4 {
		return false
	}
	names := []string{normName(cleanName(a.Name))}
	if parts := pathParts(a.Loc); len(parts) >= 2 {
		if k := normName(parts[len(parts)-1]); !genericDirs[k] {
			names = append(names, k)
		}
	}
	for _, n := range names {
		if len(n) < 4 {
			continue
		}
		if n == fn || (len(n) >= 5 && strings.Contains(fn, n)) || (len(fn) >= 5 && strings.HasPrefix(n, fn)) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------- programs uninstalled through CoreKit

type goneApp struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Pub  string `json:"pub,omitempty"`
	Loc  string `json:"loc,omitempty"`
	Kind string `json:"kind,omitempty"`
	At   int64  `json:"at"`
}

var goneMu sync.Mutex

func gonePath() string { return filepath.Join(appDataRoot(), "storage-uninstalled.json") }

// goneLoad returns the programs uninstalled through CoreKit in the last 30 days.
func goneLoad() []goneApp {
	goneMu.Lock()
	defer goneMu.Unlock()
	return goneRead()
}

func goneRead() []goneApp {
	var all, out []goneApp
	if b, err := os.ReadFile(gonePath()); err == nil {
		_ = json.Unmarshal(b, &all)
	}
	cut := time.Now().Add(-30 * 24 * time.Hour).Unix()
	for _, g := range all {
		if g.At >= cut && g.Name != "" {
			out = append(out, g)
		}
	}
	return out
}

// goneAdd remembers programs the user asked CoreKit to uninstall.
func goneAdd(apps []*stApp) {
	if len(apps) == 0 {
		return
	}
	goneMu.Lock()
	defer goneMu.Unlock()
	list := goneRead()
	have := map[string]int{}
	for i, g := range list {
		have[g.ID] = i
	}
	now := time.Now().Unix()
	for _, a := range apps {
		g := goneApp{ID: a.ID, Name: a.Name, Pub: a.Pub, Loc: a.Loc, Kind: a.Kind, At: now}
		if i, ok := have[a.ID]; ok {
			list[i] = g
		} else {
			list = append(list, g)
		}
	}
	if b, err := json.Marshal(list); err == nil {
		tmp := gonePath() + ".tmp"
		if os.WriteFile(tmp, b, 0o600) == nil {
			_ = os.Rename(tmp, gonePath())
		}
	}
}
