package main

// Storage & Performance module: where space is going, every installed program/app (with a
// bulk-select uninstall), bloatware, the reclaimable junk (caches, temp, Recycle Bin, the
// hibernation file, old Windows, Downloads clutter), and plain recommendations of what is safe to
// remove. The analyzer here is shared by Windows and Linux; Android builds the same shape itself.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------- data the UI receives

type stDrive struct {
	Name  string   `json:"name"`  // "C:" or "Internal storage"
	Label string   `json:"label"` // volume label
	Total int64    `json:"total"`
	Free  int64    `json:"free"`
	Used  int64    `json:"used"`
	Kind  string   `json:"kind"` // system | fixed | removable
	Parts []stPart `json:"parts"`
}

type stPart struct {
	Name  string `json:"name"`
	Bytes int64  `json:"bytes"`
	Color string `json:"color"`
}

type stApp struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Pub       string `json:"pub"`
	Ver       string `json:"ver"`
	Size      int64  `json:"size"`
	Installed int64  `json:"installed"`
	LastUsed  int64  `json:"lastUsed"`
	Loc       string `json:"loc"`
	Drive     string `json:"drive"`
	Source    string `json:"source"` // program | store | system | sideloaded | preinstalled
	Kind      string `json:"kind"`   // exe | msi | appx | apk
	System    bool   `json:"system"`
	Bloat     bool   `json:"bloat"`
	BloatWhy  string `json:"bloatWhy,omitempty"`
	Removable bool   `json:"removable"`
	Approx    bool   `json:"approx,omitempty"` // size is an estimate (no exact figure available)
	CodeB     int64  `json:"code,omitempty"`   // the app itself
	DataB     int64  `json:"data,omitempty"`   // its saved data (includes cache)
	CacheB    int64  `json:"cache,omitempty"`  // part of data that is only cache
	ExtB      int64  `json:"ext,omitempty"`    // game files / OBB / media kept outside the app (Android)
	Uninstall string `json:"-"`                // kept on the host only, never sent to the page
	Quiet     bool   `json:"-"`
	Family    string `json:"-"`
}

type stClean struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Desc  string `json:"desc"`
	Bytes int64  `json:"bytes"`
	Count int    `json:"count"`
	Safe  bool   `json:"safe"`
	Path  string `json:"path,omitempty"`
	Group string `json:"group,omitempty"` // Browsers | Windows | Apps | Your files
}

type stBig struct {
	Path  string `json:"path"`
	Name  string `json:"name"`
	Bytes int64  `json:"bytes"`
	Kind  string `json:"kind"` // folder | file | app
	Drive string `json:"drive,omitempty"`
	Mod   int64  `json:"mod,omitempty"` // last modified (unix seconds), 0 if unknown
}

type stRec struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	Why    string `json:"why"`
	Bytes  int64  `json:"bytes"`
	Kind   string `json:"kind"`   // app-unused | clean | download-old | big-file
	Target string `json:"target"` // app id / clean id / path
	Safe   bool   `json:"safe"`
}

// stFile is one file worth showing: a photo, video, song, document, archive or big file.
type stFile struct {
	ID    string `json:"id"` // what the delete route takes (a path on PC, a media id on Android)
	Path  string `json:"path"`
	Name  string `json:"name"`
	Dir   string `json:"dir"`
	Bytes int64  `json:"bytes"`
	Mod   int64  `json:"mod,omitempty"`
	Cat   string `json:"cat"` // photo | video | audio | doc | archive | other
}

// stCat is the total of one kind of file across the device.
type stCat struct {
	Cat   string `json:"cat"`
	Bytes int64  `json:"bytes"`
	Count int    `json:"count"`
}

// stDir is a folder and the files in it (Android: which folders hold the media).
type stDir struct {
	Path  string `json:"path"`
	Bytes int64  `json:"bytes"`
	Count int    `json:"count"`
}

type stResult struct {
	Platform string    `json:"platform"`
	Drives   []stDrive `json:"drives"`
	Apps     []stApp   `json:"apps"`
	Clean    []stClean `json:"clean"`
	Big      []stBig   `json:"big"`
	Recs     []stRec   `json:"recs"`
	Files    []stFile  `json:"files"`
	Cats     []stCat   `json:"cats"`
	Dirs     []stDir   `json:"dirs"`
	Total    int64     `json:"total"`
	Free     int64     `json:"free"`
	Used     int64     `json:"used"`
	Reclaim  int64     `json:"reclaim"` // junk + recommended, safely removable
	AppCount int       `json:"appCount"`
	Ms       int64     `json:"ms"`
	Note     string    `json:"note,omitempty"`
	Needs    []string  `json:"needs,omitempty"` // permissions the page should offer, e.g. "usage" (Android)
}

// ---------------------------------------------------------------- store (maps ids to actions)

type storageStore struct {
	mu   sync.Mutex
	last *stResult
	apps map[string]*stApp   // id -> app (for uninstall)
	cln  map[string]*stClean // id -> cleanable
	fls  map[string]*stFile  // id -> file (only files from the last scan can be deleted)
}

var storageDB = &storageStore{apps: map[string]*stApp{}, cln: map[string]*stClean{}, fls: map[string]*stFile{}}

func (s *storageStore) set(res *stResult) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.last = res
	s.apps = map[string]*stApp{}
	s.cln = map[string]*stClean{}
	s.fls = map[string]*stFile{}
	for i := range res.Files {
		s.fls[res.Files[i].ID] = &res.Files[i]
	}
	for i := range res.Apps {
		s.apps[res.Apps[i].ID] = &res.Apps[i]
	}
	for i := range res.Clean {
		s.cln[res.Clean[i].ID] = &res.Clean[i]
	}
}

// ---------------------------------------------------------------- recommendations (shared)

// finishStorage fills in the cross-cutting parts once a platform has collected drives, apps, the
// cleanables and the biggest folders: the "what's safe to remove" recommendations, the totals and
// the reclaimable figure. Kept deterministic and plain so the advice reads the same everywhere.
func finishStorage(res *stResult, now int64) {
	// totals across fixed drives
	for _, d := range res.Drives {
		if d.Kind != "removable" {
			res.Total += d.Total
			res.Free += d.Free
			res.Used += d.Used
		}
	}
	sort.SliceStable(res.Apps, func(i, j int) bool { return res.Apps[i].Size > res.Apps[j].Size })
	res.AppCount = len(res.Apps)
	sort.SliceStable(res.Clean, func(i, j int) bool { return res.Clean[i].Bytes > res.Clean[j].Bytes })
	sort.SliceStable(res.Big, func(i, j int) bool { return res.Big[i].Bytes > res.Big[j].Bytes })

	var reclaim int64
	// every safe cleanable is a recommendation
	for i := range res.Clean {
		c := &res.Clean[i]
		if c.Bytes <= 0 {
			continue
		}
		if c.Safe {
			reclaim += c.Bytes
			res.Recs = append(res.Recs, stRec{
				ID: "c-" + c.ID, Title: "Clear " + strings.ToLower(c.Name), Why: c.Desc,
				Bytes: c.Bytes, Kind: "clean", Target: c.ID, Safe: true,
			})
		}
	}
	// apps not opened in a long time (we know this on Android; on Windows LastUsed is usually 0)
	for i := range res.Apps {
		a := &res.Apps[i]
		if a.System || !a.Removable || a.LastUsed == 0 || a.Size < 30<<20 {
			continue
		}
		days := (now - a.LastUsed) / 86400
		if days >= 90 {
			res.Recs = append(res.Recs, stRec{
				ID: "a-" + a.ID, Title: "Uninstall " + a.Name, Bytes: a.Size, Kind: "app-unused", Target: a.ID,
				Why: fmt.Sprintf("Not opened in %d days and taking %s.", days, fmtSize(a.Size)),
			})
		}
	}
	// known bloatware is worth removing
	for i := range res.Apps {
		a := &res.Apps[i]
		if a.Bloat && a.Removable {
			res.Recs = append(res.Recs, stRec{
				ID: "b-" + a.ID, Title: "Remove " + a.Name, Bytes: a.Size, Kind: "app-unused", Target: a.ID,
				Why: a.BloatWhy,
			})
		}
	}
	// biggest files flagged for a look (not auto-safe)
	for _, b := range res.Big {
		if b.Kind == "file" && b.Bytes >= 1<<30 {
			res.Recs = append(res.Recs, stRec{
				ID: "f-" + b.Path, Title: "Review " + b.Name, Bytes: b.Bytes, Kind: "big-file", Target: b.Path,
				Why: "A single file using " + fmtSize(b.Bytes) + ". Delete it only if you know you don't need it.",
			})
		}
	}
	rank := map[string]int{"clean": 0, "app-unused": 1, "big-file": 2}
	sort.SliceStable(res.Recs, func(i, j int) bool {
		if rank[res.Recs[i].Kind] != rank[res.Recs[j].Kind] {
			return rank[res.Recs[i].Kind] < rank[res.Recs[j].Kind]
		}
		return res.Recs[i].Bytes > res.Recs[j].Bytes
	})
	if len(res.Recs) > 120 {
		res.Recs = res.Recs[:120]
	}
	res.Reclaim = reclaim
	if res.Clean == nil {
		res.Clean = []stClean{}
	}
	if res.Apps == nil {
		res.Apps = []stApp{}
	}
	if res.Big == nil {
		res.Big = []stBig{}
	}
	if res.Files == nil {
		res.Files = []stFile{}
	}
	if res.Cats == nil {
		res.Cats = []stCat{}
	}
	if res.Dirs == nil {
		res.Dirs = []stDir{}
	}
	if res.Recs == nil {
		res.Recs = []stRec{}
	}
}

// ---------------------------------------------------------------- bloatware list (shared helper)

// isWinBloat marks common pre-installed or nuisance Windows programs. Conservative on purpose.
func isWinBloat(name, pub string) (bool, string) {
	n := strings.ToLower(name)
	p := strings.ToLower(pub)
	for _, b := range []struct{ k, why string }{
		{"mcafee", "McAfee trial: a pre-installed antivirus trial that nags and slows boot."},
		{"norton", "Norton trial: a pre-installed antivirus trial that nags and slows boot."},
		{"candy crush", "A pre-installed game."},
		{"booking.com", "A pre-installed promotional app."},
		{"disney", "A pre-installed promotional app."},
		{"spotify", "Pre-installed by some makers; keep it only if you use it."},
		{"xbox", "Xbox extras: safe to remove if you don't game on this PC."},
		{"wps office", "Bundled trial office suite."},
		{"avast", "Bundled antivirus: remove if you didn't choose it."},
		{"avg ", "Bundled antivirus: remove if you didn't choose it."},
		{"driver booster", "A 'driver updater' that nags to buy; not needed."},
		{"driverpack", "A 'driver updater' that nags to buy; not needed."},
		{"pc app store", "A bundled app store, often unwanted."},
		{"wildtangent", "Bundled game promoter."},
		{"expressvpn", "Pre-installed promo; keep only if you use it."},
		{"onedrive", "Keep if you use it; remove if you don't."},
	} {
		if strings.Contains(n, b.k) {
			return true, b.why
		}
	}
	if strings.Contains(p, "mcafee") || strings.Contains(p, "wildtangent") {
		return true, "A pre-installed program from " + pub + "."
	}
	return false, ""
}

// ---------------------------------------------------------------- HTTP

func mountStorage(mux *http.ServeMux, base string, in *inspector) {
	mux.HandleFunc(base+"scan", in.storageScan)
	mux.HandleFunc(base+"clean", secPost(func(r *http.Request, b []byte) any {
		var q struct {
			IDs  []string            `json:"ids"`
			Pick map[string][]string `json:"pick"`
		}
		_ = json.Unmarshal(b, &q)
		if len(q.IDs) == 0 {
			return map[string]string{"error": "Nothing was selected."}
		}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
		defer cancel()
		freed, log, err := storageClean(ctx, q.IDs, q.Pick)
		if err != nil {
			return map[string]any{"error": err.Error(), "log": log}
		}
		return map[string]any{"freed": freed, "freedText": fmtSize(freed), "log": log}
	}))
	mux.HandleFunc(base+"uninstall", secPost(func(r *http.Request, b []byte) any {
		var q struct {
			IDs []string `json:"ids"`
		}
		_ = json.Unmarshal(b, &q)
		if len(q.IDs) == 0 {
			return map[string]string{"error": "Nothing was selected."}
		}
		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Minute)
		defer cancel()
		return map[string]any{"items": storageUninstall(ctx, q.IDs)}
	}))
	mux.HandleFunc(base+"delete", secPost(func(r *http.Request, b []byte) any {
		var q struct {
			IDs []string `json:"ids"`
		}
		_ = json.Unmarshal(b, &q)
		if len(q.IDs) == 0 {
			return map[string]string{"error": "Nothing was selected."}
		}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
		defer cancel()
		freed, n, log := storageDeleteFiles(ctx, q.IDs)
		return map[string]any{"freed": freed, "freedText": fmtSize(freed), "count": n, "log": log}
	}))
	mux.HandleFunc(base+"drill", secPost(func(r *http.Request, b []byte) any {
		var q struct {
			Path string `json:"path"`
		}
		_ = json.Unmarshal(b, &q)
		ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
		defer cancel()
		items, err := storageDrill(ctx, q.Path)
		if err != nil {
			return map[string]string{"error": err.Error()}
		}
		return map[string]any{"items": items, "path": q.Path}
	}))
}

func (in *inspector) storageScan(w http.ResponseWriter, r *http.Request) {
	s, cancel, ok := in.beginStream(w, r)
	if !ok {
		return
	}
	defer in.endStream()
	defer cancel()
	logLine("*", "Storage scan started")
	res, err := storageScan(s.ctx, func(p int, label string) { s.json("progress", map[string]any{"pct": p, "label": label}) })
	if err != nil {
		logLine("!", "Storage scan failed: "+err.Error())
		s.json("fail", map[string]string{"error": err.Error()})
		return
	}
	storageDB.set(res)
	logLine("#", fmt.Sprintf("Storage scan done: %d programs, %s reclaimable", res.AppCount, fmtSize(res.Reclaim)))
	var buf bytes.Buffer
	_ = json.NewEncoder(&buf).Encode(res)
	s.send("done", bytes.TrimSpace(buf.Bytes()))
}

// ---------------------------------------------------------------- file kinds (shared)

var extCat = func() map[string]string {
	m := map[string]string{}
	add := func(cat string, exts ...string) {
		for _, e := range exts {
			m[e] = cat
		}
	}
	add("video", ".mp4", ".mkv", ".avi", ".mov", ".wmv", ".flv", ".webm", ".m4v", ".3gp", ".mpg", ".mpeg", ".ts")
	add("photo", ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".heic", ".heif", ".webp", ".tif", ".tiff", ".raw", ".cr2", ".nef", ".dng", ".psd")
	add("audio", ".mp3", ".wav", ".flac", ".aac", ".m4a", ".ogg", ".wma", ".opus", ".amr")
	add("doc", ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".csv", ".odt", ".rtf", ".epub")
	add("archive", ".zip", ".rar", ".7z", ".iso", ".exe", ".msi", ".apk", ".xapk", ".apks", ".cab", ".tar", ".gz", ".obb", ".vhd", ".vhdx", ".img")
	return m
}()

func catOfName(name string) string {
	if c, ok := extCat[strings.ToLower(filepath.Ext(name))]; ok {
		return c
	}
	return "other"
}

// topFiles keeps the biggest files per kind so each kind is represented in the list.
type topFiles struct {
	per  int
	list map[string][]stFile
	cats map[string]*stCat
}

func newTopFiles(per int) *topFiles {
	return &topFiles{per: per, list: map[string][]stFile{}, cats: map[string]*stCat{}}
}

func (t *topFiles) add(f stFile) {
	c := t.cats[f.Cat]
	if c == nil {
		c = &stCat{Cat: f.Cat}
		t.cats[f.Cat] = c
	}
	c.Bytes += f.Bytes
	c.Count++
	if f.Bytes < 1<<20 {
		return
	}
	l := append(t.list[f.Cat], f)
	if len(l) > t.per*3 {
		sort.Slice(l, func(i, j int) bool { return l[i].Bytes > l[j].Bytes })
		l = l[:t.per]
	}
	t.list[f.Cat] = l
}

func (t *topFiles) merge(o *topFiles) {
	for k, c := range o.cats {
		d := t.cats[k]
		if d == nil {
			d = &stCat{Cat: k}
			t.cats[k] = d
		}
		d.Bytes += c.Bytes
		d.Count += c.Count
	}
	for k, l := range o.list {
		t.list[k] = append(t.list[k], l...)
	}
}

func (t *topFiles) result() ([]stFile, []stCat) {
	var files []stFile
	for _, l := range t.list {
		sort.Slice(l, func(i, j int) bool { return l[i].Bytes > l[j].Bytes })
		if len(l) > t.per {
			l = l[:t.per]
		}
		files = append(files, l...)
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Bytes > files[j].Bytes })
	var cats []stCat
	for _, c := range t.cats {
		cats = append(cats, *c)
	}
	sort.Slice(cats, func(i, j int) bool { return cats[i].Bytes > cats[j].Bytes })
	return files, cats
}
