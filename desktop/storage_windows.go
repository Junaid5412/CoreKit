//go:build windows

package main

// Windows side of Storage & Performance: drive usage, folder sizing, the junk CoreKit can safely
// clear, and the actions that clean or uninstall. Everything reads first and only deletes what the
// user selected.

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

//go:embed scripts/storage.ps1
var storagePS []byte

var (
	spGetLogicalDrives = kernel32.NewProc("GetLogicalDriveStringsW")
	spGetDriveType     = kernel32.NewProc("GetDriveTypeW")
	spGetDiskFree      = kernel32.NewProc("GetDiskFreeSpaceExW")
	spGetVolumeInfo    = kernel32.NewProc("GetVolumeInformationW")
	spEmptyRecycle     = shell32.NewProc("SHEmptyRecycleBinW")
)

var errStop = fmt.Errorf("stop")

// ---------------------------------------------------------------- folder sizing

func stDirSize(ctx context.Context, root string, deadline time.Time) int64 {
	var total int64
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if ctx.Err() != nil || time.Now().After(deadline) {
			return errStop
		}
		if d.IsDir() {
			return nil // WalkDir does not follow junctions/symlinks, so no double counting
		}
		if info, e := d.Info(); e == nil {
			total += info.Size()
		}
		return nil
	})
	return total
}

func fileSize(p string) int64 {
	if st, err := os.Stat(p); err == nil && !st.IsDir() {
		return st.Size()
	}
	return 0
}

// sizeMany measures several folders at once (disks like parallel reads), each with its own limit.
func sizeMany(ctx context.Context, paths []string, per time.Duration) []int64 {
	out := make([]int64, len(paths))
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	for i, p := range paths {
		if p == "" {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, p string) {
			defer wg.Done()
			defer func() { <-sem }()
			out[i] = stDirSize(ctx, p, time.Now().Add(per))
		}(i, p)
	}
	wg.Wait()
	return out
}

// childSizes lists the immediate children of a folder with their sizes, largest first. Folders
// are measured in parallel, each with its own time limit, so big drives are covered fully.
func childSizes(ctx context.Context, root string, per time.Duration) []stBig {
	ents, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	out := make([]stBig, len(ents))
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	for i, e := range ents {
		full := filepath.Join(root, e.Name())
		b := stBig{Path: full, Name: e.Name(), Kind: "file"}
		info, ierr := e.Info()
		if ierr == nil {
			b.Mod = info.ModTime().Unix()
		}
		if e.IsDir() {
			b.Kind = "folder"
			wg.Add(1)
			sem <- struct{}{}
			go func(i int, b stBig) {
				defer wg.Done()
				defer func() { <-sem }()
				b.Bytes = stDirSize(ctx, b.Path, time.Now().Add(per))
				out[i] = b
			}(i, b)
			continue
		}
		if ierr == nil {
			b.Bytes = info.Size()
		}
		out[i] = b
	}
	wg.Wait()
	res := out[:0]
	for _, b := range out {
		if b.Path != "" && b.Bytes > 0 {
			res = append(res, b)
		}
	}
	sort.SliceStable(res, func(i, j int) bool { return res[i].Bytes > res[j].Bytes })
	return res
}

// ---------------------------------------------------------------- drives

func listDrives() []stDrive {
	buf := make([]uint16, 512)
	n, _, _ := spGetLogicalDrives.Call(uintptr(len(buf)), uintptr(unsafe.Pointer(&buf[0])))
	if n == 0 {
		return nil
	}
	sysDrive := strings.ToUpper(os.Getenv("SystemDrive")) // "C:"
	var drives []stDrive
	for _, root := range strings.Split(strings.TrimRight(syscall.UTF16ToString(buf[:n]), "\x00"), "\x00") {
		if root == "" {
			continue
		}
		rp, _ := syscall.UTF16PtrFromString(root)
		t, _, _ := spGetDriveType.Call(uintptr(unsafe.Pointer(rp)))
		if t != 3 && t != 2 { // keep fixed (3) and removable (2); skip network/optical
			continue
		}
		var freeAvail, total, totalFree uint64
		if r, _, _ := spGetDiskFree.Call(uintptr(unsafe.Pointer(rp)), uintptr(unsafe.Pointer(&freeAvail)), uintptr(unsafe.Pointer(&total)), uintptr(unsafe.Pointer(&totalFree))); r == 0 || total == 0 {
			continue
		}
		label := make([]uint16, 261)
		spGetVolumeInfo.Call(uintptr(unsafe.Pointer(rp)), uintptr(unsafe.Pointer(&label[0])), 261, 0, 0, 0, 0, 0)
		name := strings.TrimRight(root, `\`)
		d := stDrive{
			Name:  name,
			Label: syscall.UTF16ToString(label),
			Total: int64(total),
			Free:  int64(totalFree),
			Used:  int64(total - totalFree),
			Kind:  "fixed",
		}
		if t == 2 {
			d.Kind = "removable"
		} else if strings.ToUpper(name) == sysDrive {
			d.Kind = "system"
		}
		drives = append(drives, d)
	}
	return drives
}

var partColors = []string{"#38bdf8", "#a78bfa", "#2dd4bf", "#fbbf24", "#f472b6", "#fb923c"}

// scanDrive measures every top-level item of a drive (in parallel), turns them into the
// "where did the space go" bar, and returns the big items for the list under it.
func scanDrive(ctx context.Context, d *stDrive) []stBig {
	kids := childSizes(ctx, d.Name+`\`, 40*time.Second)
	var parts []stPart
	var counted int64
	add := func(name, color string, bytes int64) {
		if bytes > 0 {
			parts = append(parts, stPart{Name: name, Bytes: bytes, Color: color})
			counted += bytes
		}
	}
	if d.Kind == "system" {
		var progs, win, users, data, sysf int64
		var rest []stBig
		for _, k := range kids {
			switch strings.ToLower(k.Name) {
			case "windows":
				win += k.Bytes
			case "program files", "program files (x86)":
				progs += k.Bytes
			case "users":
				users += k.Bytes
			case "programdata":
				data += k.Bytes
			default:
				if k.Kind == "file" {
					sysf += k.Bytes // pagefile, hiberfil, swapfile ...
				} else {
					rest = append(rest, k)
				}
			}
		}
		var restSum int64
		for _, k := range rest {
			restSum += k.Bytes
		}
		add("Programs", "#38bdf8", progs)
		add("Windows", "#a78bfa", win)
		add("Users & files", "#2dd4bf", users)
		add("App data", "#fbbf24", data)
		add("System files", "#f472b6", sysf)
		add("Other folders", "#fb923c", restSum)
	} else {
		for i, k := range kids {
			if i < 5 {
				add(k.Name, partColors[i%len(partColors)], k.Bytes)
			}
		}
		var more int64
		for i, k := range kids {
			if i >= 5 {
				more += k.Bytes
			}
		}
		add("Other", "#64748b", more)
	}
	if rest := d.Used - counted; rest > 0 {
		add("Not measured / protected", "#475569", rest)
	}
	if len(parts) == 0 {
		parts = []stPart{{Name: "Used", Bytes: d.Used, Color: "#38bdf8"}}
	}
	d.Parts = parts
	var big []stBig
	for _, k := range kids {
		if k.Bytes >= 50<<20 && len(big) < 30 {
			k.Drive = d.Name
			big = append(big, k)
		}
	}
	return big
}

// ---------------------------------------------------------------- cleanables

type cleanDef struct {
	id, name, desc, group string
	safe                  bool
	paths                 []string // folders whose contents are cleared (or a file to delete)
	whole                 bool     // delete the folder itself (not just its contents)
}

// expand turns wildcard patterns (browser profiles, GPU caches) into the folders that exist.
func expand(patterns ...string) []string {
	var out []string
	for _, p := range patterns {
		if p == "" {
			continue
		}
		if strings.ContainsAny(p, "*?[") {
			m, _ := filepath.Glob(p)
			out = append(out, m...)
		} else {
			out = append(out, p)
		}
	}
	return out
}

// cache folders every Chromium-based program keeps inside a profile; all are rebuilt on demand
var chromiumCacheDirs = []string{"Cache", "Code Cache", "GPUCache", "DawnCache", "DawnGraphiteCache", "DawnWebGPUCache", "GraphiteDawnCache", `Service Worker\CacheStorage`, `Service Worker\ScriptCache`}

// and the ones beside the profiles
var chromiumRootCaches = []string{"ShaderCache", "GrShaderCache", "GraphiteDawnCache", "BrowserMetrics", "component_crx_cache", `Crashpad\reports`}

// cachesIn lists the cache folders that exist under each base folder.
func cachesIn(names []string, bases ...string) []string {
	var out []string
	for _, b := range bases {
		for _, n := range names {
			if p := filepath.Join(b, n); dirExists(p) {
				out = append(out, p)
			}
		}
	}
	return out
}

// corekitCaches are the caches of CoreKit's own Safe Browser profiles (its biggest data by far).
// When cleaning, profiles that are open right now are left alone.
func corekitCaches(skipOpen bool) []string {
	var out []string
	users := expand(filepath.Join(dataDir(), "Profiles", "*"))
	users = append(users, filepath.Join(dataDir(), "Launcher"))
	for _, u := range users {
		eb := filepath.Join(u, "EBWebView")
		if !dirExists(eb) || (skipOpen && profileRunning(eb)) {
			continue
		}
		out = append(out, cachesIn(chromiumRootCaches, eb)...)
		out = append(out, cachesIn(chromiumCacheDirs, expand(filepath.Join(eb, "*"))...)...)
	}
	return out
}

// oldPackages returns all but the newest update package in each Squirrel "packages" folder.
func oldPackages(local string) []string {
	var out []string
	for _, dir := range expand(filepath.Join(local, "*", "packages")) {
		pk := expand(filepath.Join(dir, "*.nupkg"))
		if len(pk) < 2 {
			continue
		}
		sort.Slice(pk, func(i, j int) bool {
			a, _ := os.Stat(pk[i])
			b, _ := os.Stat(pk[j])
			return a != nil && b != nil && a.ModTime().After(b.ModTime())
		})
		out = append(out, pk[1:]...)
	}
	return out
}

// sysFileSize reads the size of a file Windows keeps locked (hiberfil.sys): first directly, then
// from the folder listing, which works even when the file itself cannot be opened.
func sysFileSize(p string) int64 {
	if n := fileSize(p); n > 0 {
		return n
	}
	ents, err := os.ReadDir(filepath.Dir(p))
	if err != nil {
		return 0
	}
	for _, e := range ents {
		if strings.EqualFold(e.Name(), filepath.Base(p)) {
			if info, err := e.Info(); err == nil {
				return info.Size()
			}
		}
	}
	return 0
}

func hiberPath() string { return os.Getenv("SystemDrive") + `\hiberfil.sys` }

// cleanDefs lists everything CoreKit knows how to clear. forClean is true when the list is used
// to delete (rather than measure): CoreKit's own open browser profiles are then skipped.
func cleanDefs(forClean bool) []cleanDef {
	local := os.Getenv("LOCALAPPDATA")
	roam := os.Getenv("APPDATA")
	pdata := os.Getenv("ProgramData")
	home := os.Getenv("USERPROFILE")
	sd := os.Getenv("SystemDrive") + `\`
	win := filepath.Join(sd, "Windows")
	j := filepath.Join
	chromium := func(vendor string) []string {
		ud := j(local, vendor, "User Data")
		return append(cachesIn(chromiumRootCaches, ud), cachesIn(chromiumCacheDirs, expand(j(ud, "*"))...)...)
	}
	defs := []cleanDef{
		// browsers
		{id: "chrome", group: "Browsers", name: "Chrome cache", desc: "Chrome's temporary web files, every profile.", safe: true, paths: chromium(j("Google", "Chrome"))},
		{id: "edge", group: "Browsers", name: "Edge cache", desc: "Edge's temporary web files, every profile.", safe: true, paths: chromium(j("Microsoft", "Edge"))},
		{id: "brave", group: "Browsers", name: "Brave cache", desc: "Brave's temporary web files, every profile.", safe: true, paths: chromium(j("BraveSoftware", "Brave-Browser"))},
		{id: "firefox", group: "Browsers", name: "Firefox cache", desc: "Firefox's temporary web files, every profile.", safe: true, paths: expand(j(local, "Mozilla", "Firefox", "Profiles", "*", "cache2"))},
		{id: "corekit", group: "Browsers", name: "CoreKit Safe Browser cache", desc: "Temporary web files of your Safe Browser profiles. Logins, bookmarks and settings stay.", safe: true, paths: corekitCaches(forClean)},
		// Windows
		{id: "temp-user", group: "Windows", name: "Temporary files", desc: "Leftover files in your temp folders.", safe: true, paths: []string{os.Getenv("TEMP"), j(win, "Temp")}},
		{id: "update", group: "Windows", name: "Windows Update cache", desc: "Installer files Windows keeps after updating.", safe: true, paths: []string{j(win, "SoftwareDistribution", "Download")}},
		{id: "delivery", group: "Windows", name: "Delivery Optimization", desc: "Update pieces shared with other PCs.", safe: true, paths: []string{j(win, "SoftwareDistribution", "DeliveryOptimization")}},
		{id: "prefetch", group: "Windows", name: "Prefetch", desc: "Startup hints Windows rebuilds automatically.", safe: true, paths: []string{j(win, "Prefetch")}},
		{id: "thumbs", group: "Windows", name: "Thumbnail cache", desc: "Preview images Windows rebuilds when needed.", safe: true, paths: []string{j(local, "Microsoft", "Windows", "Explorer")}},
		{id: "inetcache", group: "Windows", name: "Windows web cache", desc: "Temporary web files kept by Windows and older apps.", safe: true, paths: []string{j(local, "Microsoft", "Windows", "INetCache")}},
		{id: "storeapps", group: "Windows", name: "Store app temporary files", desc: "Temporary files of Microsoft Store apps.", safe: true, paths: expand(j(local, "Packages", "*", "AC", "INetCache"), j(local, "Packages", "*", "AC", "Temp"), j(local, "Packages", "*", "TempState"))},
		{id: "wer", group: "Windows", name: "Error reports", desc: "Saved crash reports.", safe: true, paths: []string{j(local, "Microsoft", "Windows", "WER"), j(pdata, "Microsoft", "Windows", "WER")}},
		{id: "dumps", group: "Windows", name: "Crash dumps", desc: "Memory dumps from crashes.", safe: true, paths: []string{j(local, "CrashDumps"), j(win, "Minidump"), j(win, "LiveKernelReports"), j(win, "MEMORY.DMP")}},
		{id: "winlogs", group: "Windows", name: "Windows logs", desc: "Setup and servicing logs.", safe: true, paths: []string{j(win, "Logs", "CBS"), j(win, "Logs", "DISM")}},
		{id: "recyclebin", group: "Windows", name: "Recycle Bin", desc: "Files you already deleted.", safe: true},
		// apps & developer tools
		{id: "gpu", group: "Apps", name: "Graphics shader caches", desc: "DirectX, NVIDIA and AMD caches; games rebuild them.", safe: true, paths: expand(j(local, "D3DSCache"), j(local, "NVIDIA", "DXCache"), j(local, "NVIDIA", "GLCache"), j(local, "AMD", "DxCache"), j(local, "AMD", "GLCache"))},
		{id: "spotify", group: "Apps", name: "Spotify cache", desc: "Songs saved for offline playback; they download again when needed.", safe: true, paths: expand(j(local, "Spotify", "Storage"), j(local, "Spotify", "Data"))},
		{id: "appupd", group: "Apps", name: "Old app update files", desc: "Installers that apps downloaded to update themselves and no longer need.", safe: true, paths: append(expand(j(local, "*-updater"), j(local, "SquirrelTemp")), oldPackages(local)...)},
		{id: "devcache", group: "Apps", name: "Developer caches", desc: "npm, Yarn, pip, NuGet, Go and Electron download caches.", safe: true, paths: expand(j(local, "npm-cache"), j(roam, "npm-cache"), j(local, "Yarn", "Cache"), j(local, "pip", "Cache"), j(local, "NuGet", "v3-cache"), j(local, "NuGet", "http-cache"), j(local, "go-build"), j(local, "electron", "Cache"), j(local, "electron-builder", "Cache"), j(local, "Microsoft", "TypeScript"), j(home, ".cache", "electron"))},
	}
	// every other program built on Chromium or WebView2 (chat apps, editors, launchers ...)
	claimed := map[string]bool{}
	for _, d := range defs {
		for _, p := range d.paths {
			claimed[strings.ToLower(p)] = true
		}
	}
	var appCaches []string
	bases := expand(j(roam, "*"), j(roam, "*", "*"), j(local, "*", "EBWebView", "*"), j(local, "*", "*", "EBWebView", "*"), j(local, "*", "User Data", "*"), j(local, "*", "*", "User Data", "*"))
	for _, p := range append(cachesIn(chromiumCacheDirs, bases...), cachesIn(chromiumRootCaches, expand(j(local, "*", "EBWebView"), j(local, "*", "*", "EBWebView"), j(local, "*", "User Data"), j(local, "*", "*", "User Data"))...)...) {
		if !claimed[strings.ToLower(p)] && !under(p, appDataRoot()) {
			claimed[strings.ToLower(p)] = true
			appCaches = append(appCaches, p)
		}
	}
	appCaches = append(appCaches, expand(j(roam, "Code", "CachedData"), j(roam, "Code", "CachedExtensionVSIXs"))...)
	defs = append(defs, cleanDef{id: "appcache", group: "Apps", name: "App caches", desc: "Temporary files of chat apps, editors, launchers and other apps. They rebuild them when needed.", safe: true, paths: appCaches})

	if sysFileSize(hiberPath()) > 0 {
		defs = append(defs, cleanDef{id: "hibernation", group: "Windows", name: "Hibernation file", desc: "Turns off Hibernate and Fast Startup and removes hiberfil.sys. You can turn it back on later.", safe: false, paths: []string{hiberPath()}})
	}
	if wo := sd + "Windows.old"; dirExists(wo) {
		defs = append(defs, cleanDef{id: "windowsold", group: "Windows", name: "Previous Windows (Windows.old)", desc: "Your old Windows kept after an upgrade. Removing it means you can't roll back.", safe: false, paths: []string{wo}, whole: true})
	}
	var setup []string
	for _, n := range []string{`$Windows.~BT`, `$Windows.~WS`} {
		if dirExists(sd + n) {
			setup = append(setup, sd+n)
		}
	}
	if len(setup) > 0 {
		defs = append(defs, cleanDef{id: "winsetup", group: "Windows", name: "Windows upgrade leftovers", desc: "Files from a Windows upgrade that was downloaded or started.", safe: false, paths: setup, whole: true})
	}
	return defs
}

func dirExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}

func recycleSize(ctx context.Context, drives []stDrive) int64 {
	var paths []string
	for _, d := range drives {
		if d.Kind != "removable" {
			paths = append(paths, filepath.Join(d.Name+`\`, "$Recycle.Bin"))
		}
	}
	var total int64
	for _, n := range sizeMany(ctx, paths, 10*time.Second) {
		total += n
	}
	return total
}

func downloadsDir() string { return filepath.Join(os.Getenv("USERPROFILE"), "Downloads") }

// ---------------------------------------------------------------- the scan

func storageScan(ctx context.Context, progress func(int, string)) (*stResult, error) {
	start := time.Now()
	res := &stResult{Platform: "windows"}

	progress(4, "Reading drives")
	res.Drives = listDrives()

	progress(10, "Listing installed programs")
	raw, err := runPS(ctx, storagePS, nil, func(_, _, _ string) {})
	var pr struct {
		Apps []struct {
			ID, Name, Pub, Ver, Loc, Uninstall, Source, Kind, Family string
			Size, Installed                                          int64
			Quiet, NonRemovable, System                              bool
		} `json:"apps"`
		HiberOn bool   `json:"hiberOn"`
		OsDrive string `json:"osDrive"`
	}
	if err == nil {
		_ = json.Unmarshal(raw, &pr)
	}
	sysDrive := strings.ToUpper(os.Getenv("SystemDrive"))
	for _, a := range pr.Apps {
		drive := driveOf(a.Loc)
		if drive == "" {
			if exe, _ := parseCommand(a.Uninstall); exe != "" {
				drive = driveOf(exe)
			}
		}
		if drive == "" {
			drive = sysDrive
		}
		bloat, why := isWinBloat(a.Name, a.Pub)
		var removable, system bool
		switch a.Source {
		case "store":
			removable = !a.NonRemovable
			system = a.System || a.NonRemovable
		default:
			system = a.System
			removable = !a.System && a.Uninstall != ""
		}
		res.Apps = append(res.Apps, stApp{
			ID: a.ID, Name: a.Name, Pub: a.Pub, Ver: a.Ver, Size: a.Size, Installed: a.Installed,
			Loc: a.Loc, Drive: drive, Source: a.Source, Kind: a.Kind, Removable: removable, System: system,
			Bloat: bloat && !system, BloatWhy: why, Uninstall: a.Uninstall, Quiet: a.Quiet, Family: a.Family,
		})
	}

	// many programs record no size; measure their folder so the list is complete
	progress(24, "Measuring program sizes")
	{
		var idx []int
		var paths []string
		pf := []string{strings.ToLower(os.Getenv("ProgramFiles")), strings.ToLower(os.Getenv("ProgramFiles(x86)")), strings.ToLower(os.Getenv("SystemRoot"))}
		for i, a := range res.Apps {
			if a.Size > 0 || a.Loc == "" || !dirExists(a.Loc) || filepath.Dir(a.Loc) == a.Loc {
				continue
			}
			l := strings.ToLower(strings.TrimRight(a.Loc, `\`))
			if l == pf[0] || l == pf[1] || l == pf[2] {
				continue
			}
			idx = append(idx, i)
			paths = append(paths, a.Loc)
		}
		for k, n := range sizeMany(ctx, paths, 6*time.Second) {
			res.Apps[idx[k]].Size = n
		}
	}

	progress(38, "Measuring reclaimable space")
	for _, def := range cleanDefs(false) {
		c := stClean{ID: def.id, Name: def.name, Desc: def.desc, Safe: def.safe, Group: def.group}
		switch def.id {
		case "recyclebin":
			c.Bytes = recycleSize(ctx, res.Drives)
		case "hibernation":
			c.Bytes = sysFileSize(def.paths[0])
			c.Path = def.paths[0]
		default:
			var dirs []string
			for _, p := range def.paths {
				if p == "" {
					continue
				}
				if def.whole || dirExists(p) {
					dirs = append(dirs, p)
				} else {
					c.Bytes += fileSize(p) // a single file such as MEMORY.DMP
				}
			}
			for _, n := range sizeMany(ctx, dirs, 15*time.Second) {
				c.Bytes += n
			}
		}
		if c.Bytes > 0 {
			res.Clean = append(res.Clean, c)
		}
	}

	// the whole Downloads folder, so anything in it can be picked and deleted
	progress(52, "Checking the Downloads folder")
	if dl := downloadsDir(); dirExists(dl) {
		var bytes int64
		var n int
		_ = filepath.WalkDir(dl, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			if info, e := d.Info(); e == nil {
				bytes += info.Size()
				n++
			}
			return nil
		})
		if bytes > 0 {
			res.Clean = append(res.Clean, stClean{ID: "downloads", Group: "Your files", Name: "Downloads folder", Desc: fmt.Sprintf("%d files in your Downloads folder. Open it and choose what to delete.", n), Bytes: bytes, Count: n, Safe: false, Path: dl})
		}
	}

	// data that programs no longer on this PC left behind
	progress(56, "Looking for leftovers of removed programs")
	res.Clean = append(res.Clean, scanLeftovers(ctx, res.Apps, goneLoad(), time.Now().Unix())...)

	// every drive, fully measured
	var all []stBig
	for i := range res.Drives {
		if ctx.Err() != nil {
			break
		}
		progress(60+i*30/max(1, len(res.Drives)), "Measuring "+res.Drives[i].Name)
		all = append(all, scanDrive(ctx, &res.Drives[i])...)
	}
	res.Big = all

	progress(86, "Finding photos, videos and big files")
	var partial bool
	res.Files, res.Cats, partial = scanFiles(ctx, res.Drives, 75*time.Second)
	if partial {
		res.Note = "Some folders were too large to list fully."
	}

	progress(94, "Working out recommendations")
	finishStorage(res, time.Now().Unix())
	res.Ms = time.Since(start).Milliseconds()
	return res, nil
}

var reDrive = regexp.MustCompile(`^([A-Za-z]):`)

func driveOf(path string) string {
	if m := reDrive.FindStringSubmatch(strings.Trim(path, `" `)); m != nil {
		return strings.ToUpper(m[1]) + ":"
	}
	return ""
}

// ---------------------------------------------------------------- clean

func inUseNote(what string, left int64) string {
	return fmt.Sprintf("%s: %s is in use and was skipped. Close the app and try again.", what, fmtSize(left))
}

func storageClean(ctx context.Context, ids []string, pick map[string][]string, permanent bool) (int64, []string, error) {
	defsByID := map[string]cleanDef{}
	for _, d := range cleanDefs(true) {
		defsByID[d.id] = d
	}
	var freed int64
	var log []string
	var left []string
	for _, id := range ids {
		if ctx.Err() != nil {
			break
		}
		if strings.HasPrefix(id, "left:") {
			left = append(left, strings.TrimPrefix(id, "left:"))
			continue
		}
		switch id {
		case "recyclebin":
			f := recycleSize(ctx, listDrives())
			r, _, _ := spEmptyRecycle.Call(0, 0, 7) // NOCONFIRMATION|NOPROGRESSUI|NOSOUND
			if r == 0 /* S_OK */ {
				freed += f
				log = append(log, "Emptied the Recycle Bin ("+fmtSize(f)+")")
			} else {
				log = append(log, "Could not empty the Recycle Bin (it may already be empty)")
			}
		case "hibernation":
			before := sysFileSize(hiberPath())
			err := runHidden(ctx, filepath.Join(os.Getenv("SystemRoot"), "System32", "powercfg.exe"), "/hibernate", "off")
			if after := sysFileSize(hiberPath()); err == nil && after == 0 {
				freed += before
				log = append(log, "Turned off hibernation and removed the file ("+fmtSize(before)+")")
			} else if !isAdmin() {
				log = append(log, "Could not turn off hibernation: CoreKit must run as administrator")
			} else {
				log = append(log, "Windows did not turn off hibernation. A policy on this PC may be keeping it on")
			}
		case "windowsold":
			wo := os.Getenv("SystemDrive") + `\Windows.old`
			f := stDirSize(ctx, wo, time.Now().Add(10*time.Second))
			if removeWindowsOld(ctx, wo) {
				freed += f
				log = append(log, "Removed the previous Windows ("+fmtSize(f)+")")
			} else {
				log = append(log, "Could not fully remove Windows.old (administrator needed)")
			}
		case "downloads":
			n, b, failed := removeDownloads(ctx, pick["downloads"], permanent)
			freed += b
			log = append(log, fmt.Sprintf("%s %d item(s) from Downloads (%s)", deleteVerb(permanent), n, fmtSize(b)))
			if len(failed) > 0 {
				log = append(log, fmt.Sprintf("%d Downloads item(s) are in use and were skipped", len(failed)))
			}
		default:
			def, ok := defsByID[id]
			if !ok {
				continue
			}
			var cf, stuck int64
			for _, p := range def.paths {
				if p == "" {
					continue
				}
				if def.whole {
					f := stDirSize(ctx, p, time.Now().Add(20*time.Second))
					if removeWindowsOld(ctx, p) {
						cf += f
					}
				} else if dirExists(p) {
					f, l := clearContents(ctx, p)
					cf += f
					stuck += l
				} else if sz := fileSize(p); sz > 0 && os.Remove(p) == nil {
					cf += sz
				}
			}
			freed += cf
			log = append(log, "Cleared "+strings.ToLower(def.name)+" ("+fmtSize(cf)+")")
			if stuck > 1<<20 {
				log = append(log, inUseNote(def.name, stuck))
			}
		}
	}
	if len(left) > 0 {
		var ok []string
		for _, p := range left {
			if leftoverAllowed(p) {
				ok = append(ok, filepath.Clean(p))
			}
		}
		n, b, failed := deletePaths(ctx, ok, permanent)
		freed += b
		log = append(log, fmt.Sprintf("%s %d leftover folder(s) (%s)", deleteVerb(permanent), n, fmtSize(b)))
		for _, f := range failed {
			log = append(log, "Could not remove "+f+": something on this PC is still using it")
		}
		if skipped := len(left) - len(ok); skipped > 0 {
			log = append(log, fmt.Sprintf("Skipped %d leftover(s) that changed since the scan. Rescan and try again", skipped))
		}
	}
	if !permanent && (len(left) > 0 || len(pick["downloads"]) > 0) {
		log = append(log, "Items are in the Recycle Bin. Empty it to get the space back")
	}
	return freed, log, nil
}

func deleteVerb(permanent bool) string {
	if permanent {
		return "Deleted"
	}
	return "Moved to the Recycle Bin:"
}

// clearContents deletes what is inside a folder (keeping the folder). It returns the bytes that
// really went and the bytes that stayed because a program has them open.
func clearContents(ctx context.Context, root string) (freed, left int64) {
	ents, err := os.ReadDir(root)
	if err != nil {
		return 0, 0
	}
	for _, e := range ents {
		if ctx.Err() != nil {
			break
		}
		full := filepath.Join(root, e.Name())
		if e.IsDir() {
			before := stDirSize(ctx, full, time.Now().Add(5*time.Second))
			if os.RemoveAll(full) == nil {
				freed += before
				continue
			}
			after := stDirSize(ctx, full, time.Now().Add(5*time.Second))
			if after < before {
				freed += before - after
			}
			left += after
		} else {
			sz := fileSize(full)
			if os.Remove(full) == nil {
				freed += sz
			} else {
				left += sz
			}
		}
	}
	return
}

// removeDownloads removes the chosen files or folders, but only ones inside the Downloads folder.
func removeDownloads(ctx context.Context, paths []string, permanent bool) (int, int64, []string) {
	dl := filepath.Clean(downloadsDir())
	var ok []string
	for _, p := range paths {
		p = filepath.Clean(p)
		rel, err := filepath.Rel(dl, p)
		if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			continue
		}
		if _, err := os.Lstat(p); err == nil {
			ok = append(ok, p)
		}
	}
	return deletePaths(ctx, ok, permanent)
}

func removeWindowsOld(ctx context.Context, path string) bool {
	if os.RemoveAll(path) == nil && !dirExists(path) {
		return true
	}
	// protected system files: take ownership, then delete
	_ = runHidden(ctx, filepath.Join(os.Getenv("SystemRoot"), "System32", "takeown.exe"), "/f", path, "/r", "/d", "y")
	_ = runHidden(ctx, filepath.Join(os.Getenv("SystemRoot"), "System32", "icacls.exe"), path, "/grant", "administrators:F", "/t")
	_ = os.RemoveAll(path)
	return !dirExists(path)
}

func runHidden(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
	return cmd.Run()
}

// ---------------------------------------------------------------- uninstall

func storageUninstall(ctx context.Context, ids []string) []map[string]any {
	var out []map[string]any
	var asked []*stApp
	for _, id := range ids {
		storageDB.mu.Lock()
		a := storageDB.apps[id]
		storageDB.mu.Unlock()
		if a == nil {
			out = append(out, map[string]any{"id": id, "ok": false, "msg": "Please scan again: this list is out of date."})
			continue
		}
		ok, msg := uninstallOne(ctx, a)
		if ok {
			asked = append(asked, a) // the next scan looks for what it left behind
		}
		out = append(out, map[string]any{"id": id, "name": a.Name, "ok": ok, "msg": msg})
	}
	goneAdd(asked)
	return out
}

var reMsiGUID = regexp.MustCompile(`\{[0-9A-Fa-f-]{36}\}`)

func uninstallOne(ctx context.Context, a *stApp) (bool, string) {
	cctx, cancel := context.WithTimeout(ctx, 6*time.Minute)
	defer cancel()
	switch a.Kind {
	case "appx":
		if !a.Removable {
			return false, "Windows doesn't allow removing this built-in app."
		}
		pkg := a.ID
		ps := fmt.Sprintf("Remove-AppxPackage -Package %s -ErrorAction Stop", psQuote(pkg))
		if err := runHidden(cctx, filepath.Join(os.Getenv("SystemRoot"), `System32\WindowsPowerShell\v1.0\powershell.exe`), "-NoProfile", "-NonInteractive", "-Command", ps); err != nil {
			return false, "Windows could not remove it (it may be protected)."
		}
		return true, "Removed."
	case "msi":
		if m := reMsiGUID.FindString(a.Uninstall); m != "" {
			if err := runHidden(cctx, filepath.Join(os.Getenv("SystemRoot"), "System32", "msiexec.exe"), "/x", m, "/quiet", "/norestart"); err != nil {
				return false, "The uninstaller reported an error."
			}
			return true, "Uninstalled."
		}
		fallthrough
	default:
		if a.Uninstall == "" {
			return false, "No uninstaller was recorded for this program."
		}
		exe, args := parseCommand(a.Uninstall)
		if exe == "" {
			return false, "The uninstaller could not be run."
		}
		cmd := exec.CommandContext(cctx, exe, args...)
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
		if err := cmd.Run(); err != nil {
			if a.Quiet {
				return false, "The uninstaller reported an error."
			}
			return true, "The uninstaller was opened — follow its steps to finish."
		}
		return true, "Uninstalled."
	}
}

func psQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

// parseCommand splits a Windows command line into the program and its arguments.
func parseCommand(cmd string) (string, []string) {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return "", nil
	}
	var parts []string
	if cmd[0] == '"' {
		if end := strings.Index(cmd[1:], `"`); end >= 0 {
			parts = append(parts, cmd[1:1+end])
			rest := strings.Fields(cmd[2+end:])
			parts = append(parts, rest...)
			return parts[0], parts[1:]
		}
	}
	fields := strings.Fields(cmd)
	return fields[0], fields[1:]
}

// ---------------------------------------------------------------- drill (folder contents)

func storageDrill(ctx context.Context, path string) ([]stBig, error) {
	if path == "" || !dirExists(path) {
		return nil, fmt.Errorf("that folder is not available")
	}
	items := childSizes(ctx, path, 30*time.Second)
	if len(items) > 300 {
		items = items[:300]
	}
	for i := range items {
		items[i].Can = canDelete(items[i].Path)
	}
	return items, nil
}
