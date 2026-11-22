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

func cleanDefs(hiberOn bool) []cleanDef {
	local := os.Getenv("LOCALAPPDATA")
	roam := os.Getenv("APPDATA")
	pdata := os.Getenv("ProgramData")
	sd := os.Getenv("SystemDrive") + `\`
	win := filepath.Join(sd, "Windows")
	j := filepath.Join
	chromium := func(vendor string) []string {
		ud := j(local, vendor, "User Data")
		return expand(j(ud, "*", "Cache"), j(ud, "*", "Code Cache"), j(ud, "*", "GPUCache"), j(ud, "ShaderCache"), j(ud, "GrShaderCache"))
	}
	defs := []cleanDef{
		// browsers
		{id: "chrome", group: "Browsers", name: "Chrome cache", desc: "Chrome's temporary web files, every profile.", safe: true, paths: chromium(j("Google", "Chrome"))},
		{id: "edge", group: "Browsers", name: "Edge cache", desc: "Edge's temporary web files, every profile.", safe: true, paths: chromium(j("Microsoft", "Edge"))},
		{id: "brave", group: "Browsers", name: "Brave cache", desc: "Brave's temporary web files, every profile.", safe: true, paths: chromium(j("BraveSoftware", "Brave-Browser"))},
		{id: "firefox", group: "Browsers", name: "Firefox cache", desc: "Firefox's temporary web files, every profile.", safe: true, paths: expand(j(local, "Mozilla", "Firefox", "Profiles", "*", "cache2"))},
		// Windows
		{id: "temp-user", group: "Windows", name: "Temporary files", desc: "Leftover files in your temp folders.", safe: true, paths: []string{os.Getenv("TEMP"), j(win, "Temp")}},
		{id: "update", group: "Windows", name: "Windows Update cache", desc: "Installer files Windows keeps after updating.", safe: true, paths: []string{j(win, "SoftwareDistribution", "Download")}},
		{id: "delivery", group: "Windows", name: "Delivery Optimization", desc: "Update pieces shared with other PCs.", safe: true, paths: []string{j(win, "SoftwareDistribution", "DeliveryOptimization")}},
		{id: "prefetch", group: "Windows", name: "Prefetch", desc: "Startup hints Windows rebuilds automatically.", safe: true, paths: []string{j(win, "Prefetch")}},
		{id: "thumbs", group: "Windows", name: "Thumbnail cache", desc: "Preview images Windows rebuilds when needed.", safe: true, paths: []string{j(local, "Microsoft", "Windows", "Explorer")}},
		{id: "wer", group: "Windows", name: "Error reports", desc: "Saved crash reports.", safe: true, paths: []string{j(local, "Microsoft", "Windows", "WER"), j(pdata, "Microsoft", "Windows", "WER")}},
		{id: "dumps", group: "Windows", name: "Crash dumps", desc: "Memory dumps from crashes.", safe: true, paths: []string{j(local, "CrashDumps"), j(win, "Minidump"), j(win, "LiveKernelReports"), j(win, "MEMORY.DMP")}},
		{id: "winlogs", group: "Windows", name: "Windows logs", desc: "Setup and servicing logs.", safe: true, paths: []string{j(win, "Logs", "CBS"), j(win, "Logs", "DISM")}},
		{id: "recyclebin", group: "Windows", name: "Recycle Bin", desc: "Files you already deleted.", safe: true},
		// apps & developer tools
		{id: "gpu", group: "Apps", name: "Graphics shader caches", desc: "DirectX, NVIDIA and AMD caches; games rebuild them.", safe: true, paths: expand(j(local, "D3DSCache"), j(local, "NVIDIA", "DXCache"), j(local, "NVIDIA", "GLCache"), j(local, "AMD", "DxCache"), j(local, "AMD", "GLCache"))},
		{id: "chat", group: "Apps", name: "Chat app caches", desc: "Discord, Slack and Teams temporary files.", safe: true, paths: expand(j(roam, "discord", "Cache"), j(roam, "discord", "Code Cache"), j(roam, "discord", "GPUCache"), j(roam, "Slack", "Cache"), j(roam, "Slack", "Code Cache"), j(roam, "Microsoft", "Teams", "Cache"), j(roam, "Microsoft", "Teams", "tmp"))},
		{id: "spotify", group: "Apps", name: "Spotify cache", desc: "Songs saved for offline playback; they download again when needed.", safe: true, paths: expand(j(local, "Spotify", "Storage"), j(local, "Spotify", "Data"))},
		{id: "devcache", group: "Apps", name: "Developer caches", desc: "npm, pip and NuGet download caches.", safe: true, paths: expand(j(local, "npm-cache"), j(local, "pip", "Cache"), j(local, "NuGet", "v3-cache"))},
	}
	if hiberFile := sd + "hiberfil.sys"; hiberOn && fileSize(hiberFile) > 0 {
		defs = append(defs, cleanDef{id: "hibernation", group: "Windows", name: "Hibernation file", desc: "Frees space by turning off hibernate (you can turn it back on).", safe: false, paths: []string{hiberFile}})
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
	for _, def := range cleanDefs(pr.HiberOn) {
		c := stClean{ID: def.id, Name: def.name, Desc: def.desc, Safe: def.safe, Group: def.group}
		switch def.id {
		case "recyclebin":
			c.Bytes = recycleSize(ctx, res.Drives)
		case "hibernation":
			c.Bytes = fileSize(def.paths[0])
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

func storageClean(ctx context.Context, ids []string, pick map[string][]string) (int64, []string, error) {
	hiberOn := false
	if st, err := os.Stat(os.Getenv("SystemDrive") + `\hiberfil.sys`); err == nil {
		hiberOn = st.Size() > 0
	}
	defsByID := map[string]cleanDef{}
	for _, d := range cleanDefs(hiberOn) {
		defsByID[d.id] = d
	}
	var freed int64
	var log []string
	for _, id := range ids {
		if ctx.Err() != nil {
			break
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
			before := fileSize(os.Getenv("SystemDrive") + `\hiberfil.sys`)
			if err := runHidden(ctx, filepath.Join(os.Getenv("SystemRoot"), "System32", "powercfg.exe"), "/hibernate", "off"); err != nil {
				log = append(log, "Could not turn off hibernation (CoreKit must run as administrator)")
			} else {
				freed += before
				log = append(log, "Turned off hibernation and removed the file ("+fmtSize(before)+")")
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
			n, b := removeDownloads(pick["downloads"])
			freed += b
			log = append(log, fmt.Sprintf("Deleted %d item(s) from Downloads (%s)", n, fmtSize(b)))
		default:
			def, ok := defsByID[id]
			if !ok {
				continue
			}
			var cf int64
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
					cf += clearContents(ctx, p)
				} else if sz := fileSize(p); sz > 0 && os.Remove(p) == nil {
					cf += sz
				}
			}
			freed += cf
			log = append(log, "Cleared "+strings.ToLower(def.name)+" ("+fmtSize(cf)+")")
		}
	}
	return freed, log, nil
}

// clearContents deletes the files inside a folder (keeping the folder), returning freed bytes.
func clearContents(ctx context.Context, root string) int64 {
	ents, err := os.ReadDir(root)
	if err != nil {
		return 0
	}
	var freed int64
	for _, e := range ents {
		if ctx.Err() != nil {
			break
		}
		full := filepath.Join(root, e.Name())
		if e.IsDir() {
			freed += stDirSize(ctx, full, time.Now().Add(3*time.Second))
			_ = os.RemoveAll(full)
		} else {
			freed += fileSize(full)
			_ = os.Remove(full)
		}
	}
	return freed
}

// removeDownloads deletes the chosen files or folders, but only ones inside the Downloads folder.
func removeDownloads(paths []string) (int, int64) {
	var n int
	var b int64
	dl := filepath.Clean(downloadsDir())
	for _, p := range paths {
		p = filepath.Clean(p)
		rel, err := filepath.Rel(dl, p)
		if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			continue
		}
		st, err := os.Lstat(p)
		if err != nil {
			continue
		}
		if st.IsDir() {
			s := stDirSize(context.Background(), p, time.Now().Add(30*time.Second))
			if os.RemoveAll(p) == nil {
				n++
				b += s
			}
		} else if os.Remove(p) == nil {
			n++
			b += st.Size()
		}
	}
	return n, b
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
	for _, id := range ids {
		storageDB.mu.Lock()
		a := storageDB.apps[id]
		storageDB.mu.Unlock()
		if a == nil {
			out = append(out, map[string]any{"id": id, "ok": false, "msg": "Please scan again: this list is out of date."})
			continue
		}
		ok, msg := uninstallOne(ctx, a)
		out = append(out, map[string]any{"id": id, "name": a.Name, "ok": ok, "msg": msg})
	}
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
	return items, nil
}
