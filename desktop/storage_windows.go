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

// ---------------------------------------------------------------- folder sizing (bounded)

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

// childSizes lists the immediate children of a folder with their sizes, largest first.
func childSizes(ctx context.Context, root string, budget time.Duration) []stBig {
	ents, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	deadline := time.Now().Add(budget)
	var out []stBig
	for _, e := range ents {
		if ctx.Err() != nil || time.Now().After(deadline) {
			break
		}
		full := filepath.Join(root, e.Name())
		b := stBig{Path: full, Name: e.Name(), Kind: "file"}
		if e.IsDir() {
			b.Kind = "folder"
			b.Bytes = stDirSize(ctx, full, time.Now().Add(budget/3))
		} else if info, err := e.Info(); err == nil {
			b.Bytes = info.Size()
		}
		if b.Bytes > 0 {
			out = append(out, b)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Bytes > out[j].Bytes })
	return out
}

// ---------------------------------------------------------------- drives

func listDrives() []stDrive {
	buf := make([]uint16, 256)
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

// driveParts gives a rough "where the space went" breakdown for the system drive.
func driveParts(ctx context.Context, d *stDrive) {
	if d.Kind == "removable" {
		return
	}
	root := d.Name + `\`
	budget := 6 * time.Second
	var parts []stPart
	add := func(name, color string, bytes int64) {
		if bytes > 0 {
			parts = append(parts, stPart{Name: name, Bytes: bytes, Color: color})
		}
	}
	if strings.EqualFold(d.Name, os.Getenv("SystemDrive")) {
		apps := stDirSize(ctx, os.Getenv("ProgramFiles"), time.Now().Add(budget)) + stDirSize(ctx, os.Getenv("ProgramFiles(x86)"), time.Now().Add(budget))
		win := stDirSize(ctx, filepath.Join(root, "Windows"), time.Now().Add(budget))
		users := stDirSize(ctx, filepath.Join(root, "Users"), time.Now().Add(2*budget))
		add("Programs", "#38bdf8", apps)
		add("Windows", "#a78bfa", win)
		add("Users & data", "#2dd4bf", users)
		other := d.Used - apps - win - users
		add("Other", "#64748b", other)
	} else {
		add("Used", "#38bdf8", d.Used)
	}
	d.Parts = parts
}

// ---------------------------------------------------------------- cleanables

type cleanDef struct {
	id, name, desc string
	safe           bool
	paths          []string // folders whose contents are cleared (or a file to delete)
	whole          bool     // delete the folder itself (not just its contents)
}

func cleanDefs(hiberOn bool) []cleanDef {
	local := os.Getenv("LOCALAPPDATA")
	win := filepath.Join(os.Getenv("SystemDrive")+`\`, "Windows")
	defs := []cleanDef{
		{id: "temp-user", name: "Temporary files", desc: "Leftover files in your temp folders.", safe: true, paths: []string{os.Getenv("TEMP"), filepath.Join(win, "Temp")}},
		{id: "update", name: "Windows Update cache", desc: "Installer files Windows keeps after updating.", safe: true, paths: []string{filepath.Join(win, "SoftwareDistribution", "Download")}},
		{id: "delivery", name: "Delivery Optimization", desc: "Update pieces shared with other PCs.", safe: true, paths: []string{filepath.Join(win, "SoftwareDistribution", "DeliveryOptimization")}},
		{id: "prefetch", name: "Prefetch", desc: "Startup hints Windows rebuilds automatically.", safe: true, paths: []string{filepath.Join(win, "Prefetch")}},
		{id: "thumbs", name: "Thumbnail cache", desc: "Preview images Windows rebuilds when needed.", safe: true, paths: []string{filepath.Join(local, "Microsoft", "Windows", "Explorer")}},
		{id: "wer", name: "Error reports", desc: "Saved crash reports.", safe: true, paths: []string{filepath.Join(local, "Microsoft", "Windows", "WER"), filepath.Join(os.Getenv("ProgramData"), "Microsoft", "Windows", "WER")}},
		{id: "dumps", name: "Crash dumps", desc: "Memory dumps from crashes.", safe: true, paths: []string{filepath.Join(local, "CrashDumps"), filepath.Join(win, "Minidump")}},
		{id: "chrome", name: "Chrome cache", desc: "Chrome's temporary web files.", safe: true, paths: []string{filepath.Join(local, "Google", "Chrome", "User Data", "Default", "Cache")}},
		{id: "edge", name: "Edge cache", desc: "Edge's temporary web files.", safe: true, paths: []string{filepath.Join(local, "Microsoft", "Edge", "User Data", "Default", "Cache")}},
		{id: "recyclebin", name: "Recycle Bin", desc: "Files you already deleted.", safe: true},
	}
	if hiberFile := os.Getenv("SystemDrive") + `\hiberfil.sys`; hiberOn && fileSize(hiberFile) > 0 {
		defs = append(defs, cleanDef{id: "hibernation", name: "Hibernation file", desc: "Frees space by turning off hibernate (you can turn it back on).", safe: false, paths: []string{hiberFile}})
	}
	if wo := os.Getenv("SystemDrive") + `\Windows.old`; dirExists(wo) {
		defs = append(defs, cleanDef{id: "windowsold", name: "Previous Windows (Windows.old)", desc: "Your old Windows kept after an upgrade. Removing it means you can't roll back.", safe: false, paths: []string{wo}, whole: true})
	}
	return defs
}

func dirExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}

func recycleSize(ctx context.Context, drives []stDrive) int64 {
	var total int64
	for _, d := range drives {
		if d.Kind == "removable" {
			continue
		}
		total += stDirSize(ctx, filepath.Join(d.Name+`\`, "$Recycle.Bin"), time.Now().Add(4*time.Second))
	}
	return total
}

// ---------------------------------------------------------------- the scan

func storageScan(ctx context.Context, progress func(int, string)) (*stResult, error) {
	start := time.Now()
	res := &stResult{Platform: "windows"}

	progress(5, "Reading drives")
	res.Drives = listDrives()

	progress(15, "Listing installed programs")
	raw, err := runPS(ctx, storagePS, nil, func(_, _, _ string) {})
	var pr struct {
		Apps []struct {
			ID, Name, Pub, Ver, Loc, Uninstall, Source, Kind, Family string
			Size, Installed                                          int64
			Quiet, NonRemovable                                      bool
		} `json:"apps"`
		HiberOn bool   `json:"hiberOn"`
		OsDrive string `json:"osDrive"`
	}
	if err == nil {
		_ = json.Unmarshal(raw, &pr)
	}
	for _, a := range pr.Apps {
		drive := driveOf(a.Loc)
		bloat, why := isWinBloat(a.Name, a.Pub)
		removable := true
		src := a.Source
		if a.Source == "store" {
			removable = !a.NonRemovable
		}
		res.Apps = append(res.Apps, stApp{
			ID: a.ID, Name: a.Name, Pub: a.Pub, Ver: a.Ver, Size: a.Size, Installed: a.Installed,
			Loc: a.Loc, Drive: drive, Source: src, Kind: a.Kind, Removable: removable,
			Bloat: bloat, BloatWhy: why, Uninstall: a.Uninstall, Quiet: a.Quiet, Family: a.Family,
		})
	}

	progress(45, "Measuring reclaimable space")
	for _, def := range cleanDefs(pr.HiberOn) {
		c := stClean{ID: def.id, Name: def.name, Desc: def.desc, Safe: def.safe}
		switch def.id {
		case "recyclebin":
			c.Bytes = recycleSize(ctx, res.Drives)
		case "hibernation":
			c.Bytes = fileSize(def.paths[0])
			c.Path = def.paths[0]
		default:
			for _, p := range def.paths {
				if p == "" {
					continue
				}
				if def.whole {
					c.Bytes += stDirSize(ctx, p, time.Now().Add(8*time.Second))
				} else if dirExists(p) {
					c.Bytes += stDirSize(ctx, p, time.Now().Add(4*time.Second))
				}
			}
		}
		if c.Bytes > 0 {
			res.Clean = append(res.Clean, c)
		}
	}

	// Downloads clutter: old installers/archives
	progress(65, "Checking the Downloads folder")
	if dl := filepath.Join(os.Getenv("USERPROFILE"), "Downloads"); dirExists(dl) {
		var bytes int64
		var n int
		cut := time.Now().AddDate(0, 0, -14)
		_ = filepath.WalkDir(dl, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			ext := strings.ToLower(filepath.Ext(p))
			if ext == ".exe" || ext == ".msi" || ext == ".zip" || ext == ".iso" || ext == ".rar" || ext == ".7z" || ext == ".dmg" {
				if info, e := d.Info(); e == nil && info.ModTime().Before(cut) {
					bytes += info.Size()
					n++
				}
			}
			return nil
		})
		if bytes > 0 {
			res.Clean = append(res.Clean, stClean{ID: "downloads", Name: "Old downloads", Desc: fmt.Sprintf("%d installer/archive files over two weeks old in your Downloads folder. Review before deleting.", n), Bytes: bytes, Count: n, Safe: false, Path: dl})
		}
	}

	progress(75, "Finding the biggest folders")
	seen := map[string]bool{}
	for i := range res.Drives {
		if ctx.Err() != nil {
			break
		}
		driveParts(ctx, &res.Drives[i])
		for _, b := range childSizes(ctx, res.Drives[i].Name+`\`, 8*time.Second) {
			if b.Bytes >= 500<<20 && !seen[b.Path] {
				seen[b.Path] = true
				b.Drive = res.Drives[i].Name
				res.Big = append(res.Big, b)
			}
		}
	}

	progress(92, "Working out recommendations")
	finishStorage(res, time.Now().Unix())
	res.Ms = time.Since(start).Milliseconds()
	return res, nil
}

var reDrive = regexp.MustCompile(`^([A-Za-z]):`)

func driveOf(path string) string {
	if m := reDrive.FindStringSubmatch(path); m != nil {
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
			n, b := removeFiles(pick["downloads"])
			freed += b
			log = append(log, fmt.Sprintf("Deleted %d old download(s) (%s)", n, fmtSize(b)))
		default:
			def, ok := defsByID[id]
			if !ok {
				continue
			}
			var cf int64
			for _, p := range def.paths {
				if p != "" {
					cf += clearContents(ctx, p)
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

func removeFiles(paths []string) (int, int64) {
	var n int
	var b int64
	for _, p := range paths {
		s := fileSize(p)
		if os.Remove(p) == nil {
			n++
			b += s
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
	return childSizes(ctx, path, 20*time.Second), nil
}
