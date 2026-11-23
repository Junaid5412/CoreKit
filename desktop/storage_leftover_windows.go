//go:build windows

package main

// Finds data folders that no installed program owns any more: in AppData (Local, Roaming,
// LocalLow) and empty shells in Program Files, plus whatever the programs uninstalled through
// CoreKit left behind. Nothing here is ever marked safe; the user reviews and chooses.

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// folders that never belong to "a program you can uninstall"
var leftSkip = func() map[string]bool {
	m := map[string]bool{}
	for _, n := range []string{
		"microsoft", "packages", "temp", "programs", "publishers", "comms", "connecteddevicesplatform", "d3dscache",
		"crashdumps", "virtualstore", "placeholdertilelogofolder", "application data", "history", "temporary internet files",
		"peerdistrepub", "packagemanagement", "package cache", "windows", "windowsapps", "identities", "speech",
		"toastnotificationmanagercompat", "diagnostics", "elevateddiagnostics", "squirreltemp", "corekit", "cache", "caches",
		"intel", "nvidia", "nvidia corporation", "amd", "ati", "realtek", "synaptics", "dell", "hp", "lenovo", "asus", "acer", "msi",
		"wsl", "lxss", "docker", "nuget", "pip", "npm", "npm-cache", "nvm", "yarn", "pnpm", "pnpm-cache", "node-gyp", "go-build",
		"composer", "pypoetry", "conda", "cargo", "rustup", "gem", "maven", "gradle", "jupyter", "code", "git", "gh", "ssh", "gnupg",
		"vim", "nvim", "emacs", "python", "dotnet", ".net", "ms-playwright", "electron", "electron-builder", "fontconfig",
		"common files", "internet explorer", "windows defender", "windows defender advanced threat protection", "windows mail",
		"windows media player", "windows nt", "windows photo viewer", "windows portable devices", "windows security",
		"windows sidebar", "windowspowershell", "modifiablewindowsapps", "reference assemblies", "msbuild", "uninstall information",
		"microsoft.net", "microsoft update health tools", "rempl", "usoshared", "ssh",
	} {
		m[n] = true
	}
	return m
}()

// dirFacts measures a folder and notes its newest change and whether it still holds program files.
// done is false when the time limit was hit, so the facts are incomplete.
func dirFacts(ctx context.Context, root string, deadline time.Time) (bytes, newest int64, hasBin, done bool) {
	done = true
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if ctx.Err() != nil || time.Now().After(deadline) {
			done = false
			return errStop
		}
		info, e := d.Info()
		if e != nil {
			return nil
		}
		if m := info.ModTime().Unix(); m > newest {
			newest = m
		}
		if d.IsDir() {
			return nil
		}
		bytes += info.Size()
		switch strings.ToLower(filepath.Ext(d.Name())) {
		case ".exe", ".dll", ".sys", ".msi":
			hasBin = true
		}
		return nil
	})
	return
}

// hasProgramFiles reports whether a folder still holds something that can run.
func hasProgramFiles(ctx context.Context, root string) bool {
	found := false
	deadline := time.Now().Add(3 * time.Second)
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if ctx.Err() != nil || time.Now().After(deadline) {
			found = true // could not finish looking: assume it is a real program
			return errStop
		}
		if !d.IsDir() {
			switch strings.ToLower(filepath.Ext(d.Name())) {
			case ".exe", ".dll", ".sys", ".msi":
				found = true
				return errStop
			}
		}
		return nil
	})
	return found
}

func subDirs(root string) []string {
	ents, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range ents {
		if e.IsDir() {
			out = append(out, e.Name())
		}
	}
	return out
}

// startMenuNames are the shortcuts in the Start menu: proof a program is still there even when it
// has no entry in the installed-programs list (portable and per-user installs).
func startMenuNames() []string {
	var out []string
	for _, root := range []string{
		filepath.Join(os.Getenv("APPDATA"), `Microsoft\Windows\Start Menu\Programs`),
		filepath.Join(os.Getenv("ProgramData"), `Microsoft\Windows\Start Menu\Programs`),
	} {
		_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				if p != root {
					out = append(out, d.Name())
				}
				return nil
			}
			if strings.EqualFold(filepath.Ext(d.Name()), ".lnk") {
				out = append(out, strings.TrimSuffix(d.Name(), filepath.Ext(d.Name())))
			}
			return nil
		})
	}
	return out
}

type leftCand struct {
	path, name, where, why string
	pf                     bool // an install folder (Program Files), not a data folder
	sure                   bool // left by a program uninstalled through CoreKit
}

func agoWords(now, t int64) string {
	d := (now - t) / 86400
	switch {
	case d < 60:
		return fmt.Sprintf("%d days ago", d)
	case d < 730:
		return fmt.Sprintf("%d months ago", d/30)
	}
	return fmt.Sprintf("%d years ago", d/365)
}

// locNamedFor checks that an install folder is named after its program or maker, so a shared
// folder a program happened to be installed into is never offered.
func locNamedFor(loc, name, pub string) bool {
	base := filepath.Base(filepath.Clean(loc))
	if belongsTo(base, &stApp{Name: name}) {
		return true
	}
	bn := normName(base)
	for _, w := range strings.Fields(cleanName(name) + " " + reCorp.ReplaceAllString(pub, " ")) {
		if k := normName(w); len(k) >= 4 && !genericWords[k] && strings.Contains(bn, k) {
			return true
		}
	}
	return false
}

// safeInstallDir says whether an uninstalled program's own folder may be offered for removal.
func safeInstallDir(loc string, installed []stApp) bool {
	loc = filepath.Clean(loc)
	if len(pathParts(loc)) < 3 || !dirExists(loc) || isReparse(loc) || under(loc, os.Getenv("SystemRoot")) || under(loc, os.Getenv("ProgramData")) {
		return false // needs drive + two folders: C:\Program Files\Name
	}
	if k := normName(filepath.Base(loc)); genericDirs[k] || leftSkip[strings.ToLower(filepath.Base(loc))] {
		return false
	}
	if home := os.Getenv("USERPROFILE"); under(loc, home) && !under(loc, filepath.Join(os.Getenv("LOCALAPPDATA"), "Programs")) {
		if len(pathParts(strings.TrimPrefix(loc, filepath.Clean(home)))) < 4 {
			return false // Desktop, Documents\Something, AppData\Local\Name are handled as data, not here
		}
	}
	for i := range installed {
		if l := installed[i].Loc; l != "" && (under(l, loc) || under(loc, l)) {
			return false // another installed program lives in or around it
		}
	}
	return true
}

// scanLeftovers returns the leftover folders as cleanable items in the "Leftovers" group.
func scanLeftovers(ctx context.Context, apps []stApp, gone []goneApp, now int64) []stClean {
	// what is installed right now
	byApps := newInstallIndex()
	installedID := map[string]bool{}
	installedName := map[string]bool{}
	for i := range apps {
		byApps.addApp(&apps[i])
		installedID[apps[i].ID] = true
		installedName[normName(cleanName(apps[i].Name))] = true
	}
	for _, n := range startMenuNames() {
		byApps.add(n)
	}
	var really []goneApp // uninstalled through CoreKit and truly no longer installed
	for _, g := range gone {
		if !installedID[g.ID] && !installedName[normName(cleanName(g.Name))] {
			really = append(really, g)
		}
	}

	local, roam := os.Getenv("LOCALAPPDATA"), os.Getenv("APPDATA")
	low := filepath.Join(filepath.Dir(local), "LocalLow")
	pfRoots := []string{os.Getenv("ProgramFiles"), os.Getenv("ProgramFiles(x86)")}
	seen := map[string]bool{}
	var cands []leftCand
	add := func(c leftCand) {
		k := strings.ToLower(c.path)
		if !seen[k] && !isReparse(c.path) {
			seen[k] = true
			cands = append(cands, c)
		}
	}

	// 1. what programs uninstalled through CoreKit left behind
	for _, g := range really {
		a := stApp{Name: g.Name, Loc: g.Loc}
		why := "Left behind by " + g.Name + ", which you uninstalled."
		if g.Kind != "appx" && g.Loc != "" && locNamedFor(g.Loc, g.Name, g.Pub) && safeInstallDir(g.Loc, apps) {
			add(leftCand{path: filepath.Clean(g.Loc), name: filepath.Base(g.Loc), where: filepath.Dir(g.Loc), why: why, pf: true, sure: true})
		}
		for _, r := range []struct{ root, where string }{{local, `AppData\Local`}, {roam, `AppData\Roaming`}, {low, `AppData\LocalLow`}} {
			for _, n := range subDirs(r.root) {
				if !leftSkip[strings.ToLower(n)] && belongsTo(n, &a) && !byApps.owns(n) {
					add(leftCand{path: filepath.Join(r.root, n), name: n, where: r.where, why: why, sure: true})
				}
			}
		}
	}

	// 2. empty shells in Program Files: no installed program matches and no program files remain
	pfLeft := map[string]bool{}
	for _, root := range pfRoots {
		if root == "" {
			continue
		}
		for _, n := range subDirs(root) {
			if leftSkip[strings.ToLower(n)] || strings.HasPrefix(strings.ToLower(n), "windows") || strings.HasPrefix(strings.ToLower(n), "microsoft") || byApps.owns(n) {
				continue
			}
			pfLeft[strings.ToLower(n)] = true
			add(leftCand{path: filepath.Join(root, n), name: n, where: filepath.Base(root), pf: true})
		}
	}

	// 3. data folders in AppData that nothing installed owns. Folders in Program Files and
	//    AppData\Local\Programs count as installed too (programs with no uninstall entry).
	full := newInstallIndex()
	for k := range byApps.keys {
		full.keys[k] = true
	}
	for _, root := range append(pfRoots, filepath.Join(local, "Programs")) {
		if root == "" {
			continue
		}
		for _, n := range subDirs(root) {
			if pfLeft[strings.ToLower(n)] && !hasProgramFiles(ctx, filepath.Join(root, n)) {
				continue // an empty shell proves nothing
			}
			full.add(n)
			if !genericWords[normName(n)] && len(subDirs(filepath.Join(root, n))) <= 12 {
				for _, m := range subDirs(filepath.Join(root, n)) { // Vendor\Product
					full.add(m)
				}
			}
		}
	}
	for _, r := range []struct{ root, where string }{{local, `AppData\Local`}, {roam, `AppData\Roaming`}, {low, `AppData\LocalLow`}} {
		for _, n := range subDirs(r.root) {
			ln := strings.ToLower(n)
			if leftSkip[ln] || strings.HasPrefix(n, ".") || strings.HasPrefix(n, "{") || strings.HasPrefix(ln, "microsoft") || full.owns(n) {
				continue
			}
			add(leftCand{path: filepath.Join(r.root, n), name: n, where: r.where})
		}
	}

	// measure the candidates, then keep the ones that are old and worth the space
	type fact struct {
		bytes, newest int64
		hasBin, done  bool
	}
	facts := make([]fact, len(cands))
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	for i := range cands {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			f := &facts[i]
			f.bytes, f.newest, f.hasBin, f.done = dirFacts(ctx, cands[i].path, time.Now().Add(15*time.Second))
		}(i)
	}
	wg.Wait()

	var out []stClean
	for i, c := range cands {
		f := facts[i]
		if f.bytes < 1<<20 {
			continue
		}
		why := c.why
		if !c.sure {
			if !f.done || f.newest == 0 {
				continue // not fully read: say nothing rather than guess
			}
			if c.pf {
				if f.hasBin || now-f.newest < 30*86400 {
					continue // still holds program files, or was touched recently
				}
				why = "An empty program folder: no installed program matches it and no program files are left inside."
			} else {
				if f.bytes < 5<<20 || now-f.newest < 14*86400 {
					continue
				}
				why = "No installed program matches this folder."
			}
			why += " Last changed " + agoWords(now, f.newest) + "."
		}
		out = append(out, stClean{
			ID: "left:" + c.path, Name: c.name + "  (" + c.where + ")", Desc: why, Bytes: f.bytes,
			Safe: false, Path: c.path, Group: "Leftovers", Mod: f.newest,
		})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Bytes > out[j].Bytes })
	if len(out) > 60 {
		out = out[:60]
	}
	return out
}

// leftoverAllowed re-checks a leftover right before deleting it: it must come from the last scan
// and still sit directly in AppData or Program Files (or be an uninstalled program's own folder).
func leftoverAllowed(path string) bool {
	path = filepath.Clean(path)
	storageDB.mu.Lock()
	c := storageDB.cln["left:"+path]
	storageDB.mu.Unlock()
	if c == nil || c.Group != "Leftovers" || !dirExists(path) || isReparse(path) || under(path, os.Getenv("SystemRoot")) {
		return false
	}
	return len(pathParts(path)) >= 3
}
