//go:build windows

package main

// Windows photos / videos / music / documents / big files: a bounded walk of the user's profile and
// the other fixed drives, totalled per kind, with the biggest of each kind listed.

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

func scanFiles(ctx context.Context, drives []stDrive, budget time.Duration) ([]stFile, []stCat, bool) {
	deadline := time.Now().Add(budget)
	sysDrive := strings.ToUpper(os.Getenv("SystemDrive"))
	roots := []string{}
	if up := os.Getenv("USERPROFILE"); up != "" {
		roots = append(roots, up)
	}
	for _, d := range drives {
		if d.Kind == "fixed" && !strings.EqualFold(d.Name, sysDrive) {
			roots = append(roots, d.Name+`\`)
		}
	}
	skip := map[string]bool{"$recycle.bin": true, "system volume information": true, "windows": true, "program files": true, "program files (x86)": true, "programdata": true, "appdata": true, "$windows.~bt": true, "$windows.~ws": true, "windows.old": true, "recovery": true}
	all := newTopFiles(150)
	var mu sync.Mutex
	var wg sync.WaitGroup
	partial := false
	for _, root := range roots {
		wg.Add(1)
		go func(root string) {
			defer wg.Done()
			t := newTopFiles(150)
			_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
				if err != nil {
					if d != nil && d.IsDir() {
						return fs.SkipDir
					}
					return nil
				}
				if ctx.Err() != nil || time.Now().After(deadline) {
					mu.Lock()
					partial = true
					mu.Unlock()
					return errStop
				}
				if d.IsDir() {
					if skip[strings.ToLower(d.Name())] && p != root {
						return fs.SkipDir
					}
					return nil
				}
				info, e := d.Info()
				if e != nil || info.Size() <= 0 {
					return nil
				}
				t.add(stFile{ID: p, Path: p, Name: d.Name(), Dir: filepath.Dir(p), Bytes: info.Size(), Mod: info.ModTime().Unix(), Cat: catOfName(d.Name())})
				return nil
			})
			mu.Lock()
			all.merge(t)
			mu.Unlock()
		}(root)
	}
	wg.Wait()
	files, cats := all.result()
	return files, cats, partial
}

// storageDeleteFiles sends files from the last scan to the Recycle Bin. Anything not in that scan,
// or inside Windows / Program Files, is refused.
func storageDeleteFiles(ctx context.Context, ids []string) (int64, int, []string) {
	var paths []string
	var freed int64
	var log []string
	protected := []string{os.Getenv("SystemRoot"), os.Getenv("ProgramFiles"), os.Getenv("ProgramFiles(x86)"), os.Getenv("ProgramData")}
	for _, id := range ids {
		storageDB.mu.Lock()
		f := storageDB.fls[id]
		storageDB.mu.Unlock()
		if f == nil {
			log = append(log, "Skipped a file that is not in the last scan. Rescan and try again.")
			continue
		}
		bad := false
		for _, pr := range protected {
			if pr != "" && strings.HasPrefix(strings.ToLower(f.Path), strings.ToLower(pr)+`\`) {
				bad = true
			}
		}
		if bad || !storFileExists(f.Path) {
			log = append(log, "Skipped "+f.Name)
			continue
		}
		paths = append(paths, f.Path)
		freed += f.Bytes
	}
	moved := 0
	for i := 0; i < len(paths); i += 30 {
		end := i + 30
		if end > len(paths) {
			end = len(paths)
		}
		var q []string
		for _, p := range paths[i:end] {
			q = append(q, psQuote(p))
		}
		ps := "Add-Type -AssemblyName Microsoft.VisualBasic; foreach ($p in @(" + strings.Join(q, ",") + ")) { try { [Microsoft.VisualBasic.FileIO.FileSystem]::DeleteFile($p,'OnlyErrorDialogs','SendToRecycleBin') } catch {} }"
		if err := runHidden(ctx, filepath.Join(os.Getenv("SystemRoot"), `System32\WindowsPowerShell\v1.0\powershell.exe`), "-NoProfile", "-NonInteractive", "-Command", ps); err != nil {
			log = append(log, "Windows could not move some files to the Recycle Bin.")
		}
	}
	for _, p := range paths {
		if !storFileExists(p) {
			moved++
		}
	}
	if moved < len(paths) {
		freed = freed * int64(moved) / int64(max(1, len(paths)))
	}
	log = append(log, "Moved "+itoa(moved)+" file(s) to the Recycle Bin. Empty the Recycle Bin to get the space back.")
	return freed, moved, log
}

func itoa(n int) string            { return strconv.Itoa(n) }
func storFileExists(p string) bool { _, err := os.Stat(p); return err == nil }
