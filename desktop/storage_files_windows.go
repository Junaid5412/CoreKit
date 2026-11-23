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

// storageDeleteFiles removes files from the last scan (ids) and items picked in the folder browser
// (paths). By default they go to the Recycle Bin. Files not in the scan, and anything the folder
// browser guard refuses, are skipped.
func storageDeleteFiles(ctx context.Context, ids, paths []string, permanent bool) (int64, int, []string) {
	var ok []string
	var log []string
	skipped := 0
	for _, id := range ids {
		storageDB.mu.Lock()
		f := storageDB.fls[id]
		storageDB.mu.Unlock()
		if f == nil || !canDelete(f.Path) || !storFileExists(f.Path) {
			skipped++
			continue
		}
		ok = append(ok, f.Path)
	}
	for _, p := range paths {
		p = filepath.Clean(p)
		if !canDelete(p) || !storFileExists(p) {
			skipped++
			continue
		}
		ok = append(ok, p)
	}
	n, freed, failed := deletePaths(ctx, ok, permanent)
	if permanent {
		log = append(log, "Deleted "+itoa(n)+" item(s) ("+fmtSize(freed)+")")
	} else {
		log = append(log, "Moved "+itoa(n)+" item(s) to the Recycle Bin ("+fmtSize(freed)+"). Empty it to get the space back")
	}
	for i, f := range failed {
		if i == 5 {
			log = append(log, "and "+itoa(len(failed)-5)+" more could not be removed")
			break
		}
		log = append(log, "Could not remove "+f+": it is in use")
	}
	if skipped > 0 {
		log = append(log, "Skipped "+itoa(skipped)+" protected or changed item(s)")
	}
	return freed, n, log
}

func itoa(n int) string            { return strconv.Itoa(n) }
func storFileExists(p string) bool { _, err := os.Stat(p); return err == nil }
