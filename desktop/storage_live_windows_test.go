//go:build windows

package main

// Runs the Storage module against the real Windows of the CI runner (CK_LIVE=1 only).

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestStorageLiveScan(t *testing.T) {
	if testingLiveOff() {
		t.Skip("set CK_LIVE=1 to run against this PC")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	res, err := storageScan(ctx, func(p int, label string) { t.Logf("%3d%% %s", p, label) })
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Drives) == 0 {
		t.Fatal("no drives found")
	}
	var sys *stDrive
	for i := range res.Drives {
		if res.Drives[i].Kind == "system" {
			sys = &res.Drives[i]
		}
	}
	if sys == nil || sys.Total == 0 || sys.Used == 0 {
		t.Fatalf("system drive not measured: %+v", res.Drives)
	}
	t.Logf("system drive %s: %s used of %s, %d parts", sys.Name, fmtSize(sys.Used), fmtSize(sys.Total), len(sys.Parts))
	if res.AppCount == 0 {
		t.Fatal("no installed programs found (the registry list failed)")
	}
	t.Logf("programs: %d, cleanables: %d, reclaimable: %s, recs: %d", res.AppCount, len(res.Clean), fmtSize(res.Reclaim), len(res.Recs))
	for _, c := range res.Clean {
		t.Logf("  clean %-22s %s safe=%v", c.Name, fmtSize(c.Bytes), c.Safe)
	}
	t.Logf("files listed: %d, kinds: %+v", len(res.Files), res.Cats)
	for _, f := range res.Files {
		if f.ID == "" || f.Cat == "" || f.Bytes <= 0 {
			t.Fatalf("bad file entry: %+v", f)
		}
	}
	// every app we list must carry the fields the UI needs
	for i, a := range res.Apps {
		if a.ID == "" || a.Name == "" {
			t.Fatalf("app %d missing id/name: %+v", i, a)
		}
		if i >= 3 {
			break
		}
		t.Logf("  app %-40s %s [%s]", a.Name, fmtSize(a.Size), a.Source)
	}
	// drilling into a real folder must return sized children
	if items, err := storageDrill(ctx, `C:\Windows`); err != nil || len(items) == 0 {
		t.Fatalf("drill C:\\Windows: %v (%d items)", err, len(items))
	}

	// a safe, reversible clean: clear the user temp folder and confirm it reports freed bytes
	storageDB.set(res)
	freed, log, err := storageClean(ctx, []string{"temp-user"}, nil, true)
	if err != nil {
		t.Fatalf("clean temp: %v", err)
	}
	t.Logf("cleaned temp: freed %s, %v", fmtSize(freed), log)
}

func testingLiveOff() bool { return os.Getenv("CK_LIVE") != "1" }

// Only files inside Downloads may be deleted, whatever paths the page sends.
func TestStorageLiveDownloadsGuard(t *testing.T) {
	if testingLiveOff() {
		t.Skip("set CK_LIVE=1 to run against this PC")
	}
	home := t.TempDir()
	t.Setenv("USERPROFILE", home)
	dl := downloadsDir()
	_ = os.MkdirAll(filepath.Join(dl, "sub"), 0o755)
	inside := filepath.Join(dl, "a.zip")
	folder := filepath.Join(dl, "sub")
	outside := filepath.Join(home, "keep.txt")
	for _, p := range []string{inside, filepath.Join(folder, "b.bin"), outside} {
		if err := os.WriteFile(p, []byte("12345"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	n, b, failed := removeDownloads(context.Background(), []string{inside, folder, outside, dl, filepath.Join(dl, "..", "keep.txt")}, true)
	if n != 2 || b != 10 || len(failed) != 0 {
		t.Fatalf("removed %d items, %d bytes, %d failed; want 2 items, 10 bytes", n, b, len(failed))
	}
	if _, err := os.Stat(outside); err != nil {
		t.Fatal("a file outside Downloads was deleted")
	}
	if _, err := os.Stat(dl); err != nil {
		t.Fatal("the Downloads folder itself was deleted")
	}
}

func mkFile(t *testing.T, path string, size int, age time.Duration) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, make([]byte, size), 0o644); err != nil {
		t.Fatal(err)
	}
	when := time.Now().Add(-age)
	_ = os.Chtimes(path, when, when)
	_ = os.Chtimes(filepath.Dir(path), when, when)
}

// The Recycle Bin path and the permanent path both really remove files and folders.
func TestStorageLiveRecycle(t *testing.T) {
	if testingLiveOff() {
		t.Skip("set CK_LIVE=1 to run against this PC")
	}
	for _, permanent := range []bool{false, true} {
		dir := t.TempDir()
		f := filepath.Join(dir, "one.bin")
		d := filepath.Join(dir, "folder")
		mkFile(t, f, 1000, 0)
		mkFile(t, filepath.Join(d, "in", "two.bin"), 2000, 0)
		n, freed, failed := deletePaths(context.Background(), []string{f, d}, permanent)
		if n != 2 || freed != 3000 || len(failed) != 0 || !pathGone(f) || !pathGone(d) {
			t.Fatalf("permanent=%v: removed %d, freed %d, failed %v", permanent, n, freed, failed)
		}
	}
}

// The folder browser refuses Windows, programs and the folders everything hangs off.
func TestStorageLiveCanDelete(t *testing.T) {
	if testingLiveOff() {
		t.Skip("set CK_LIVE=1 to run against this PC")
	}
	home, local := os.Getenv("USERPROFILE"), os.Getenv("LOCALAPPDATA")
	win := os.Getenv("SystemRoot")
	mine := filepath.Join(local, "CKTestLeftover")
	mkFile(t, filepath.Join(mine, "x.bin"), 10, 0)
	own := filepath.Join(home, "CKTestFolder")
	mkFile(t, filepath.Join(own, "y.bin"), 10, 0)
	prof := filepath.Join(appDataRoot(), "Browser", "Profiles", "cktest")
	mkFile(t, filepath.Join(prof, "z.bin"), 10, 0)
	defer os.RemoveAll(mine)
	defer os.RemoveAll(own)
	defer os.RemoveAll(prof)
	no := []string{
		win, filepath.Join(win, "System32"), filepath.Join(win, "explorer.exe"), os.Getenv("ProgramFiles"),
		filepath.Join(os.Getenv("ProgramFiles"), "Common Files"), os.Getenv("ProgramData"), os.Getenv("SystemDrive") + `\`,
		os.Getenv("SystemDrive") + `\pagefile.sys`, os.Getenv("SystemDrive") + `\Users`, home, filepath.Join(home, "AppData"),
		local, filepath.Join(local, "Microsoft"), filepath.Join(local, "Microsoft", "Windows"), filepath.Join(local, "Packages"),
		filepath.Join(local, "Temp"), filepath.Join(home, "Documents"), filepath.Join(home, "Desktop"), filepath.Join(home, "NTUSER.DAT"),
		appDataRoot(), filepath.Join(appDataRoot(), "Browser"), filepath.Join(appDataRoot(), "Browser", "Profiles"),
		filepath.Join(appDataRoot(), "Browser", "config.dat"), `relative\path`, `C:`,
	}
	for _, p := range no {
		if canDelete(p) {
			t.Errorf("must refuse %s", p)
		}
	}
	yes := []string{mine, filepath.Join(mine, "x.bin"), own, filepath.Join(own, "y.bin"), prof, filepath.Join(prof, "z.bin")}
	for _, p := range yes {
		if !canDelete(p) {
			t.Errorf("should allow %s", p)
		}
	}
}

// Leftovers: old unowned folders are found, fresh or owned ones are not, and only scanned
// leftovers can be removed.
func TestStorageLiveLeftovers(t *testing.T) {
	if testingLiveOff() {
		t.Skip("set CK_LIVE=1 to run against this PC")
	}
	root := t.TempDir()
	local, roam := filepath.Join(root, "AppData", "Local"), filepath.Join(root, "AppData", "Roaming")
	t.Setenv("LOCALAPPDATA", local)
	t.Setenv("APPDATA", roam)
	old := 200 * 24 * time.Hour
	mkFile(t, filepath.Join(local, "ZzQuuxPlumbus", "save.bin"), 6<<20, old)      // unowned and old: leftover
	mkFile(t, filepath.Join(local, "ZzFreshThing", "data.bin"), 6<<20, 0)         // unowned but in use
	mkFile(t, filepath.Join(roam, "Qwertium", "profile.bin"), 6<<20, old)         // owned by an installed program
	mkFile(t, filepath.Join(roam, "ZzSmall", "a.bin"), 1000, old)                 // too small to matter
	mkFile(t, filepath.Join(roam, "Zebra Notes", "notes.db"), 2<<20, 0)           // left by a program just uninstalled
	mkFile(t, filepath.Join(local, "Microsoft", "Anything", "x.bin"), 6<<20, old) // never touched
	mkFile(t, filepath.Join(roam, "ZzLiveTool", "settings.bin"), 6<<20, old)      // data of a program that has no uninstall entry
	pf := filepath.Join(root, "Program Files")
	t.Setenv("ProgramFiles", pf)
	t.Setenv("ProgramFiles(x86)", filepath.Join(root, "none"))
	mkFile(t, filepath.Join(pf, "ZzDeadShell", "install.log"), 2<<20, old) // empty shell of a removed program
	mkFile(t, filepath.Join(pf, "ZzLiveTool", "tool.exe"), 2<<20, old)     // still a program: never offered
	mkFile(t, filepath.Join(pf, "Zebra Notes", "zebra.exe"), 2<<20, 0)     // the uninstalled program's own folder
	mkFile(t, filepath.Join(pf, "Shared", "other.bin"), 2<<20, 0)          // not named after the program
	apps := []stApp{{ID: "q", Name: "Qwertium Browser 12.1 (x64)", Pub: "Qwertium LLC"}}
	gone := []goneApp{
		{ID: "z", Name: "Zebra Notes", Loc: filepath.Join(pf, "Zebra Notes"), At: time.Now().Unix()},
		{ID: "y", Name: "Yak Player", Loc: filepath.Join(pf, "Shared"), At: time.Now().Unix()},
	}
	got := map[string]stClean{}
	for _, c := range scanLeftovers(context.Background(), apps, gone, time.Now().Unix()) {
		if under(c.Path, root) {
			got[filepath.Base(filepath.Dir(c.Path))+"/"+filepath.Base(c.Path)] = c
		}
		if c.Safe || c.Group != "Leftovers" || !strings.HasPrefix(c.ID, "left:") {
			t.Fatalf("bad leftover entry: %+v", c)
		}
	}
	want := map[string]int64{"Local/ZzQuuxPlumbus": 6 << 20, "Roaming/Zebra Notes": 2 << 20, "Program Files/Zebra Notes": 2 << 20, "Program Files/ZzDeadShell": 2 << 20}
	for k, b := range want {
		if got[k].Bytes != b {
			t.Errorf("missing or wrong size: %s (%d)", k, got[k].Bytes)
		}
	}
	for k, c := range got {
		if _, ok := want[k]; !ok {
			t.Errorf("must not be offered: %s — %s", k, c.Desc)
		}
		t.Logf("leftover: %s — %s", c.Name, c.Desc)
	}
	if !strings.Contains(got["Roaming/Zebra Notes"].Desc, "you uninstalled") {
		t.Fatalf("desc: %q", got["Roaming/Zebra Notes"].Desc)
	}

	// only what the last scan listed may be removed
	target := got["Local/ZzQuuxPlumbus"]
	storageDB.mu.Lock()
	storageDB.cln = map[string]*stClean{target.ID: &target}
	storageDB.mu.Unlock()
	fresh := filepath.Join(local, "ZzFreshThing")
	freed, log, _ := storageClean(context.Background(), []string{target.ID, "left:" + fresh, "left:" + os.Getenv("SystemRoot")}, nil, true)
	if !pathGone(target.Path) || pathGone(fresh) || freed != 6<<20 {
		t.Fatalf("freed %d, log %v", freed, log)
	}
}

// Windows keeps hiberfil.sys / pagefile.sys locked; their size must still be readable.
func TestStorageLiveLockedFileSize(t *testing.T) {
	if testingLiveOff() {
		t.Skip("set CK_LIVE=1 to run against this PC")
	}
	found := false
	for _, n := range []string{"hiberfil.sys", "pagefile.sys", "swapfile.sys"} {
		for _, d := range listDrives() {
			p := d.Name + `\` + n
			if _, err := os.Lstat(p); err != nil {
				continue
			}
			found = true
			if sz := sysFileSize(p); sz <= 0 {
				t.Errorf("%s exists but its size reads as %d", p, sz)
			} else {
				t.Logf("%s = %s", p, fmtSize(sz))
			}
		}
	}
	if !found {
		t.Skip("no locked system file on this machine")
	}
}
