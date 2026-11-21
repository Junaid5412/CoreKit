//go:build windows

package main

// Runs the Storage module against the real Windows of the CI runner (CK_LIVE=1 only).

import (
	"context"
	"os"
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
	freed, log, err := storageClean(ctx, []string{"temp-user"}, nil)
	if err != nil {
		t.Fatalf("clean temp: %v", err)
	}
	t.Logf("cleaned temp: freed %s, %v", fmtSize(freed), log)
}

func testingLiveOff() bool { return os.Getenv("CK_LIVE") != "1" }
