package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestStorageRecommend(t *testing.T) {
	now := time.Now().Unix()
	res := &stResult{
		Drives: []stDrive{{Name: "C:", Total: 100 << 30, Free: 20 << 30, Used: 80 << 30, Kind: "system"}},
		Apps: []stApp{
			{ID: "old", Name: "Old App", Size: 200 << 20, LastUsed: now - 200*86400, Removable: true},
			{ID: "recent", Name: "Recent", Size: 200 << 20, LastUsed: now - 2*86400, Removable: true},
			{ID: "bloat", Name: "McAfee LiveSafe", Pub: "McAfee", Size: 500 << 20, Removable: true},
			{ID: "sys", Name: "System thing", Size: 500 << 20, System: true, Removable: false},
		},
		Clean: []stClean{
			{ID: "temp", Name: "Temp", Bytes: 1 << 30, Safe: true},
			{ID: "old-dl", Name: "Old downloads", Bytes: 2 << 30, Safe: false},
		},
		Big: []stBig{{Path: `C:\big.iso`, Name: "big.iso", Bytes: 4 << 30, Kind: "file"}},
	}
	for i := range res.Apps { // bloat detection is applied by the collector; mimic it
		if b, why := isWinBloat(res.Apps[i].Name, res.Apps[i].Pub); b {
			res.Apps[i].Bloat, res.Apps[i].BloatWhy = b, why
		}
	}
	finishStorage(res, now)

	if res.Reclaim != 1<<30 { // only the safe cleanable counts toward reclaim
		t.Fatalf("reclaim = %d, want %d", res.Reclaim, 1<<30)
	}
	has := map[string]stRec{}
	for _, r := range res.Recs {
		has[r.Target] = r
	}
	if _, ok := has["temp"]; !ok {
		t.Error("safe cleanable should be recommended")
	}
	if _, ok := has["old"]; !ok {
		t.Error("app unused 200 days should be recommended")
	}
	if _, ok := has["recent"]; ok {
		t.Error("recently used app should NOT be recommended")
	}
	if _, ok := has["bloat"]; !ok {
		t.Error("bloatware should be recommended")
	}
	if r, ok := has[`C:\big.iso`]; !ok || r.Kind != "big-file" {
		t.Error("big file should be flagged")
	}
	// clean recs come first (safe)
	if len(res.Recs) > 0 && res.Recs[0].Kind != "clean" {
		t.Errorf("safe clean recs should sort first, got %s", res.Recs[0].Kind)
	}
}

func TestWinBloat(t *testing.T) {
	for _, c := range []struct {
		name, pub string
		want      bool
	}{
		{"McAfee LiveSafe", "McAfee", true},
		{"Candy Crush Saga", "King", true},
		{"Visual Studio Code", "Microsoft", false},
		{"Google Chrome", "Google", false},
	} {
		if got, _ := isWinBloat(c.name, c.pub); got != c.want {
			t.Errorf("isWinBloat(%q) = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestStorageScanShape(t *testing.T) { // the preview/other build path must return a usable shape
	res, err := storageScan(context.Background(), func(int, string) {})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Drives) == 0 || res.Apps == nil || res.Clean == nil || res.Recs == nil {
		t.Fatalf("empty slices in result: %+v", res)
	}
	b := jsonOf(t, res)
	for _, k := range []string{`"drives"`, `"apps"`, `"clean"`, `"recs"`, `"reclaim"`, `"total"`} {
		if !strings.Contains(b, k) {
			t.Errorf("result JSON missing %s", k)
		}
	}
}

func jsonOf(t *testing.T, v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
