//go:build !windows

package main

import (
	"context"
	"fmt"
	"time"
)

// Linux build is a preview: it shows a representative layout so the shared UI can be worked on,
// and the actions explain that the native Linux host is not finished yet.

func storageScan(ctx context.Context, progress func(int, string)) (*stResult, error) {
	progress(20, "Reading drives")
	res := &stResult{Platform: "linux"}
	res.Drives = []stDrive{
		{Name: "/", Label: "System", Total: 512 << 30, Free: 180 << 30, Used: 332 << 30, Kind: "system",
			Parts: []stPart{{"Programs", 90 << 30, "#38bdf8"}, {"System", 60 << 30, "#a78bfa"}, {"Home", 150 << 30, "#2dd4bf"}, {"Other", 32 << 30, "#64748b"}}},
	}
	progress(60, "Listing programs")
	res.Apps = []stApp{
		{ID: "a1", Name: "Example Browser", Pub: "Example", Ver: "1.0", Size: 420 << 20, Source: "program", Kind: "exe", Removable: true, Drive: "/"},
		{ID: "a2", Name: "Old Game Trial", Pub: "Games Inc", Ver: "2.3", Size: 2 << 30, Source: "program", Kind: "exe", Removable: true, Bloat: true, BloatWhy: "A pre-installed game trial.", Drive: "/"},
	}
	res.Clean = []stClean{
		{ID: "temp-user", Name: "Temporary files", Desc: "Leftover temp files.", Bytes: 1200 << 20, Safe: true, Group: "Windows"},
		{ID: "cache", Name: "App caches", Desc: "Rebuilt automatically.", Bytes: 800 << 20, Safe: true, Group: "Apps"},
		{ID: "left:/home/user/.config/oldapp", Name: "oldapp  (.config)", Desc: "No installed program matches this folder. Last changed 8 months ago.", Bytes: 300 << 20, Group: "Leftovers", Path: "/home/user/.config/oldapp"},
	}
	progress(90, "Working out recommendations")
	finishStorage(res, time.Now().Unix())
	res.Note = "Linux support is a preview."
	return res, nil
}

func storageClean(ctx context.Context, ids []string, pick map[string][]string, permanent bool) (int64, []string, error) {
	return 0, []string{"Cleaning is not available in the Linux preview yet."}, nil
}

func storageUninstall(ctx context.Context, ids []string) []map[string]any {
	out := []map[string]any{}
	for _, id := range ids {
		out = append(out, map[string]any{"id": id, "ok": false, "msg": "Uninstall is not available in the Linux preview yet."})
	}
	return out
}

func storageDrill(ctx context.Context, path string) ([]stBig, error) {
	return nil, fmt.Errorf("folder details are not available in the Linux preview yet")
}

func storageDeleteFiles(ctx context.Context, ids, paths []string, permanent bool) (int64, int, []string) {
	return 0, 0, []string{"Deleting files is not available in the Linux preview yet."}
}
