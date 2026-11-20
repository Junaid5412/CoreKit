//go:build !windows

package main

// Security module outside Windows: the Go host here only serves tests and the UI preview
// (Android has its own Kotlin collector). Fixes are simulated on the sample data.

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

//go:embed testdata/sec_sample.json
var secSampleJSON []byte

func secDir() string {
	d := os.Getenv("CK_SEC_DIR")
	if d == "" {
		d = filepath.Join(os.TempDir(), "corekit-security")
	}
	os.MkdirAll(d, 0700)
	return d
}

func secProtect(b []byte) ([]byte, error)   { return append([]byte{}, b...), nil }
func secUnprotect(b []byte) ([]byte, error) { return append([]byte{}, b...), nil }

func secCollect(ctx context.Context, cb func(kind, a, b string)) ([]byte, error) {
	steps := []string{"Checking Windows protection", "Reading running programs", "Checking start-up entries", "Checking scheduled tasks", "Checking services", "Checking hidden triggers (WMI, IFEO, sign-in hooks)", "Checking downloaded programs", "Verifying digital signatures", "Reading network connections", "Reading Windows Defender history", "Checking hosts file, proxy and certificates", "Listing installed apps"}
	for i, s := range steps {
		cb("P", fmt.Sprint(3+i*92/len(steps)), s)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(120 * time.Millisecond):
		}
	}
	return secSampleJSON, nil
}

type psFix struct {
	OK   bool            `json:"ok"`
	Msg  string          `json:"msg"`
	Undo json.RawMessage `json:"undo"`
}

func secRunFix(ctx context.Context, req map[string]any) (psFix, error) {
	return psFix{OK: true, Msg: "done (preview)"}, nil
}

func secAutorunRemove(ctx context.Context, a autoRef) (json.RawMessage, error) {
	b, _ := json.Marshal(map[string]string{"op": "reg-set", "path": a.Key, "name": a.Name, "data": a.Value})
	return b, nil
}

func secFixSetting(ctx context.Context, key string) (json.RawMessage, error) {
	b, _ := json.Marshal(map[string]string{"op": "note", "key": key})
	return b, nil
}

func secUndo(ctx context.Context, raw json.RawMessage) error { return nil }

func secHarden(ctx context.Context, ids []string) (string, error) {
	return fmt.Sprintf("Turned on: %v (preview)", ids), nil
}

func secBloatAction(ctx context.Context, b secBloat) (string, json.RawMessage, error) {
	return "Removed (preview)", nil, nil
}

func secDefenderScan(ctx context.Context, path string) (string, bool) { return "", false }

func secPIDsOf(path string) []int { return nil }

func secKill(pid int) error { return nil }

func removeFileHard(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

var previewShield = false

func secShieldStatus() map[string]any {
	return map[string]any{"platform": "preview", "installed": previewShield, "running": previewShield, "admin": true, "checked": 0, "blocked": 0, "warned": 0}
}

func secShieldSet(on bool) error { previewShield = on; return nil }

func runShield() int { return 0 }
