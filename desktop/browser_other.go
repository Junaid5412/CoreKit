//go:build !windows

package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	engineFile  = "xray"
	engineAsset = "Xray-linux-64.zip"
)

func appDataRoot() string {
	d := filepath.Join(os.TempDir(), "corekit-test")
	os.MkdirAll(d, 0700)
	return d
}

// test builds: no encryption (DPAPI is Windows-only)
func protect(b []byte) ([]byte, error) { return append([]byte("T1"), b...), nil }
func unprotect(b []byte) ([]byte, error) {
	if len(b) < 2 || string(b[:2]) != "T1" {
		return nil, errors.New("bad data")
	}
	return b[2:], nil
}

func engineCommand(exe string, args ...string) *exec.Cmd { return exec.Command(exe, args...) }
func bindToJob(c *exec.Cmd)                              {}
func findBrowserPaths() (string, string)                 { return "/usr/bin/msedge", "/usr/bin/chrome" }

var (
	mockMu      sync.Mutex
	mockRunning = map[string]bool{}
	mockEngine  = false
)

func launchUnelevated(exe string, args []string, flags uint32) error {
	for _, a := range args {
		if strings.HasPrefix(a, "--user-data-dir=") {
			mockMu.Lock()
			mockRunning[strings.TrimPrefix(a, "--user-data-dir=")] = true
			mockMu.Unlock()
		}
	}
	logLine("#", "launch "+filepath.Base(exe)+" "+strings.Join(args, " "))
	return nil
}
func profileRunning(dir string) bool { mockMu.Lock(); defer mockMu.Unlock(); return mockRunning[dir] }
func closeProfile(dir string)        { mockMu.Lock(); delete(mockRunning, dir); mockMu.Unlock() }

func init() {
	engineEnsureHook = func(p *brProxy) (int, error) {
		if !mockEngine {
			return 0, errNeedEngine
		}
		if _, _, _, err := parseProxy(p.Link); err != nil {
			return 0, err
		}
		return 31000, nil
	}
	engineVersionHook = func() string {
		if mockEngine {
			return "Xray 25.10.15"
		}
		return ""
	}
	engineInstallHook = func(progress func(int, string)) (string, error) {
		for i := 0; i <= 100; i += 10 {
			progress(i, "Downloading")
			time.Sleep(120 * time.Millisecond)
		}
		mockEngine = true
		return "Xray 25.10.15", nil
	}
	proxyTestHook = func(p *brProxy, port int) brTest {
		time.Sleep(700 * time.Millisecond)
		return brTest{OK: true, Ms: 142, IP: "203.0.113.7", Country: "DE", Hidden: true, At: time.Now().Unix()}
	}
}
