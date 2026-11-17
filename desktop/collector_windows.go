//go:build windows

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

// runPS runs an embedded PowerShell script and streams its P/L lines; returns the R json.
func runPS(ctx context.Context, scriptBody []byte, args []string, cb func(kind, a, b string)) ([]byte, error) {
	f, err := os.CreateTemp("", "corekit-*.ps1")
	if err != nil {
		return nil, err
	}
	script := f.Name()
	defer os.Remove(script)
	f.Write(scriptBody)
	f.Close()

	ps := filepath.Join(os.Getenv("SystemRoot"), `System32\WindowsPowerShell\v1.0\powershell.exe`)
	cmd := exec.CommandContext(ctx, ps, append([]string{"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", script}, args...)...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	var result []byte
	sc := bufio.NewScanner(out)
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	for sc.Scan() {
		line := strings.TrimPrefix(strings.TrimRight(sc.Text(), "\r"), "\ufeff")
		parts := strings.SplitN(line, "|", 3)
		switch {
		case parts[0] == "R" && len(line) > 2:
			result = []byte(line[2:])
		case len(parts) == 3 && (parts[0] == "P" || parts[0] == "L"):
			cb(parts[0], parts[1], parts[2])
		}
	}
	werr := cmd.Wait()
	if ctx.Err() != nil {
		return nil, errors.New("cancelled")
	}
	if result == nil {
		msg := strings.TrimSpace(stderr.String())
		if len(msg) > 400 {
			msg = msg[len(msg)-400:]
		}
		return nil, fmt.Errorf("collector returned no data (%v) %s", werr, msg)
	}
	if !json.Valid(result) {
		return nil, errors.New("collector returned invalid data")
	}
	return result, nil
}
