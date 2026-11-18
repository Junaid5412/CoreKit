//go:build !windows

package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"syscall"
)

func vmPlatformQemu() (*vmQemu, error) {
	exe, err := exec.LookPath("qemu-system-x86_64")
	if err != nil {
		return nil, errors.New("the emulator is not installed")
	}
	accel := "tcg,thread=multi"
	if f, err := os.OpenFile("/dev/kvm", os.O_RDWR, 0); err == nil {
		f.Close()
		accel = "kvm;tcg,thread=multi"
	}
	return &vmQemu{exe: exe, accel: accel}, nil
}

func vmPlatformHost(h map[string]any) {
	h["fast"] = false
	if os.Getenv("CK_QEMU") == "" {
		if f, err := os.OpenFile("/dev/kvm", os.O_RDWR, 0); err == nil {
			f.Close()
			h["fast"] = true
		}
	}
}

// vmHideWindow: on Linux/Android the emulator dies with CoreKit's engine.
func vmHideWindow(c *exec.Cmd) {
	c.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL, Setpgid: true}
}
func vmHostRAMWindows() int { return 0 }

func diskUsed(st os.FileInfo) int64 {
	if s, ok := st.Sys().(*syscall.Stat_t); ok {
		return int64(s.Blocks) * 512
	}
	return st.Size()
}

func vmFreeSpace() int64 {
	var s syscall.Statfs_t
	os.MkdirAll(vmRoot(), 0700)
	if syscall.Statfs(vmRoot(), &s) != nil {
		return 0
	}
	return int64(s.Bavail) * int64(s.Bsize)
}

func vmMakeSparse(*os.File)            {}
func vmDiskUsedPath(path string) int64 { return -1 }
func vmEnableWHPX() error              { return errors.New("not on this system") }

func vmGetEmulator(ctx context.Context, prog func(got, total int64, verifying bool, speed int64)) error {
	return errors.New("not needed on this system")
}
