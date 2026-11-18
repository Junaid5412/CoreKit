//go:build windows

package main

import (
	"archive/zip"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

var (
	procGlobalMemoryStatusEx  = kernel32.NewProc("GlobalMemoryStatusEx")
	procGetDiskFreeSpaceExW   = kernel32.NewProc("GetDiskFreeSpaceExW")
	procGetCompressedFileSize = kernel32.NewProc("GetCompressedFileSizeW")
	procDeviceIoControl       = kernel32.NewProc("DeviceIoControl")
)

func vmQemuDir() string { return filepath.Join(vmRoot(), "qemu") }

func vmPlatformQemu() (*vmQemu, error) {
	exe := filepath.Join(vmQemuDir(), "qemu-system-x86_64.exe")
	if _, err := os.Stat(exe); err != nil {
		return nil, errors.New("the emulator is not downloaded yet")
	}
	// Hyper-V acceleration (Windows Hypervisor Platform) when switched on, else software
	// Nehalem: everything Android x86_64 needs (SSE4.2, POPCNT) and no AVX/XSAVE state,
	// which Hyper-V's platform API can fail to hand over ("failed to get xsave state")
	return &vmQemu{exe: exe, pre: []string{"-L", filepath.Join(vmQemuDir(), "share")}, accel: "whpx,kernel-irqchip=off;tcg,thread=multi", cpu: "Nehalem"}, nil
}

func vmPlatformHost(h map[string]any) {
	h["fast"] = vmWHPXOn()
	h["needsEmulator"] = true
	h["emulatorPublished"] = vmEmuSHA != ""
}

// vmWHPXOn: is the Windows Hypervisor Platform feature enabled?
func vmWHPXOn() bool {
	_, err := os.Stat(filepath.Join(os.Getenv("SystemRoot"), "System32", "WinHvPlatform.dll"))
	return err == nil
}

// vmEnableWHPX switches on the Windows Hypervisor Platform (needs a restart).
func vmEnableWHPX() error {
	c := exec.Command(filepath.Join(os.Getenv("SystemRoot"), "System32", "dism.exe"), "/online", "/enable-feature", "/featurename:HypervisorPlatform", "/all", "/norestart")
	vmHideWindow(c)
	out, err := c.CombinedOutput()
	if err != nil && !strings.Contains(string(out), "3010") {
		return errors.New("Windows did not allow it. Run CoreKit as administrator.")
	}
	return nil
}

// QEMU for Windows, repackaged by CoreKit's build (tools/vm) and pinned by hash.
var vmEmuURL = vmRelease + "qemu-win64.zip"
var vmEmuSHA = vmPin["qemu-win64.zip"]

func vmGetEmulator(ctx context.Context, prog func(got, total int64, verifying bool, speed int64)) error {
	if vmEmuSHA == "" {
		return errors.New("the emulator package is not published yet")
	}
	zp := filepath.Join(vmRoot(), "qemu-win64.zip")
	if err := vmFetch(ctx, vmEmuURL, vmEmuSHA, zp, prog); err != nil {
		return err
	}
	tmp := vmQemuDir() + ".new"
	os.RemoveAll(tmp)
	zr, err := zip.OpenReader(zp)
	if err != nil {
		os.Remove(zp)
		return errors.New("the emulator package is damaged")
	}
	defer zr.Close()
	for _, f := range zr.File {
		name := filepath.FromSlash(f.Name)
		if strings.Contains(name, "..") {
			continue
		}
		dst := filepath.Join(tmp, name)
		if f.FileInfo().IsDir() {
			os.MkdirAll(dst, 0700)
			continue
		}
		os.MkdirAll(filepath.Dir(dst), 0700)
		rc, err := f.Open()
		if err != nil {
			return err
		}
		out, err := os.Create(dst)
		if err != nil {
			rc.Close()
			return err
		}
		_, err = io.Copy(out, rc)
		rc.Close()
		out.Close()
		if err != nil {
			return err
		}
	}
	os.RemoveAll(vmQemuDir())
	if err := os.Rename(tmp, vmQemuDir()); err != nil {
		return err
	}
	zr.Close()
	os.Remove(zp)
	return nil
}

func vmHideWindow(c *exec.Cmd) {
	c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
}

func vmHostRAMWindows() int {
	var m struct {
		Length   uint32
		Load     uint32
		Total    uint64
		Avail    uint64
		TotPage  uint64
		AvPage   uint64
		TotVirt  uint64
		AvVirt   uint64
		AvExtVir uint64
	}
	m.Length = uint32(unsafe.Sizeof(m))
	if r, _, _ := procGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&m))); r == 0 {
		return 0
	}
	return int(m.Total / (1 << 20))
}

func vmFreeSpace() int64 {
	os.MkdirAll(vmRoot(), 0700)
	p, _ := syscall.UTF16PtrFromString(vmRoot())
	var free uint64
	if r, _, _ := procGetDiskFreeSpaceExW.Call(uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&free)), 0, 0); r == 0 {
		return 0
	}
	return int64(free)
}

func diskUsed(st os.FileInfo) int64 { return st.Size() }

// vmDiskUsedPath reports the real (sparse) size of a file on NTFS.
func vmDiskUsedPath(path string) int64 {
	p, _ := syscall.UTF16PtrFromString(path)
	var hi uint32
	lo, _, _ := procGetCompressedFileSize.Call(uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&hi)))
	if uint32(lo) == 0xFFFFFFFF {
		return -1
	}
	return int64(hi)<<32 | int64(uint32(lo))
}

// vmMakeSparse marks a file sparse so an 8 GB disk only uses what is written.
func vmMakeSparse(f *os.File) {
	var n uint32
	procDeviceIoControl.Call(f.Fd(), 0x900c4, 0, 0, 0, 0, uintptr(unsafe.Pointer(&n)), 0)
}
