//go:build windows

package main

// Deleting on Windows, the careful way: recoverable deletes go to the Recycle Bin, every delete is
// checked afterwards, and the folder browser refuses anything Windows or installed programs need.

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

var spSHFileOperation = shell32.NewProc("SHFileOperationW")

// SHFILEOPSTRUCTW (64-bit layout)
type shFileOp struct {
	hwnd    uintptr
	wFunc   uint32
	pFrom   *uint16
	pTo     *uint16
	fFlags  uint16
	aborted int32
	nameMap uintptr
	title   *uint16
}

// recycle moves files or folders to the Recycle Bin. Windows deletes an item outright only when
// it is too big for the bin.
func recycle(paths []string) {
	if len(paths) == 0 {
		return
	}
	var list []uint16
	for _, p := range paths {
		u, err := syscall.UTF16FromString(p) // includes the terminating NUL
		if err != nil {
			continue
		}
		list = append(list, u...)
	}
	if len(list) == 0 {
		return
	}
	list = append(list, 0) // the list ends with a second NUL
	done := make(chan struct{})
	go func() {
		defer close(done)
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		procCoInitializeEx.Call(0, 0x2) // apartment threaded
		op := shFileOp{
			wFunc:  3,                                 // FO_DELETE
			pFrom:  &list[0],                          //
			fFlags: 0x0040 | 0x0010 | 0x0004 | 0x0400, // ALLOWUNDO | NOCONFIRMATION | SILENT | NOERRORUI
		}
		spSHFileOperation.Call(uintptr(unsafe.Pointer(&op)))
		runtime.KeepAlive(list)
	}()
	<-done
}

func pathGone(p string) bool {
	_, err := os.Lstat(p)
	return os.IsNotExist(err)
}

// measure returns the size of a file or folder.
func measure(ctx context.Context, p string) int64 {
	st, err := os.Lstat(p)
	if err != nil {
		return 0
	}
	if st.IsDir() {
		return stDirSize(ctx, p, time.Now().Add(30*time.Second))
	}
	return st.Size()
}

// deletePaths removes the given items and reports what really went: how many, how many bytes,
// and the names that could not be removed (usually because a program has them open).
func deletePaths(ctx context.Context, paths []string, permanent bool) (n int, freed int64, failed []string) {
	sizes := make([]int64, len(paths))
	for i, p := range paths {
		sizes[i] = measure(ctx, p)
	}
	if permanent {
		for _, p := range paths {
			_ = os.RemoveAll(p)
		}
	} else {
		for i := 0; i < len(paths); i += 40 {
			recycle(paths[i:min(i+40, len(paths))])
		}
	}
	for i, p := range paths {
		if pathGone(p) {
			n++
			freed += sizes[i]
			continue
		}
		if left := measure(ctx, p); left < sizes[i] {
			freed += sizes[i] - left // a folder that was only partly removed
		}
		failed = append(failed, filepath.Base(p))
	}
	return
}

func isReparse(p string) bool {
	st, err := os.Lstat(p)
	if err != nil {
		return false
	}
	if st.Mode()&os.ModeSymlink != 0 {
		return true
	}
	if d, ok := st.Sys().(*syscall.Win32FileAttributeData); ok {
		return d.FileAttributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0
	}
	return false
}

func hiddenSystem(p string) bool {
	st, err := os.Lstat(p)
	if err != nil {
		return false
	}
	if d, ok := st.Sys().(*syscall.Win32FileAttributeData); ok {
		return d.FileAttributes&syscall.FILE_ATTRIBUTE_SYSTEM != 0
	}
	return false
}

func under(p, root string) bool {
	if root == "" {
		return false
	}
	p, root = strings.ToLower(filepath.Clean(p)), strings.ToLower(filepath.Clean(root))
	return p == root || strings.HasPrefix(p, strings.TrimRight(root, `\`)+`\`)
}

func samePath(a, b string) bool {
	return b != "" && strings.EqualFold(filepath.Clean(a), filepath.Clean(b))
}

// canDelete is the folder browser's guard. It allows the user's own files and other drives, and
// refuses Windows, installed programs, system files, and the folders everything else hangs off.
func canDelete(p string) bool {
	p = filepath.Clean(p)
	if !filepath.IsAbs(p) || len(p) < 4 || isReparse(p) || hiddenSystem(p) {
		return false
	}
	parts := pathParts(p[2:]) // after "C:"
	if len(parts) == 0 {
		return false
	}
	for _, root := range []string{os.Getenv("SystemRoot"), os.Getenv("ProgramFiles"), os.Getenv("ProgramFiles(x86)"), os.Getenv("ProgramW6432"), os.Getenv("ProgramData")} {
		if under(p, root) {
			return false
		}
	}
	switch strings.ToLower(parts[0]) {
	case "$recycle.bin", "system volume information", "recovery", "boot", "efi", "$winreagent", "$windows.~bt", "$windows.~ws", "windows.old", "documents and settings", "msocache", "perflogs", "config.msi":
		return false
	case "windows", "program files", "program files (x86)", "programdata", "intel", "amd", "nvidia", "drivers", "swsetup", "inetpub":
		if len(parts) < 3 { // also a second Windows or program folder on another drive
			return false
		}
	}
	if under(p, appDataRoot()) { // CoreKit's own data: only a browser profile or what is inside one
		profiles := filepath.Join(appDataRoot(), "Browser", "Profiles")
		return under(p, profiles) && !samePath(p, profiles)
	}
	sys := strings.EqualFold(p[:2], os.Getenv("SystemDrive"))
	home := os.Getenv("USERPROFILE")
	if sys && strings.EqualFold(parts[0], "users") {
		if !under(p, home) || samePath(p, home) {
			return false // other accounts, and the profile folder itself
		}
		rel := pathParts(strings.TrimPrefix(p[len(filepath.Clean(home)):], `\`))
		if len(rel) == 0 {
			return false
		}
		if strings.EqualFold(rel[0], "AppData") {
			if len(rel) < 3 { // AppData, AppData\Local, AppData\Roaming, AppData\LocalLow
				return false
			}
			if len(rel) == 3 {
				switch strings.ToLower(rel[2]) {
				case "microsoft", "packages", "programs", "temp", "publishers", "comms", "connecteddevicesplatform":
					return false
				}
			}
			switch strings.ToLower(rel[2]) {
			case "microsoft", "packages", "programs": // one level down is still a program's own home
				if len(rel) < 5 {
					return false
				}
			}
			return true
		}
		if len(rel) == 1 { // the folders Windows itself keeps in a profile
			l := strings.ToLower(rel[0])
			switch l {
			case "desktop", "documents", "downloads", "pictures", "music", "videos", "favorites", "links", "contacts", "searches", "saved games", "3d objects", "appdata":
				return false
			}
			return !strings.HasPrefix(l, "ntuser") && !strings.HasPrefix(l, "onedrive")
		}
		return true
	}
	if sys && len(parts) == 1 {
		st, err := os.Lstat(p)
		return err == nil && st.IsDir() // a plain folder someone made on C:, never a root file
	}
	return true
}
