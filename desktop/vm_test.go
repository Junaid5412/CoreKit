package main

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVMWriteDiskFromTemplate(t *testing.T) {
	dst := filepath.Join(t.TempDir(), "data.img")
	if err := vmWriteDisk("testdata/vm_tpl.ckt", dst); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(dst)
	if err != nil || st.Size() != 1<<30 {
		t.Fatalf("size %v %v", st.Size(), err)
	}
	f, _ := os.Open(dst)
	defer f.Close()
	sb := make([]byte, 2)
	f.ReadAt(sb, 1024+0x38) // ext4 superblock magic
	if binary.LittleEndian.Uint16(sb) != 0xEF53 {
		t.Fatalf("no ext4 superblock: %x", sb)
	}
	if u := diskUsed(st); u > 64<<20 {
		t.Fatalf("disk is not sparse: %d bytes used", u)
	}
	if err := vmWriteDisk("vm_test.go", filepath.Join(t.TempDir(), "x")); err == nil {
		t.Fatal("accepted a bad template")
	}
}

// a tiny ISO 9660 image with two files in the root directory
func makeISO(files map[string][]byte) []byte {
	sec := func(n int) int { return n * 2048 }
	img := make([]byte, sec(40))
	pvd := img[sec(16):]
	pvd[0] = 1
	copy(pvd[1:6], "CD001")
	dir := img[sec(18):sec(19)]
	off := 0
	next := 20
	rec := func(name string, ext, size int, isDir bool) {
		l := 33 + len(name)
		if l%2 == 1 {
			l++
		}
		r := dir[off : off+l]
		r[0] = byte(l)
		binary.LittleEndian.PutUint32(r[2:], uint32(ext))
		binary.LittleEndian.PutUint32(r[10:], uint32(size))
		if isDir {
			r[25] = 2
		}
		r[32] = byte(len(name))
		copy(r[33:], name)
		off += l
	}
	rec("\x00", 18, 2048, true)
	rec("\x01", 18, 2048, true)
	for name, data := range files {
		rec(strings.ToUpper(name)+";1", next, len(data), false)
		copy(img[sec(next):], data)
		next += (len(data) + 2047) / 2048
	}
	root := pvd[156:]
	root[0] = 34
	binary.LittleEndian.PutUint32(root[2:], 18)
	binary.LittleEndian.PutUint32(root[10:], 2048)
	return img
}

func TestVMReadISO(t *testing.T) {
	iso := makeISO(map[string][]byte{"kernel": []byte("KERNELDATA"), "initrd.img": bytes.Repeat([]byte("i"), 5000)})
	r := bytes.NewReader(iso)
	k, err := isoReadFile(r, "kernel")
	if err != nil || string(k) != "KERNELDATA" {
		t.Fatalf("kernel: %q %v", k, err)
	}
	i, err := isoReadFile(r, "initrd.img")
	if err != nil || len(i) != 5000 {
		t.Fatalf("initrd: %d %v", len(i), err)
	}
	if _, err := isoReadFile(r, "system.sfs"); err == nil {
		t.Fatal("found a missing file")
	}
}

func TestVMRing(t *testing.T) {
	r := newRing(10)
	r.write([]byte("hello "))
	r.write([]byte("world!!"))
	b, n := r.since(0)
	if string(b) != "lo world!!" || n != 13 {
		t.Fatalf("%q %d", b, n)
	}
	b, n = r.since(11)
	if string(b) != "!!" || n != 13 {
		t.Fatalf("%q %d", b, n)
	}
}

func TestVMInstallErrors(t *testing.T) {
	if !strings.Contains(vmInstallError("Failure [INSTALL_FAILED_NO_MATCHING_ABIS: x]"), "ARM") {
		t.Fatal("abi message")
	}
	if vmInstallError("Failure [INSTALL_FAILED_FOO]") != "Install failed: INSTALL_FAILED_FOO" {
		t.Fatal("generic message")
	}
}
