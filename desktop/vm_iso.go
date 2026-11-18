package main

import (
	"encoding/binary"
	"errors"
	"io"
	"strings"
)

// isoReadFile reads one file from the root directory of an ISO 9660 image.
func isoReadFile(r io.ReaderAt, name string) ([]byte, error) {
	pvd := make([]byte, 2048)
	if _, err := r.ReadAt(pvd, 16*2048); err != nil {
		return nil, err
	}
	if pvd[0] != 1 || string(pvd[1:6]) != "CD001" {
		return nil, errors.New("not an ISO image")
	}
	root := pvd[156 : 156+34]
	ext := int64(binary.LittleEndian.Uint32(root[2:6]))
	size := int64(binary.LittleEndian.Uint32(root[10:14]))
	if size <= 0 || size > 1<<24 {
		return nil, errors.New("bad ISO directory")
	}
	dir := make([]byte, size)
	if _, err := r.ReadAt(dir, ext*2048); err != nil {
		return nil, err
	}
	want := strings.ToUpper(name)
	for off := 0; off < len(dir); {
		l := int(dir[off])
		if l == 0 { // records don't cross sector boundaries
			off = (off/2048 + 1) * 2048
			continue
		}
		if off+l > len(dir) || l < 34 {
			break
		}
		rec := dir[off : off+l]
		nl := int(rec[32])
		if 33+nl <= len(rec) {
			id := string(rec[33 : 33+nl])
			if i := strings.IndexByte(id, ';'); i >= 0 {
				id = id[:i]
			}
			id = strings.TrimSuffix(strings.ToUpper(id), ".")
			if id == want && rec[25]&2 == 0 {
				fe := int64(binary.LittleEndian.Uint32(rec[2:6]))
				fs := int64(binary.LittleEndian.Uint32(rec[10:14]))
				if fs > 256<<20 {
					return nil, errors.New("file too big")
				}
				b := make([]byte, fs)
				if _, err := r.ReadAt(b, fe*2048); err != nil {
					return nil, err
				}
				return b, nil
			}
		}
		off += l
	}
	return nil, errors.New("not found in image")
}
