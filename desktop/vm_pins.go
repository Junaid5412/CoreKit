package main

// Checksums and sizes of the files on the vm-images release (.github/workflows/vm-images.yml).
// A download that doesn't match is refused. Empty means "not published yet".
var vmPin = map[string]string{
	"android9-lite.iso":         "f70c1abb53db3cc50366f408da771495f618759a47dc2b122d363efc6fb5cc81",
	"data8g.ckt":                "e5bbc4c6444dda4103d2fa9be3fd15f47b095602c41d363dc64cfac10081e369",
	"qemu-win64.zip":            "a849dfc6d7ab095d67cf5a83bfdcc3ee51231e0b408897189e0170bd8bb88097",
	"android9-lite.state.gz":    "9542ec6f31e1ba3a695c5022ad1c513c37b18ab84fac2194bf14af9a0388f75b",
	"android9-lite-started.ckt": "2162b40fb3a75a4c54a4fe8d667b60674a0bca2e5d8080435cb17e38495e0977",
	// the Android emulator build the pre-started save was made with (size-hash of libqemu.so)
	"prestart.qemu": "27162625-b40096de9e0e97e1",
}

var vmSize = map[string]int64{
	"android9-lite.iso":         629710848,
	"data8g.ckt":                28086,
	"qemu-win64.zip":            61475989,
	"android9-lite.state.gz":    487668069,
	"android9-lite-started.ckt": 26144131,
}
