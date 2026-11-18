package main

// Checksums and sizes of the files on the vm-images release (.github/workflows/vm-images.yml).
// A download that doesn't match is refused. Empty means "not published yet".
var vmPin = map[string]string{
	"android9-lite.iso":         "6174c1af281bd26efe8cbcd6a521310da6a71dff4c92abe90ee712030768a0f0",
	"data8g.ckt":                "25532cb1a0da25694f3628cd6b9056254e20545fded5d1add45df0e437205c5b",
	"qemu-win64.zip":            "3afb6aed77c43c8aee5b0600a896819f465d843908222371fa71010d88c2f47d",
	"android9-lite.state.gz":    "0bc1243b40d2ad6dc4954c4b37ef70c6c0c4eb15c5d471ef582dcd33b585da1a",
	"android9-lite-started.ckt": "f094dc90c157f13d5af1226a65c122e6c7c8fce4243d909258037a68286ca91b",
	// the Android emulator build the pre-started save was made with (size-hash of libqemu.so)
	"prestart.qemu": "27162625-b40096de9e0e97e1",
}

var vmSize = map[string]int64{
	"android9-lite.iso":         629710848,
	"data8g.ckt":                28084,
	"qemu-win64.zip":            61475989,
	"android9-lite.state.gz":    838693758,
	"android9-lite-started.ckt": 31421740,
}
