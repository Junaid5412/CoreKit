package main

// Checksums and sizes of the files on the vm-images release (.github/workflows/vm-images.yml).
// A download that doesn't match is refused. Empty means "not published yet".
var vmPin = map[string]string{
	"android9-mini.iso":         "7d99f4d5c920b319050ea44a2fcce21ccaa017cc32dfa86c117f12d0ae155748",
	"data8g.ckt":                "25532cb1a0da25694f3628cd6b9056254e20545fded5d1add45df0e437205c5b",
	"qemu-win64.zip":            "3afb6aed77c43c8aee5b0600a896819f465d843908222371fa71010d88c2f47d",
	"android9-mini.state.gz":    "e3cb8c264e74cc5265f2fb12b8789e4f310481383bcc4bfa214bc6c812526641",
	"android9-mini-started.ckt": "52b200f75bb09232d4faba48e026fdca34da8934456685918c6968d5bfc9a9c4",
	// the Android emulator build the pre-started save was made with (size-hash of libqemu.so)
	"prestart.qemu": "27162625-b40096de9e0e97e1",
}

var vmSize = map[string]int64{
	"android9-mini.iso":         498143232,
	"data8g.ckt":                28084,
	"qemu-win64.zip":            61475989,
	"android9-mini.state.gz":    306256636,
	"android9-mini-started.ckt": 12631550,
}
