package main

// Checksums and sizes of the files on the vm-images release (.github/workflows/vm-images.yml).
// A download that doesn't match is refused. Empty means "not published yet".
var vmPin = map[string]string{}

var vmSize = map[string]int64{}
