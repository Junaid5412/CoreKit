//go:build windows

package main

import _ "embed"

//go:embed testdata/sec_sample.json
var secSampleJSON []byte
