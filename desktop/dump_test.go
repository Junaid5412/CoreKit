package main

import (
	"os"
	"testing"
)

// CK_DUMP=dir go test -run TestDumpScripts  — writes page scripts for browser tests
func TestDumpScripts(t *testing.T) {
	d := os.Getenv("CK_DUMP")
	if d == "" {
		t.Skip()
	}
	os.WriteFile(d+"/collect.js", []byte(collectScript), 0644)
	os.WriteFile(d+"/detect.js", []byte(detectScript), 0644)
	os.WriteFile(d+"/privacy.js", []byte(privacyScript), 0644)
}
