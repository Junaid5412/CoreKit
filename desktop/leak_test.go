package main

import "testing"

func TestLeakyCandidate(t *testing.T) {
	cases := map[string]bool{
		"candidate:1 1 udp 2122260223 1f2e3d4c-aaaa.local 54321 typ host": false,
		"candidate:2 1 udp 1686052607 203.0.113.7 54321 typ srflx":        false,
		"candidate:3 1 udp 1686052607 37.210.1.2 54321 typ srflx":         true,
		"candidate:4 1 udp 2122260223 192.168.1.20 54321 typ host":        true,
	}
	for c, want := range cases {
		if leakyCandidate(c, "203.0.113.7") != want {
			t.Errorf("%s -> %v", c, !want)
		}
	}
}
