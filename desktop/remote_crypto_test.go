package main

import (
	"bytes"
	"testing"
)

func TestSpakeAgreeAndReject(t *testing.T) {
	if !p256.IsOnCurve(spakeM.x, spakeM.y) || !p256.IsOnCurve(spakeN.x, spakeN.y) || spakeM.x.Cmp(spakeN.x) == 0 {
		t.Fatal("bad M/N")
	}
	run := func(codeA, codeB string) (*sessionKeys, *sessionKeys) {
		a, _ := newSpake('A', codeA)
		b, _ := newSpake('B', codeB)
		ka, err := a.finish(b.msg, "viewer", "shared")
		if err != nil {
			t.Fatal(err)
		}
		kb, err := b.finish(a.msg, "viewer", "shared")
		if err != nil {
			t.Fatal(err)
		}
		return ka, kb
	}
	ka, kb := run("482917", "482917")
	if !bytes.Equal(ka.a2b, kb.a2b) || !bytes.Equal(ka.b2a, kb.b2a) || !bytes.Equal(ka.confA, kb.confA) || !bytes.Equal(ka.confB, kb.confB) {
		t.Fatal("same code must give the same keys")
	}
	if bytes.Equal(ka.a2b, ka.b2a) {
		t.Fatal("directions must differ")
	}
	ka, kb = run("482917", "482918")
	if bytes.Equal(ka.confB, kb.confB) || bytes.Equal(ka.a2b, kb.a2b) {
		t.Fatal("wrong code must not agree")
	}
	// channel round trip + tamper
	s, _ := newDir(ka.a2b)
	o, _ := newDir(ka.a2b)
	c := s.seal([]byte("hello"))
	if p, err := o.open(c); err != nil || string(p) != "hello" {
		t.Fatal("round trip", err)
	}
	c2 := s.seal([]byte("again"))
	c2[3] ^= 1
	if _, err := o.open(c2); err == nil {
		t.Fatal("tampered message accepted")
	}
}
