package main

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

// waitEv reads events from a subscriber until one matches.
func waitEv(t *testing.T, s *rSub, what string, match func(map[string]any) bool) map[string]any {
	t.Helper()
	deadline := time.After(8 * time.Second)
	for {
		select {
		case b := <-s.ch:
			var m map[string]any
			json.Unmarshal(b, &m)
			if match(m) {
				return m
			}
		case <-s.kick:
			if f, _ := s.frame.Swap([]byte(nil)).([]byte); len(f) > 0 {
				var m map[string]any
				json.Unmarshal(f, &m)
				if match(m) {
					return m
				}
			}
		case <-deadline:
			t.Fatalf("timed out waiting for %s", what)
		}
	}
}

func TestRemoteSessionEndToEnd(t *testing.T) {
	host, viewer := newREngine(), newREngine()
	host.name, viewer.name = "HostPC", "ViewerPhone"
	hs, vs := host.subscribe(false), viewer.subscribe(false)
	if err := host.startHosting(); err != nil {
		t.Fatal(err)
	}
	defer host.shutdown()
	addr := fmt.Sprintf("127.0.0.1:%d", host.port)

	// wrong code: refused before any approval prompt
	wrong := "000000"
	if host.code == wrong {
		wrong = "111111"
	}
	viewer.connect(wrong, addr)
	m := waitEv(t, vs, "connfail", func(m map[string]any) bool { return m["t"] == "connfail" })
	if m["msg"] == "" {
		t.Fatal("no message")
	}
	time.Sleep(150 * time.Millisecond)
	if host.pending != nil {
		t.Fatal("wrong code reached the approval prompt")
	}

	// right code: host is asked, allows, frames flow
	viewer.connect(host.code, addr)
	req := waitEv(t, hs, "request", func(m map[string]any) bool { return m["t"] == "request" })
	if req["peer"].(map[string]any)["name"] != "ViewerPhone" {
		t.Fatalf("peer name: %v", req)
	}
	host.answer(req["id"].(string), true)
	waitEv(t, vs, "viewer session", func(m map[string]any) bool {
		s, _ := m["session"].(map[string]any)
		return m["t"] == "state" && s != nil && s["role"] == "viewer"
	})
	fr := waitEv(t, vs, "frame", func(m map[string]any) bool { return m["t"] == "frame" })
	if fr["w"].(float64) != 1280 || len(fr["d"].(string)) < 100 {
		t.Fatalf("frame: %v %d", fr["w"], len(fr["d"].(string)))
	}

	// input reaches the shared device
	viewer.command(map[string]any{"t": "in", "k": "click", "b": 0.0, "x": 0.5, "y": 0.25})
	ok := false
	for i := 0; i < 50 && !ok; i++ {
		time.Sleep(40 * time.Millisecond)
		host.mu.Lock()
		ok = len(host.inputs) > 0 && host.inputs[0]["k"] == "click"
		host.mu.Unlock()
	}
	if !ok {
		t.Fatal("input did not arrive")
	}

	// call signalling is relayed both ways
	viewer.command(map[string]any{"t": "sig", "data": map[string]any{"type": "ring", "video": true}})
	waitEv(t, hs, "sig at host", func(m map[string]any) bool {
		d, _ := m["data"].(map[string]any)
		return m["t"] == "sig" && d["type"] == "ring"
	})
	host.command(map[string]any{"t": "sig", "data": map[string]any{"type": "answer"}})
	waitEv(t, vs, "sig at viewer", func(m map[string]any) bool {
		d, _ := m["data"].(map[string]any)
		return m["t"] == "sig" && d["type"] == "answer"
	})

	// a second viewer is refused while busy
	other := newREngine()
	ot := other.subscribe(false)
	other.connect(host.code, addr)
	waitEv(t, ot, "busy", func(m map[string]any) bool { return m["t"] == "connfail" })

	// the shared side ends it; the viewer is told
	host.disconnect("")
	waitEv(t, vs, "bye", func(m map[string]any) bool { return m["t"] == "bye" })
	time.Sleep(100 * time.Millisecond)
	if host.session() != nil || viewer.session() != nil {
		t.Fatal("session not cleared")
	}
}

func TestRemoteDenied(t *testing.T) {
	host, viewer := newREngine(), newREngine()
	hs, vs := host.subscribe(false), viewer.subscribe(false)
	if err := host.startHosting(); err != nil {
		t.Fatal(err)
	}
	defer host.shutdown()
	viewer.connect(host.code, fmt.Sprintf("127.0.0.1:%d", host.port))
	req := waitEv(t, hs, "request", func(m map[string]any) bool { return m["t"] == "request" })
	host.answer(req["id"].(string), false)
	m := waitEv(t, vs, "declined", func(m map[string]any) bool { return m["t"] == "connfail" })
	t.Log(m["msg"])
}
