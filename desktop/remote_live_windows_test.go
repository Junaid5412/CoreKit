//go:build windows

package main

// Remote Access against the real Windows screen of the CI runner (CK_LIVE=1 only):
// a viewer pairs with this PC, the PC allows it, and real screen frames must arrive.

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"image/jpeg"
	"testing"
	"time"
)

func TestRemoteLiveWindowsScreen(t *testing.T) {
	live(t)
	host, viewer := newREngine(), newREngine()
	host.name, viewer.name = "RunnerPC", "TestPhone"
	hs, vs := host.subscribe(false), viewer.subscribe(false)
	if err := host.startHosting(); err != nil {
		t.Fatal(err)
	}
	defer host.shutdown()
	defer viewer.shutdown()
	viewer.connect(host.code, fmt.Sprintf("127.0.0.1:%d", host.port))
	req := waitEv(t, hs, "request", func(m map[string]any) bool { return m["t"] == "request" })
	host.answer(req["id"].(string), true)
	st := waitEv(t, vs, "viewer session", func(m map[string]any) bool {
		s, _ := m["session"].(map[string]any)
		return m["t"] == "state" && s != nil && s["role"] == "viewer"
	})
	t.Logf("session: %v", st["session"])
	n, bytesIn := 0, 0
	start := time.Now()
	for time.Since(start) < 6*time.Second {
		fr := waitEv(t, vs, "frame", func(m map[string]any) bool { return m["t"] == "frame" })
		raw, err := base64.StdEncoding.DecodeString(fr["d"].(string))
		if err != nil {
			t.Fatal(err)
		}
		img, err := jpeg.Decode(bytes.NewReader(raw))
		if err != nil {
			t.Fatalf("frame is not a JPEG: %v", err)
		}
		n++
		bytesIn += len(raw)
		if n == 1 {
			b := img.Bounds()
			var sum, cnt uint64
			for y := b.Min.Y; y < b.Max.Y; y += 7 {
				for x := b.Min.X; x < b.Max.X; x += 7 {
					r, g, bl, _ := img.At(x, y).RGBA()
					sum += uint64(r+g+bl) / 3 >> 8
					cnt++
				}
			}
			t.Logf("first frame after %s: %vx%v (%d KB), average brightness %d/255", time.Since(start).Round(time.Millisecond), fr["w"], fr["h"], len(raw)/1024, sum/cnt)
			if fr["w"].(float64) < 320 {
				t.Fatalf("frame too small: %v", fr["w"])
			}
		}
	}
	t.Logf("%d frames in 6 s, %d KB", n, bytesIn/1024)
	if n < 2 {
		t.Fatal("frames stopped after the first one")
	}
	host.disconnect("")
	waitEv(t, vs, "bye", func(m map[string]any) bool { return m["t"] == "bye" })
}
