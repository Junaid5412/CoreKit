//go:build android

package main

// Android build (runs as libcorekit.so --remote): the app captures the screen
// (MediaProjection) and posts frames to /frame; input goes back to the app through the
// /glue event stream, where an accessibility service performs it.

import (
	"os"
	"time"
)

func rDeviceName() string {
	if n := os.Getenv("CK_NAME"); n != "" {
		return n
	}
	return "Android phone"
}
func rPlatform() string { return "android" }
func rPrepareHost()     {}
func rCanControl(e *rEngine) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.a11y
}
func rScreenSize(e *rEngine) (int, int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.gW > 0 {
		return e.gW, e.gH
	}
	return 1080, 2340
}
func rInject(e *rEngine, m map[string]any) {
	out := map[string]any{}
	for k, v := range m {
		out[k] = v
	}
	out["t"] = "in"
	e.emitGlue(out)
}
func rQualityChanged(e *rEngine, q string) {
	e.emitGlue(map[string]any{"t": "capture", "on": true, "q": q})
}

type glueCap struct {
	e    *rEngine
	last uint64
}

func rNewCapturer(e *rEngine) rCapturer {
	e.emitGlue(map[string]any{"t": "capture", "on": true, "q": "auto"})
	return &glueCap{e: e}
}
func (g *glueCap) close() { g.e.emitGlue(map[string]any{"t": "capture", "on": false}) }

// grab returns the newest frame the app posted (waits briefly for one).
func (g *glueCap) grab(q rQuality) ([]byte, int, int, error) {
	deadline := time.Now().Add(q.every)
	for {
		g.e.mu.Lock()
		seq, f, w, h := g.e.gSeq, g.e.gFrame, g.e.gW, g.e.gH
		g.e.mu.Unlock()
		if seq != g.last && f != nil {
			g.last = seq
			return f, w, h, nil
		}
		if time.Now().After(deadline) {
			return nil, 0, 0, nil
		}
		time.Sleep(10 * time.Millisecond)
	}
}
