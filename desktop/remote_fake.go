//go:build !windows && !android

package main

// Desktop Linux / test build: a synthetic screen and recorded input, so the remote
// engine and its page can be exercised without real capture.

import (
	"bytes"
	"image"
	"image/color"
	"image/jpeg"
	"os"
	"sync/atomic"
	"time"
)

func rDeviceName() string {
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return "Linux PC"
}
func rPlatform() string                    { return "linux" }
func rPrepareHost()                        {}
func rScreenSize(e *rEngine) (int, int)    { return 1280, 720 }
func rCanControl(e *rEngine) bool          { return true }
func rQualityChanged(e *rEngine, q string) {}

func rInject(e *rEngine, m map[string]any) {
	e.mu.Lock()
	e.inputs = append(e.inputs, m)
	e.mu.Unlock()
}

type fakeCap struct{ n atomic.Int64 }

func rNewCapturer(e *rEngine) rCapturer { return &fakeCap{} }
func (f *fakeCap) close()               {}

// grab draws a moving test pattern (so the viewer can see frames flowing).
func (f *fakeCap) grab(q rQuality) ([]byte, int, int, error) {
	n := f.n.Add(1)
	w, h := 1280, 720
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	bar := int(n*16) % w
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			c := color.RGBA{uint8(14 + x*30/w), uint8(20 + y*40/h), 30, 255}
			if x/80%2 == y/80%2 {
				c = color.RGBA{18, 26, 36, 255}
			}
			if x >= bar && x < bar+40 {
				c = color.RGBA{45, 212, 191, 255}
			}
			img.Pix[(y*w+x)*4], img.Pix[(y*w+x)*4+1], img.Pix[(y*w+x)*4+2], img.Pix[(y*w+x)*4+3] = c.R, c.G, c.B, 255
		}
	}
	var b bytes.Buffer
	jpeg.Encode(&b, img, &jpeg.Options{Quality: q.jpegQ})
	_ = time.Now
	return b.Bytes(), w, h, nil
}
