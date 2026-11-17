package main

import (
	"context"
	"crypto/tls"
	"io"
	"math"
	"math/rand"
	"net/http"
	"net/http/httptrace"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

type speedResult struct {
	OK     bool    `json:"ok"`
	Down   float64 `json:"down"`
	Up     float64 `json:"up"`
	Ping   float64 `json:"ping"`
	Jitter float64 `json:"jitter"`
	Server string  `json:"server"`
	Error  string  `json:"error,omitempty"`
}

// speedImpl can be replaced by a mock in tests.
var speedImpl = runSpeed

const speedHost = "https://speed.cloudflare.com"

func speedClient() *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{} // HTTP/1.1: one TCP connection per stream
	tr.MaxIdleConnsPerHost = 16
	tr.DisableCompression = true
	return &http.Client{Transport: tr}
}

func round1(v float64) float64 { return math.Round(v*10) / 10 }

// runSpeed measures latency, download and upload against Cloudflare's speed test endpoints.
func runSpeed(ctx context.Context, prog func(phase string, pct int, mbps float64)) speedResult {
	res := speedResult{Server: "Cloudflare"}
	cl := speedClient()

	// ---- latency (time to first byte on a warm connection)
	prog("Latency", 85, 0)
	var samples []float64
	for i := 0; i < 12 && ctx.Err() == nil; i++ {
		var t0, t1 time.Time
		trace := &httptrace.ClientTrace{WroteRequest: func(httptrace.WroteRequestInfo) { t0 = time.Now() }, GotFirstResponseByte: func() { t1 = time.Now() }}
		rctx, c := context.WithTimeout(httptrace.WithClientTrace(ctx, trace), 4*time.Second)
		req, _ := http.NewRequestWithContext(rctx, "GET", speedHost+"/__down?bytes=0", nil)
		resp, err := cl.Do(req)
		if err == nil {
			if v := resp.Header.Get("cf-meta-colo"); v != "" {
				res.Server = "Cloudflare " + v
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if i > 0 && !t0.IsZero() && t1.After(t0) {
				samples = append(samples, float64(t1.Sub(t0).Microseconds())/1000)
			}
		}
		c()
		if err != nil && i == 0 {
			res.Error = "speed test server unreachable"
			return res
		}
	}
	if len(samples) == 0 {
		res.Error = "no latency samples"
		return res
	}
	sorted := append([]float64(nil), samples...)
	sort.Float64s(sorted)
	res.Ping = round1(sorted[len(sorted)/2])
	var jd float64
	for i := 1; i < len(samples); i++ {
		jd += math.Abs(samples[i] - samples[i-1])
	}
	if len(samples) > 1 {
		res.Jitter = round1(jd / float64(len(samples)-1))
	}

	res.Down = round1(transfer(ctx, cl, false, 6, 8*time.Second, func(p float64, mbps float64) { prog("Download", 87+int(p*7), mbps) }))
	res.Up = round1(transfer(ctx, cl, true, 4, 7*time.Second, func(p float64, mbps float64) { prog("Upload", 94+int(p*5), mbps) }))
	res.OK = res.Down > 0 || res.Up > 0
	if !res.OK {
		res.Error = "transfer failed"
	}
	return res
}

type countingReader struct {
	n    *int64
	left int
	buf  []byte
}

func (c *countingReader) Read(p []byte) (int, error) {
	if c.left <= 0 {
		return 0, io.EOF
	}
	n := len(p)
	if n > c.left {
		n = c.left
	}
	if n > len(c.buf) {
		n = len(c.buf)
	}
	copy(p, c.buf[:n])
	c.left -= n
	atomic.AddInt64(c.n, int64(n))
	return n, nil
}

// transfer runs parallel streams for the given duration and returns Mbps (excluding a short warm-up).
func transfer(ctx context.Context, cl *http.Client, upload bool, streams int, dur time.Duration, tick func(p float64, mbps float64)) float64 {
	tctx, cancel := context.WithTimeout(ctx, dur)
	defer cancel()
	var total int64
	payload := make([]byte, 256*1024)
	rand.Read(payload)
	var wg sync.WaitGroup
	for i := 0; i < streams; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, 64*1024)
			for tctx.Err() == nil {
				var req *http.Request
				if upload {
					size := 8 << 20
					req, _ = http.NewRequestWithContext(tctx, "POST", speedHost+"/__up", &countingReader{n: &total, left: size, buf: payload})
					req.ContentLength = int64(size)
					req.Header.Set("Content-Type", "application/octet-stream")
				} else {
					req, _ = http.NewRequestWithContext(tctx, "GET", speedHost+"/__down?bytes=50000000", nil)
				}
				resp, err := cl.Do(req)
				if err != nil {
					if tctx.Err() == nil {
						time.Sleep(200 * time.Millisecond)
					}
					continue
				}
				if upload {
					io.Copy(io.Discard, resp.Body)
				} else {
					for {
						n, err := resp.Body.Read(buf)
						atomic.AddInt64(&total, int64(n))
						if err != nil {
							break
						}
					}
				}
				resp.Body.Close()
			}
		}()
	}
	start := time.Now()
	warm := 1500 * time.Millisecond
	var warmBytes int64 = -1
	var warmAt time.Time
	lastB, lastT := int64(0), start
	ema := 0.0
	tk := time.NewTicker(250 * time.Millisecond)
	defer tk.Stop()
loop:
	for {
		select {
		case <-tctx.Done():
			break loop
		case now := <-tk.C:
			b := atomic.LoadInt64(&total)
			inst := float64(b-lastB) * 8 / now.Sub(lastT).Seconds() / 1e6
			lastB, lastT = b, now
			if ema == 0 {
				ema = inst
			} else {
				ema = ema*0.7 + inst*0.3
			}
			if warmBytes < 0 && now.Sub(start) >= warm {
				warmBytes, warmAt = b, now
			}
			tick(math.Min(1, now.Sub(start).Seconds()/dur.Seconds()), ema)
		}
	}
	wg.Wait()
	end := time.Now()
	b := atomic.LoadInt64(&total)
	if warmBytes < 0 {
		return float64(b) * 8 / end.Sub(start).Seconds() / 1e6
	}
	return float64(b-warmBytes) * 8 / end.Sub(warmAt).Seconds() / 1e6
}
