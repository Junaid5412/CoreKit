package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type inspector struct {
	module   string
	keep     string // our own browser profile folder name (never closed by "clear browser cache")
	mu       sync.Mutex
	scanning bool
	lastPing time.Time
	gotPing  bool
	byeAt    time.Time
	ctx      context.Context
	job      *fixJob
}

// fixJob runs repairs in the background so they survive the browser dropping
// connections when the network changes (renew IP / adapter restart).
type fixEvent struct {
	Type string `json:"type"`
	Kind string `json:"kind,omitempty"`
	Text string `json:"text,omitempty"`
	Pct  int    `json:"pct"`
}
type fixJob struct {
	mu     sync.Mutex
	ID     string
	Events []fixEvent
	Done   bool
	Result json.RawMessage
	Err    string
}

func (in *inspector) jobRunning() bool {
	in.mu.Lock()
	defer in.mu.Unlock()
	if in.job == nil {
		return false
	}
	in.job.mu.Lock()
	defer in.job.mu.Unlock()
	return !in.job.Done
}

func randToken() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func runInspector(module string) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		logLine("!", "Could not start local server: "+err.Error())
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	in := &inspector{ctx: ctx, module: module}
	tok := randToken()
	base := "/" + tok + "/"
	mux := http.NewServeMux()
	mux.HandleFunc(base, in.index)
	mux.HandleFunc(base+"api/ping", in.ping)
	mux.HandleFunc(base+"api/bye", in.bye)
	mux.HandleFunc(base+"api/scan", in.scan)
	mux.HandleFunc(base+"api/save", in.save)
	mux.HandleFunc(base+"api/reveal", in.reveal)
	mux.HandleFunc(base+"api/net/scan", in.netScan)
	mux.HandleFunc(base+"api/net/fix", in.netFix)
	mux.HandleFunc(base+"api/net/fixstatus", in.netFixStatus)
	mux.HandleFunc(base+"api/open", in.open)
	mux.HandleFunc(base+"api/logs/scan", in.logsScan)
	mux.HandleFunc(base+"api/logs/restore", in.logsRestore)
	mux.HandleFunc(base+"api/logs/save", in.logsSave)
	mountRemote(mux, base+"api/remote/", nil)
	mountRemoteRec(mux, base+"api/remote/")
	mountSecurity(mux, base+"api/sec/", in)
	mountStorage(mux, base+"api/storage/", in)
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	url := fmt.Sprintf("http://127.0.0.1:%d%s", ln.Addr().(*net.TCPAddr).Port, base)

	win := launchWindow(url)
	if win != nil {
		in.keep = win.keepTag()
	}
	start := time.Now()
	fellBack := false
	for {
		time.Sleep(300 * time.Millisecond)
		in.mu.Lock()
		last, got, byeAt := in.lastPing, in.gotPing, in.byeAt
		in.mu.Unlock()
		exited := win == nil || win.exited()
		if !byeAt.IsZero() && time.Since(byeAt) > 1500*time.Millisecond && last.Before(byeAt) {
			break
		}
		busy := in.jobRunning()
		if got && exited && time.Since(last) > 12*time.Second && !busy {
			break
		}
		if got && time.Since(last) > 120*time.Second && !busy {
			break
		}
		if !got && time.Since(start) > 25*time.Second {
			if !fellBack {
				fellBack = true
				openDefaultBrowser(url)
				start = time.Now()
				continue
			}
			logLine("!", "Interface did not respond.")
			break
		}
	}
	if in.jobRunning() {
		logLine("~", "Waiting for the running repair to finish...")
		for i := 0; i < 600 && in.jobRunning(); i++ {
			time.Sleep(500 * time.Millisecond)
		}
	}
	cancel()
	sctx, c2 := context.WithTimeout(context.Background(), 2*time.Second)
	_ = srv.Shutdown(sctx)
	c2()
	if win != nil {
		win.cleanup()
	}
}

func (in *inspector) index(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if in.module == "net" {
		w.Write(netHTML)
		return
	}
	if in.module == "logs" {
		w.Write(logsHTML)
		return
	}
	if in.module == "remote" {
		w.Write(remoteHTML)
		return
	}
	if in.module == "security" {
		w.Write(securityHTML)
		return
	}
	if in.module == "storage" {
		w.Write(storageHTML)
		return
	}
	w.Write(indexHTML)
}

func (in *inspector) ping(w http.ResponseWriter, r *http.Request) {
	in.mu.Lock()
	in.lastPing = time.Now()
	in.gotPing = true
	in.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func (in *inspector) bye(w http.ResponseWriter, r *http.Request) {
	in.mu.Lock()
	in.byeAt = time.Now()
	in.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------- SSE helpers

type sse struct {
	w   http.ResponseWriter
	fl  http.Flusher
	mu  sync.Mutex
	ctx context.Context
}

func (in *inspector) beginStream(w http.ResponseWriter, r *http.Request) (*sse, context.CancelFunc, bool) {
	in.mu.Lock()
	jobBusy := in.job != nil && func() bool { in.job.mu.Lock(); defer in.job.mu.Unlock(); return !in.job.Done }()
	if in.scanning || jobBusy {
		in.mu.Unlock()
		http.Error(w, "busy", http.StatusConflict)
		return nil, nil, false
	}
	in.scanning = true
	in.mu.Unlock()
	fl, ok := w.(http.Flusher)
	if !ok {
		in.endStream()
		http.Error(w, "streaming unsupported", 500)
		return nil, nil, false
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	ctx, cancel := context.WithCancel(r.Context())
	go func() {
		select {
		case <-in.ctx.Done():
			cancel()
		case <-ctx.Done():
		}
	}()
	return &sse{w: w, fl: fl, ctx: ctx}, cancel, true
}

func (in *inspector) endStream() { in.mu.Lock(); in.scanning = false; in.mu.Unlock() }

func (s *sse) send(ev string, data []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fmt.Fprintf(s.w, "event: %s\ndata: %s\n\n", ev, data)
	s.fl.Flush()
}
func (s *sse) json(ev string, v any) { b, _ := json.Marshal(v); s.send(ev, b) }

// ---------------------------------------------------------------- module 1: health

func runCollector(ctx context.Context, cb func(kind, a, b string)) ([]byte, error) {
	return runPS(ctx, collectorPS, nil, cb)
}

func (in *inspector) scan(w http.ResponseWriter, r *http.Request) {
	s, cancel, ok := in.beginStream(w, r)
	if !ok {
		return
	}
	defer in.endStream()
	defer cancel()
	fmt.Println()
	res, err := runCollector(s.ctx, func(kind, a, b string) {
		switch kind {
		case "P":
			p, _ := strconv.Atoi(a)
			s.json("progress", map[string]any{"pct": p, "label": b})
		case "L":
			logLine(a, b)
		}
	})
	if err != nil {
		logLine("!", "Scan failed: "+err.Error())
		s.json("fail", map[string]string{"error": err.Error()})
		return
	}
	logLine("#", "Scan complete. Report is open in the window.")
	s.send("done", res)
}

// ---------------------------------------------------------------- module 2: internet troubleshooter

var siteRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9.\-]{0,251}[a-z0-9])?$`)

func sanitizeSites(raw string) string {
	out := []string{}
	for _, s := range strings.Split(raw, ",") {
		s = strings.ToLower(strings.TrimSpace(s))
		if i := strings.Index(s, "://"); i >= 0 {
			s = s[i+3:]
		}
		if i := strings.IndexAny(s, "/?#:"); i >= 0 {
			s = s[:i]
		}
		if s != "" && strings.Contains(s, ".") && siteRe.MatchString(s) {
			out = append(out, s)
		}
		if len(out) == 5 {
			break
		}
	}
	return strings.Join(out, ",")
}

var allowedFix = regexp.MustCompile(`^(flushdns|dns:(cloudflare|google|quad9|opendns|auto)|renew-ip|restart-adapter|enable-adapters|sync-time|reset-proxy|clear-cert-cache|update-roots|clear-browser-cache|reset-hosts|reset-stack|reboot)$`)

func (in *inspector) netScan(w http.ResponseWriter, r *http.Request) {
	s, cancel, ok := in.beginStream(w, r)
	if !ok {
		return
	}
	defer in.endStream()
	defer cancel()
	sites := sanitizeSites(r.URL.Query().Get("sites"))
	doSpeed := r.URL.Query().Get("speed") != "0"
	fmt.Println()
	if sites != "" {
		logLine("#", "Extra sites to test: "+sites)
	}
	res, err := runPS(s.ctx, netPS, []string{"-Mode", "scan", "-Sites", sites}, func(kind, a, b string) {
		switch kind {
		case "P":
			p, _ := strconv.Atoi(a)
			s.json("progress", map[string]any{"pct": p, "label": b})
		case "L":
			logLine(a, b)
		}
	})
	if err != nil {
		logLine("!", "Diagnosis failed: "+err.Error())
		s.json("fail", map[string]string{"error": err.Error()})
		return
	}
	var head struct {
		Online bool `json:"online"`
	}
	_ = json.Unmarshal(res, &head)
	speed := []byte("null")
	if doSpeed && head.Online {
		sr := speedImpl(s.ctx, func(phase string, pct int, mbps float64) {
			label := phase
			if mbps > 0 {
				label = fmt.Sprintf("%s  %.1f Mbps", phase, mbps)
			}
			s.json("progress", map[string]any{"pct": pct, "label": label})
		})
		if sr.OK {
			logLine("+", fmt.Sprintf("Speed: down %.1f Mbps  up %.1f Mbps  ping %.0f ms  jitter %.1f ms", sr.Down, sr.Up, sr.Ping, sr.Jitter))
		} else {
			logLine("~", "Speed test unavailable: "+sr.Error)
		}
		speed, _ = json.Marshal(sr)
	}
	logLine("#", "Diagnosis complete. Results are open in the window.")
	s.send("done", []byte(fmt.Sprintf(`{"net":%s,"speed":%s}`, res, speed)))
}

func (in *inspector) netFix(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", 405)
		return
	}
	acts := []string{}
	for _, a := range strings.Split(r.URL.Query().Get("actions"), ",") {
		a = strings.TrimSpace(a)
		if allowedFix.MatchString(a) {
			acts = append(acts, a)
		}
	}
	if len(acts) == 0 {
		http.Error(w, "no valid actions", 400)
		return
	}
	in.mu.Lock()
	if in.scanning || (in.job != nil && func() bool { in.job.mu.Lock(); defer in.job.mu.Unlock(); return !in.job.Done }()) {
		in.mu.Unlock()
		http.Error(w, "busy", http.StatusConflict)
		return
	}
	j := &fixJob{ID: randToken()}
	in.job = j
	keep := in.keep
	in.mu.Unlock()

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
		defer cancel()
		fmt.Println()
		logLine("#", "Repair started: "+strings.Join(acts, ", "))
		res, err := runPS(ctx, netPS, []string{"-Mode", "fix", "-Actions", strings.Join(acts, ","), "-Keep", keep}, func(kind, a, b string) {
			j.mu.Lock()
			defer j.mu.Unlock()
			switch kind {
			case "P":
				p, _ := strconv.Atoi(a)
				j.Events = append(j.Events, fixEvent{Type: "progress", Text: b, Pct: p})
			case "L":
				logLine(a, b)
				j.Events = append(j.Events, fixEvent{Type: "log", Kind: a, Text: b})
			}
		})
		j.mu.Lock()
		if err != nil {
			j.Err = err.Error()
			logLine("!", "Repair failed: "+err.Error())
		} else {
			j.Result = res
			logLine("#", "Repair finished.")
		}
		j.Done = true
		j.mu.Unlock()
	}()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"id": j.ID})
}

func (in *inspector) netFixStatus(w http.ResponseWriter, r *http.Request) {
	in.mu.Lock()
	j := in.job
	in.mu.Unlock()
	if j == nil || j.ID != r.URL.Query().Get("id") {
		http.Error(w, "unknown job", 404)
		return
	}
	since, _ := strconv.Atoi(r.URL.Query().Get("since"))
	j.mu.Lock()
	defer j.mu.Unlock()
	if since < 0 || since > len(j.Events) {
		since = 0
	}
	out := map[string]any{"events": j.Events[since:], "next": len(j.Events), "done": j.Done, "error": j.Err}
	if j.Done && j.Result != nil {
		out["result"] = j.Result
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(out)
}

func (in *inspector) open(w http.ResponseWriter, r *http.Request) {
	openTarget(r.URL.Query().Get("what"))
	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------- reports

var unsafeName = regexp.MustCompile(`[^A-Za-z0-9 _\-\.]+`)

func (in *inspector) save(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", 405)
		return
	}
	var req struct {
		Name string `json:"name"`
		HTML string `json:"html"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<20)).Decode(&req); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	name := unsafeName.ReplaceAllString(req.Name, "")
	if name == "" {
		name = "CoreKit-Report"
	}
	dir := reportsDir()
	path := filepath.Join(dir, name+".html")
	if err := os.WriteFile(path, []byte(req.HTML), 0644); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	logLine("+", "Report saved: "+path)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"path": path})
}

func (in *inspector) reveal(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Path string `json:"path"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	if req.Path != "" && filepath.Dir(req.Path) == reportsDir() {
		revealFile(req.Path)
	}
	w.WriteHeader(http.StatusNoContent)
}

// reportsDir returns a writable "Reports" folder next to the exe (falls back to Documents).
func reportsDir() string {
	if exe, err := os.Executable(); err == nil {
		d := filepath.Join(filepath.Dir(exe), "Reports")
		if os.MkdirAll(d, 0755) == nil {
			probe := filepath.Join(d, ".write-test")
			if os.WriteFile(probe, []byte("x"), 0644) == nil {
				os.Remove(probe)
				return d
			}
		}
	}
	home, _ := os.UserHomeDir()
	d := filepath.Join(home, "Documents", "CoreKit Reports")
	os.MkdirAll(d, 0755)
	return d
}
