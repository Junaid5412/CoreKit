package main

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"time"
)

// Activity Log module: reads Windows' own audit records (sign-ins, programs, file
// changes, deletions, USB) so the user can see who used this PC and when. All work
// is done by activity.ps1; this just streams its output to the page.

func (in *inspector) logsScan(w http.ResponseWriter, r *http.Request) {
	days := 7
	if d, err := strconv.Atoi(r.URL.Query().Get("days")); err == nil {
		days = d
	}
	if days < 1 {
		days = 1
	} else if days > 90 {
		days = 90
	}
	s, cancel, ok := in.beginStream(w, r)
	if !ok {
		return
	}
	defer in.endStream()
	defer cancel()
	res, err := runPS(s.ctx, activityPS, []string{"-days", strconv.Itoa(days)}, func(kind, a, b string) {
		switch kind {
		case "P":
			p, _ := strconv.Atoi(a)
			s.json("progress", map[string]any{"pct": p, "label": b})
		case "L":
			logLine(a, b)
		}
	})
	if err != nil {
		logLine("!", "Activity log failed: "+err.Error())
		s.json("fail", map[string]string{"error": err.Error()})
		return
	}
	s.send("done", res)
}

// restoreToken is "<drive>|<SID folder>|$I<name>" — exactly what activity.ps1 emitted.
var restoreToken = regexp.MustCompile(`^[A-Za-z]\|S-[0-9\-]+\|\$I[A-Za-z0-9][A-Za-z0-9.]*$`)

func (in *inspector) logsRestore(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", 405)
		return
	}
	var req struct {
		Token string `json:"token"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req) != nil || !restoreToken.MatchString(req.Token) {
		writeJSON(w, map[string]string{"error": "This item can no longer be restored."})
		return
	}
	res, err := runPS(r.Context(), activityRestorePS, []string{"-token", req.Token}, func(_, _, _ string) {})
	if err != nil || len(res) == 0 {
		writeJSON(w, map[string]string{"error": "Restore could not run."})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(res)
}

func (in *inspector) logsSave(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", 405)
		return
	}
	var req struct {
		Text string `json:"text"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<20)).Decode(&req) != nil {
		http.Error(w, "bad", 400)
		return
	}
	path := filepath.Join(reportsDir(), "CoreKit-Activity-"+time.Now().Format("2006-01-02-150405")+".csv")
	if err := os.WriteFile(path, []byte(req.Text), 0644); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	logLine("+", "Activity report saved: "+path)
	writeJSON(w, map[string]string{"path": path})
}
