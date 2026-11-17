package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Session recordings from the Remote Access viewer. The page streams the video in
// one-second pieces (begin → chunk… → end) into the Reports folder, so a long
// recording never sits in memory and a crash still leaves a playable file.

type recFile struct {
	mu   sync.Mutex
	f    *os.File
	path string
	size int64
	last time.Time
}

var (
	recMu    sync.Mutex
	recFiles = map[string]*recFile{}
)

const recMaxBytes = 8 << 30 // 8 GB per recording

func mountRemoteRec(mux *http.ServeMux, prefix string) {
	mux.HandleFunc(prefix+"rec", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		q := r.URL.Query()
		switch q.Get("op") {
		case "begin":
			recSweep()
			name := strings.TrimSpace(unsafeName.ReplaceAllString(q.Get("name"), ""))
			if name == "" || strings.Contains(name, "..") {
				name = "CoreKit-Remote"
			}
			ext := "webm"
			if q.Get("ext") == "mp4" {
				ext = "mp4"
			}
			path := recUniquePath(reportsDir(), name, ext)
			f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
			if err != nil {
				http.Error(w, "could not create the file", 500)
				return
			}
			id := randID()
			recMu.Lock()
			recFiles[id] = &recFile{f: f, path: path, last: time.Now()}
			recMu.Unlock()
			logLine("*", "Remote: recording to "+path)
			writeJSON(w, map[string]string{"id": id})
		case "chunk":
			rf := recGet(q.Get("id"), false)
			if rf == nil {
				http.Error(w, "no such recording", 404)
				return
			}
			rf.mu.Lock()
			defer rf.mu.Unlock()
			if rf.f == nil {
				http.Error(w, "recording closed", 410)
				return
			}
			n, err := io.Copy(rf.f, http.MaxBytesReader(w, r.Body, 64<<20))
			rf.size += n
			rf.last = time.Now()
			if err != nil || rf.size > recMaxBytes {
				http.Error(w, "could not write", 500)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		case "end":
			rf := recGet(q.Get("id"), true)
			if rf == nil {
				http.Error(w, "no such recording", 404)
				return
			}
			rf.mu.Lock()
			defer rf.mu.Unlock()
			if rf.f != nil {
				rf.f.Close()
				rf.f = nil
			}
			if rf.size == 0 {
				os.Remove(rf.path)
				http.Error(w, "nothing was recorded", 400)
				return
			}
			logLine("+", fmt.Sprintf("Remote: recording saved (%d KB): %s", rf.size/1024, rf.path))
			writeJSON(w, map[string]string{"path": rf.path, "label": filepath.Base(rf.path)})
		default:
			http.Error(w, "bad op", 400)
		}
	})
}

func recGet(id string, remove bool) *recFile {
	recMu.Lock()
	defer recMu.Unlock()
	rf := recFiles[id]
	if remove {
		delete(recFiles, id)
	}
	return rf
}

// recSweep closes recordings whose page went away without saying "end".
func recSweep() {
	recMu.Lock()
	defer recMu.Unlock()
	for id, rf := range recFiles {
		rf.mu.Lock()
		if time.Since(rf.last) > 10*time.Minute {
			if rf.f != nil {
				rf.f.Close()
				rf.f = nil
			}
			delete(recFiles, id)
		}
		rf.mu.Unlock()
	}
}

func recUniquePath(dir, name, ext string) string {
	p := filepath.Join(dir, name+"."+ext)
	for i := 2; i < 1000; i++ {
		if _, err := os.Stat(p); os.IsNotExist(err) {
			return p
		}
		p = filepath.Join(dir, fmt.Sprintf("%s (%d).%s", name, i, ext))
	}
	return p
}
