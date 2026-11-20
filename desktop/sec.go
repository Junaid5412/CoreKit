package main

// Security module: Deep Scan, investigate, one-tap fix with Quarantine, history, trusted
// list, bloatware and Live Shield. Windows collects with security.ps1 (sec_windows.go);
// the analysis is sec_rules.go. Android has its own collector producing the same JSON.

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed scripts/security.ps1
var securityPS []byte

//go:embed scripts/security_fix.ps1
var securityFixPS []byte

// ---------------------------------------------------------------- local store

type secRecord struct {
	ID       string            `json:"id"`
	T        int64             `json:"t"`
	Source   string            `json:"source"` // scan | shield | bloat | harden
	Title    string            `json:"title"`
	Sub      string            `json:"sub,omitempty"`
	Path     string            `json:"path,omitempty"`
	SHA      string            `json:"sha256,omitempty"`
	Sev      string            `json:"sev,omitempty"`
	Score    int               `json:"score,omitempty"`
	Reasons  []secReason       `json:"reasons,omitempty"`
	Origin   *secOrigin        `json:"origin,omitempty"`
	Chain    []secStep         `json:"chain,omitempty"`
	Persist  []secPersist      `json:"persist,omitempty"`
	Intel    []secIntel        `json:"intel,omitempty"`
	MITRE    []string          `json:"mitre,omitempty"`
	Action   string            `json:"action"`
	Done     []string          `json:"done"`
	Failed   []string          `json:"failed,omitempty"`
	QID      string            `json:"qid,omitempty"`
	Undo     []json.RawMessage `json:"undo,omitempty"`
	Restored int64             `json:"restored,omitempty"`
	CanUndo  bool              `json:"canUndo"`
}

type secSettings struct {
	KeyEnc  string   `json:"keyEnc,omitempty"`
	Trusted []string `json:"trusted"`
	Shield  bool     `json:"shield"`
}

type secStore struct {
	mu   sync.Mutex
	dir  string
	set  secSettings
	hist []secRecord
	last *secResult
	byID map[string]*secFinding
}

var secDB = &secStore{}

func (s *secStore) open() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dir != "" {
		return
	}
	s.dir = secDir()
	_ = os.MkdirAll(filepath.Join(s.dir, "Quarantine"), 0700)
	if b, err := os.ReadFile(filepath.Join(s.dir, "settings.json")); err == nil {
		_ = json.Unmarshal(b, &s.set)
	}
	if b, err := os.ReadFile(filepath.Join(s.dir, "history.json")); err == nil {
		_ = json.Unmarshal(b, &s.hist)
	}
}

func (s *secStore) saveLocked() {
	b, _ := json.MarshalIndent(s.set, "", " ")
	_ = os.WriteFile(filepath.Join(s.dir, "settings.json"), b, 0600)
	if len(s.hist) > 500 {
		s.hist = s.hist[len(s.hist)-500:]
	}
	h, _ := json.MarshalIndent(s.hist, "", " ")
	_ = os.WriteFile(filepath.Join(s.dir, "history.json"), h, 0600)
}

func (s *secStore) addRecord(r secRecord) secRecord {
	s.open()
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.ID == "" {
		r.ID = "r" + randToken()[:10]
	}
	if r.T == 0 {
		r.T = time.Now().Unix()
	}
	s.hist = append(s.hist, r)
	s.saveLocked()
	return r
}

func (s *secStore) trustedFn() func(string) bool {
	s.open()
	s.mu.Lock()
	m := map[string]bool{}
	for _, t := range s.set.Trusted {
		m[lc(t)] = true
	}
	s.mu.Unlock()
	return func(k string) bool { return m[lc(k)] }
}

func (s *secStore) apiKey() string {
	s.open()
	s.mu.Lock()
	enc := s.set.KeyEnc
	s.mu.Unlock()
	if enc == "" {
		return ""
	}
	b, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return ""
	}
	p, err := secUnprotect(b)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(p))
}

// ---------------------------------------------------------------- Quarantine
//
// A quarantined file is moved into the private Quarantine folder and scrambled (XOR with a
// per-file key), so it can neither run nor be opened by accident, and is restored byte for byte.

type qMeta struct {
	ID    string `json:"id"`
	Path  string `json:"path"`
	SHA   string `json:"sha256"`
	Size  int64  `json:"size"`
	T     int64  `json:"t"`
	Key   string `json:"key"`
	Title string `json:"title"`
}

func scramble(b []byte, key []byte) {
	for i := range b {
		b[i] ^= key[i%len(key)] ^ byte(i*31)
	}
}

func quarantineFile(path, title string) (qMeta, error) {
	secDB.open()
	path = normPath(path)
	st, err := os.Stat(path)
	if err != nil {
		return qMeta{}, err
	}
	if st.IsDir() {
		return qMeta{}, errors.New("is a folder")
	}
	if st.Size() > 512<<20 {
		return qMeta{}, errors.New("file is too large to quarantine")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return qMeta{}, err
	}
	sum := sha256.Sum256(data)
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	m := qMeta{ID: "q" + randToken()[:10], Path: path, SHA: hex.EncodeToString(sum[:]), Size: st.Size(), T: time.Now().Unix(), Key: hex.EncodeToString(key), Title: title}
	scramble(data, key)
	qd := filepath.Join(secDB.dir, "Quarantine")
	if err := os.WriteFile(filepath.Join(qd, m.ID+".ckq"), data, 0600); err != nil {
		return qMeta{}, err
	}
	mb, _ := json.Marshal(m)
	if err := os.WriteFile(filepath.Join(qd, m.ID+".json"), mb, 0600); err != nil {
		os.Remove(filepath.Join(qd, m.ID+".ckq"))
		return qMeta{}, err
	}
	if err := removeFileHard(path); err != nil {
		os.Remove(filepath.Join(qd, m.ID+".ckq"))
		os.Remove(filepath.Join(qd, m.ID+".json"))
		return qMeta{}, fmt.Errorf("could not remove the original: %w", err)
	}
	return m, nil
}

func restoreQuarantine(id string) (string, error) {
	secDB.open()
	if !strings.HasPrefix(id, "q") || strings.ContainsAny(id, `/\.`) {
		return "", errors.New("unknown item")
	}
	qd := filepath.Join(secDB.dir, "Quarantine")
	mb, err := os.ReadFile(filepath.Join(qd, id+".json"))
	if err != nil {
		return "", errors.New("this item is no longer in quarantine")
	}
	var m qMeta
	if json.Unmarshal(mb, &m) != nil {
		return "", errors.New("damaged quarantine record")
	}
	data, err := os.ReadFile(filepath.Join(qd, id+".ckq"))
	if err != nil {
		return "", err
	}
	key, _ := hex.DecodeString(m.Key)
	if len(key) == 0 {
		return "", errors.New("damaged quarantine record")
	}
	scramble(data, key)
	dst := m.Path
	if _, err := os.Stat(dst); err == nil {
		dst = dst + ".restored"
	}
	_ = os.MkdirAll(filepath.Dir(dst), 0755)
	if err := os.WriteFile(dst, data, 0755); err != nil {
		return "", err
	}
	os.Remove(filepath.Join(qd, id+".ckq"))
	os.Remove(filepath.Join(qd, id+".json"))
	return dst, nil
}

func deleteQuarantine(id string) error {
	secDB.open()
	if !strings.HasPrefix(id, "q") || strings.ContainsAny(id, `/\.`) {
		return errors.New("unknown item")
	}
	qd := filepath.Join(secDB.dir, "Quarantine")
	os.Remove(filepath.Join(qd, id+".ckq"))
	return os.Remove(filepath.Join(qd, id+".json"))
}

func listQuarantine() []qMeta {
	secDB.open()
	qd := filepath.Join(secDB.dir, "Quarantine")
	ents, _ := os.ReadDir(qd)
	out := []qMeta{}
	for _, e := range ents {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(qd, e.Name()))
		if err != nil {
			continue
		}
		var m qMeta
		if json.Unmarshal(b, &m) == nil {
			m.Key = ""
			out = append(out, m)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].T > out[j].T })
	return out
}

// ---------------------------------------------------------------- threat intelligence (MalwareBazaar)

type intelCache struct {
	mu sync.Mutex
	m  map[string]intelEntry
}

type intelEntry struct {
	I secIntel `json:"i"`
	T int64    `json:"t"`
}

var intelC = &intelCache{}

func (c *intelCache) load() {
	if c.m != nil {
		return
	}
	c.m = map[string]intelEntry{}
	if b, err := os.ReadFile(filepath.Join(secDB.dir, "intel-cache.json")); err == nil {
		_ = json.Unmarshal(b, &c.m)
	}
}

func (c *intelCache) save() {
	now := time.Now().Unix()
	for k, v := range c.m {
		if now-v.T > 7*86400 && v.I.Verdict != "malicious" {
			delete(c.m, k)
		}
	}
	b, _ := json.Marshal(c.m)
	_ = os.WriteFile(filepath.Join(secDB.dir, "intel-cache.json"), b, 0600)
}

var mbEndpoint = "https://mb-api.abuse.ch/api/v1/"

// lookupHashes asks MalwareBazaar about SHA-256 hashes (only the hashes leave the device).
func lookupHashes(ctx context.Context, key string, hashes []string, cl *http.Client) (map[string]secIntel, int, error) {
	secDB.open()
	intelC.mu.Lock()
	intelC.load()
	out := map[string]secIntel{}
	todo := []string{}
	now := time.Now().Unix()
	for _, h := range dedupe(hashes) {
		h = lc(h)
		if len(h) != 64 {
			continue
		}
		if e, ok := intelC.m[h]; ok && (now-e.T < 3*86400 || e.I.Verdict == "malicious") {
			out[h] = e.I
			continue
		}
		todo = append(todo, h)
	}
	intelC.mu.Unlock()
	if key == "" || len(todo) == 0 {
		return out, 0, nil
	}
	if len(todo) > 120 {
		todo = todo[:120]
	}
	if cl == nil {
		cl = &http.Client{Timeout: 10 * time.Second}
	}
	var mu sync.Mutex
	var firstErr error
	n := 0
	sem := make(chan struct{}, 6)
	var wg sync.WaitGroup
	for _, h := range todo {
		wg.Add(1)
		sem <- struct{}{}
		go func(h string) {
			defer wg.Done()
			defer func() { <-sem }()
			it, err := mbLookup(ctx, cl, key, h)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				if firstErr == nil {
					firstErr = err
				}
				return
			}
			n++
			out[h] = it
			intelC.mu.Lock()
			intelC.m[h] = intelEntry{I: it, T: time.Now().Unix()}
			intelC.mu.Unlock()
		}(h)
	}
	wg.Wait()
	intelC.mu.Lock()
	intelC.save()
	intelC.mu.Unlock()
	if n == 0 && firstErr != nil {
		return out, 0, firstErr
	}
	return out, n, nil
}

func mbLookup(ctx context.Context, cl *http.Client, key, h string) (secIntel, error) {
	form := url.Values{"query": {"get_info"}, "hash": {h}}
	req, _ := http.NewRequestWithContext(ctx, "POST", mbEndpoint, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Auth-Key", key)
	req.Header.Set("User-Agent", "CoreKit/"+appVersion)
	resp, err := cl.Do(req)
	if err != nil {
		return secIntel{}, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return secIntel{}, errors.New("the abuse.ch key was refused")
	}
	return parseMB(b)
}

func parseMB(b []byte) (secIntel, error) {
	var r struct {
		Status string `json:"query_status"`
		Data   []struct {
			Sig   string   `json:"signature"`
			Tags  []string `json:"tags"`
			First string   `json:"first_seen"`
			SHA   string   `json:"sha256_hash"`
		} `json:"data"`
	}
	if err := json.Unmarshal(b, &r); err != nil {
		return secIntel{}, errors.New("unexpected reply from MalwareBazaar")
	}
	switch r.Status {
	case "ok":
		if len(r.Data) == 0 {
			return secIntel{Source: "MalwareBazaar", Verdict: "unknown"}, nil
		}
		d := r.Data[0]
		return secIntel{Source: "MalwareBazaar", Verdict: "malicious", Family: d.Sig, Tags: d.Tags, First: d.First, Link: "https://bazaar.abuse.ch/sample/" + d.SHA + "/"}, nil
	case "hash_not_found", "no_results":
		return secIntel{Source: "MalwareBazaar", Verdict: "unknown"}, nil
	case "unknown_auth_key", "user_blacklisted":
		return secIntel{}, errors.New("the abuse.ch key was refused")
	}
	return secIntel{}, errors.New("MalwareBazaar: " + r.Status)
}

// ---------------------------------------------------------------- the scan

// runSecScan collects, checks hashes online, analyses and asks Defender for a second opinion.
func runSecScan(ctx context.Context, progress func(int, string)) (*secResult, error) {
	secDB.open()
	start := time.Now()
	raw, err := secCollect(ctx, func(kind, a, b string) {
		if kind == "P" {
			p, _ := strconv.Atoi(a)
			progress(p*80/100, b)
		} else if kind == "L" {
			logLine(a, b)
		}
	})
	if err != nil {
		return nil, err
	}
	var r rawSec
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("scan data unreadable: %w", err)
	}
	key := secDB.apiKey()
	intelState := "off"
	var intel map[string]secIntel
	if key != "" {
		progress(82, "Checking files against known malware")
		hs := []string{}
		for _, f := range r.Files {
			if f.SHA != "" {
				hs = append(hs, f.SHA)
			}
		}
		var n int
		intel, n, err = lookupHashes(ctx, key, hs, nil)
		if err != nil {
			intelState = "error: " + shortErr(err)
			logLine("!", "Online check: "+shortErr(err))
		} else {
			intelState = "on"
		}
		logLine("+", fmt.Sprintf("Checked %d file fingerprints online", n))
	} else {
		intel, _, _ = lookupHashes(ctx, "", nil, nil)
	}
	progress(88, "Scoring what was found")
	res := analyzeSec(&r, time.Now().Unix(), secDB.trustedFn(), intel)
	res.Intel = intelState
	res.Scanned.Lookups = len(intel)
	// second opinion from Windows Defender on the files that look worst
	n := 0
	for i := range res.Findings {
		f := &res.Findings[i]
		if n >= 6 || ctx.Err() != nil {
			break
		}
		if f.Path == "" || f.Score < 40 || f.Signed == "valid" || f.Kind == "threat" || f.Kind == "setting" {
			continue
		}
		n++
		progress(88+n, "Asking Windows Defender about "+filepath.Base(f.Path))
		if name, ok := secDefenderScan(ctx, f.Path); ok && name != "" {
			f.Reasons = append([]secReason{{"Windows Defender identifies it as " + name, 100}}, f.Reasons...)
			f.Intel = append(f.Intel, secIntel{Source: "Windows Defender", Verdict: "malicious", Family: name})
		}
	}
	rescore(res)
	res.Ms = time.Since(start).Milliseconds()
	secDB.mu.Lock()
	secDB.last = res
	secDB.byID = map[string]*secFinding{}
	for i := range res.Findings {
		secDB.byID[res.Findings[i].ID] = &res.Findings[i]
	}
	secDB.mu.Unlock()
	progress(100, "Done")
	return res, nil
}

func rescore(res *secResult) {
	res.Counts = secCounts{}
	for i := range res.Findings {
		f := &res.Findings[i]
		f.Reasons = dedupeReasons(f.Reasons)
		f.Score = total(f.Reasons)
		f.Sev = sevOf(f.Score)
		f.Summary = summaryOf(f)
		switch f.Sev {
		case "high":
			res.Counts.High++
		case "med":
			res.Counts.Med++
		case "low":
			res.Counts.Low++
		default:
			res.Counts.Info++
		}
	}
	sort.SliceStable(res.Findings, func(i, j int) bool { return res.Findings[i].Score > res.Findings[j].Score })
	res.Score, res.Verdict = overall(res)
}

// ---------------------------------------------------------------- fixing

type fixOutcome struct {
	OK     bool      `json:"ok"`
	Msg    string    `json:"msg"`
	Record secRecord `json:"record"`
}

func recordOf(f *secFinding, action string) secRecord {
	return secRecord{Source: "scan", Title: f.Title, Sub: f.Sub, Path: f.Path, SHA: f.SHA, Sev: f.Sev, Score: f.Score, Reasons: f.Reasons, Origin: f.Origin, Chain: f.Chain, Persist: f.Persist, Intel: f.Intel, MITRE: f.MITRE, Action: action}
}

func applyFix(ctx context.Context, f *secFinding, action string) fixOutcome {
	rec := recordOf(f, action)
	var errs []string
	note := func(ok bool, what string, err error) {
		if ok {
			rec.Done = append(rec.Done, what)
		} else {
			rec.Failed = append(rec.Failed, what+": "+shortErr(err))
			errs = append(errs, what)
		}
	}
	removeAuto := func() {
		for _, a := range f.Auto {
			undo, err := secAutorunRemove(ctx, a)
			note(err == nil, "Removed start-up entry ("+a.Kind+")", err)
			if err == nil && len(undo) > 0 {
				rec.Undo = append(rec.Undo, undo)
			}
		}
	}
	switch action {
	case "kill":
		pids := append([]int{}, f.PIDs...)
		if f.Path != "" {
			pids = append(pids, secPIDsOf(f.Path)...)
		}
		if len(pids) == 0 {
			note(true, "Was not running", nil)
		}
		for _, p := range dedupeInts(pids) {
			note(secKill(p) == nil, fmt.Sprintf("Stopped process %d", p), errors.New("access denied or already gone"))
		}
	case "quarantine":
		if f.Path == "" {
			return fixOutcome{false, "There is no file to quarantine.", rec}
		}
		if sysDir(f.Path) {
			return fixOutcome{false, "Windows system files are never quarantined. Stop the process instead.", rec}
		}
		for _, p := range dedupeInts(append(append([]int{}, f.PIDs...), secPIDsOf(f.Path)...)) {
			note(secKill(p) == nil, fmt.Sprintf("Stopped process %d", p), errors.New("could not stop it"))
		}
		removeAuto()
		time.Sleep(300 * time.Millisecond)
		m, err := quarantineFile(f.Path, f.Title)
		note(err == nil, "Moved the file to Quarantine", err)
		if err == nil {
			rec.QID = m.ID
			if rec.SHA == "" {
				rec.SHA = m.SHA
			}
		}
	case "remove":
		if len(f.Auto) == 0 {
			return fixOutcome{false, "Nothing to remove.", rec}
		}
		removeAuto()
	case "fixsetting":
		undo, err := secFixSetting(ctx, f.FixKey)
		note(err == nil, "Fixed: "+f.Title, err)
		if err == nil && len(undo) > 0 {
			rec.Undo = append(rec.Undo, undo)
		}
	case "defender":
		_, err := secRunFix(ctx, map[string]any{"op": "defender-remove"})
		note(err == nil, "Windows Defender removed the threat", err)
	case "trust":
		secDB.open()
		secDB.mu.Lock()
		if f.SHA != "" {
			secDB.set.Trusted = append(secDB.set.Trusted, lc(f.SHA))
		} else if f.Path != "" {
			secDB.set.Trusted = append(secDB.set.Trusted, lc(f.Path))
		}
		secDB.set.Trusted = dedupe(secDB.set.Trusted)
		secDB.saveLocked()
		secDB.mu.Unlock()
		note(true, "Marked as trusted: it won't be reported again", nil)
	default:
		return fixOutcome{false, "Unknown action.", rec}
	}
	rec.CanUndo = rec.QID != "" || len(rec.Undo) > 0
	rec = secDB.addRecord(rec)
	if len(errs) > 0 && len(rec.Done) == 0 {
		return fixOutcome{false, "Could not fix it: " + strings.Join(rec.Failed, "; "), rec}
	}
	msg := strings.Join(rec.Done, " · ")
	if len(errs) > 0 {
		msg += " (some steps failed: " + strings.Join(errs, ", ") + ")"
	}
	return fixOutcome{len(errs) == 0, msg, rec}
}

func dedupeInts(a []int) []int {
	seen := map[int]bool{}
	out := []int{}
	for _, x := range a {
		if x > 4 && !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}

func undoRecord(ctx context.Context, id string) (string, error) {
	secDB.open()
	secDB.mu.Lock()
	var rec *secRecord
	for i := range secDB.hist {
		if secDB.hist[i].ID == id {
			rec = &secDB.hist[i]
		}
	}
	if rec == nil {
		secDB.mu.Unlock()
		return "", errors.New("record not found")
	}
	if rec.Restored > 0 {
		secDB.mu.Unlock()
		return "", errors.New("already restored")
	}
	r := *rec
	secDB.mu.Unlock()
	msgs := []string{}
	if r.QID != "" {
		p, err := restoreQuarantine(r.QID)
		if err != nil {
			return "", err
		}
		msgs = append(msgs, "File restored to "+p)
	}
	for _, u := range r.Undo {
		if err := secUndo(ctx, u); err != nil {
			msgs = append(msgs, "Could not restore a setting: "+shortErr(err))
		} else {
			msgs = append(msgs, "Setting restored")
		}
	}
	secDB.mu.Lock()
	for i := range secDB.hist {
		if secDB.hist[i].ID == id {
			secDB.hist[i].Restored = time.Now().Unix()
		}
	}
	secDB.saveLocked()
	secDB.mu.Unlock()
	return strings.Join(msgs, " · "), nil
}

// ---------------------------------------------------------------- HTTP (Windows host; Android answers the same calls)

func mountSecurity(mux *http.ServeMux, base string, in *inspector) {
	mux.HandleFunc(base+"scan", in.secScan)
	mux.HandleFunc(base+"fix", secPost(func(r *http.Request, b []byte) any {
		var q struct{ ID, Action string }
		if json.Unmarshal(b, &q) != nil {
			return map[string]string{"error": "bad request"}
		}
		secDB.mu.Lock()
		f := secDB.byID[q.ID]
		secDB.mu.Unlock()
		if f == nil {
			return map[string]string{"error": "Please scan again: this result is out of date."}
		}
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
		defer cancel()
		logLine("*", "Security fix: "+q.Action+" "+f.Title)
		return applyFix(ctx, f, q.Action)
	}))
	mux.HandleFunc(base+"fixall", secPost(func(r *http.Request, b []byte) any {
		var q struct{ IDs []string }
		_ = json.Unmarshal(b, &q)
		ctx, cancel := context.WithTimeout(r.Context(), 6*time.Minute)
		defer cancel()
		out := []fixOutcome{}
		for _, id := range q.IDs {
			secDB.mu.Lock()
			f := secDB.byID[id]
			secDB.mu.Unlock()
			if f == nil {
				continue
			}
			act := ""
			for _, a := range f.Actions {
				if a.Main {
					act = a.ID
				}
			}
			if act == "" || act == "trust" {
				continue
			}
			out = append(out, applyFix(ctx, f, act))
		}
		return map[string]any{"results": out}
	}))
	mux.HandleFunc(base+"history", func(w http.ResponseWriter, r *http.Request) {
		secDB.open()
		secDB.mu.Lock()
		h := append([]secRecord{}, secDB.hist...)
		secDB.mu.Unlock()
		sort.SliceStable(h, func(i, j int) bool { return h[i].T > h[j].T })
		writeJSON(w, map[string]any{"items": h, "quarantine": listQuarantine()})
	})
	mux.HandleFunc(base+"undo", secPost(func(r *http.Request, b []byte) any {
		var q struct{ ID string }
		_ = json.Unmarshal(b, &q)
		msg, err := undoRecord(r.Context(), q.ID)
		if err != nil {
			return map[string]string{"error": err.Error()}
		}
		return map[string]string{"msg": msg}
	}))
	mux.HandleFunc(base+"qdelete", secPost(func(r *http.Request, b []byte) any {
		var q struct{ ID string }
		_ = json.Unmarshal(b, &q)
		if err := deleteQuarantine(q.ID); err != nil {
			return map[string]string{"error": err.Error()}
		}
		return map[string]string{"msg": "Deleted for good"}
	}))
	mux.HandleFunc(base+"settings", func(w http.ResponseWriter, r *http.Request) {
		secDB.open()
		if r.Method == http.MethodPost {
			var q struct {
				Key     *string  `json:"key"`
				Untrust []string `json:"untrust"`
			}
			if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&q) != nil {
				writeJSON(w, map[string]string{"error": "bad request"})
				return
			}
			if q.Key != nil {
				k := strings.TrimSpace(*q.Key)
				if k != "" && !validKey(k) {
					writeJSON(w, map[string]string{"error": "That doesn't look like an abuse.ch Auth-Key."})
					return
				}
				if k != "" {
					ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
					_, err := mbLookup(ctx, &http.Client{Timeout: 12 * time.Second}, k, strings.Repeat("0", 64))
					cancel()
					if err != nil && strings.Contains(err.Error(), "refused") {
						writeJSON(w, map[string]string{"error": "abuse.ch refused this key. Check it and try again."})
						return
					}
				}
				enc := ""
				if k != "" {
					b, err := secProtect([]byte(k))
					if err != nil {
						writeJSON(w, map[string]string{"error": "Could not store the key securely."})
						return
					}
					enc = base64.StdEncoding.EncodeToString(b)
				}
				secDB.mu.Lock()
				secDB.set.KeyEnc = enc
				secDB.saveLocked()
				secDB.mu.Unlock()
			}
			if len(q.Untrust) > 0 {
				secDB.mu.Lock()
				drop := map[string]bool{}
				for _, u := range q.Untrust {
					drop[lc(u)] = true
				}
				keep := []string{}
				for _, t := range secDB.set.Trusted {
					if !drop[lc(t)] {
						keep = append(keep, t)
					}
				}
				secDB.set.Trusted = keep
				secDB.saveLocked()
				secDB.mu.Unlock()
			}
		}
		secDB.mu.Lock()
		out := map[string]any{"keySet": secDB.set.KeyEnc != "", "trusted": append([]string{}, secDB.set.Trusted...), "dir": secDB.dir}
		secDB.mu.Unlock()
		out["shield"] = secShieldStatus()
		writeJSON(w, out)
	})
	mux.HandleFunc(base+"shield", secPost(func(r *http.Request, b []byte) any {
		var q struct {
			On bool `json:"on"`
		}
		_ = json.Unmarshal(b, &q)
		if err := secShieldSet(q.On); err != nil {
			return map[string]any{"error": err.Error(), "shield": secShieldStatus()}
		}
		secDB.open()
		secDB.mu.Lock()
		secDB.set.Shield = q.On
		secDB.saveLocked()
		secDB.mu.Unlock()
		return map[string]any{"shield": secShieldStatus()}
	}))
	mux.HandleFunc(base+"harden", secPost(func(r *http.Request, b []byte) any {
		var q struct {
			IDs []string `json:"ids"`
		}
		_ = json.Unmarshal(b, &q)
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
		defer cancel()
		res, err := secHarden(ctx, q.IDs)
		if err != nil {
			return map[string]string{"error": err.Error()}
		}
		secDB.addRecord(secRecord{Source: "harden", Title: "Turned on protection: " + strings.Join(q.IDs, ", "), Action: "harden", Done: []string{res}})
		return map[string]string{"msg": res}
	}))
	mux.HandleFunc(base+"asr", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"rules": asrRules})
	})
	mux.HandleFunc(base+"bloat", secPost(func(r *http.Request, b []byte) any {
		var q struct{ ID string }
		_ = json.Unmarshal(b, &q)
		secDB.mu.Lock()
		var bl *secBloat
		if secDB.last != nil {
			for i := range secDB.last.Bloat {
				if secDB.last.Bloat[i].ID == q.ID {
					bl = &secDB.last.Bloat[i]
				}
			}
		}
		secDB.mu.Unlock()
		if bl == nil {
			return map[string]string{"error": "Please scan again: this list is out of date."}
		}
		ctx, cancel := context.WithTimeout(r.Context(), 4*time.Minute)
		defer cancel()
		msg, undo, err := secBloatAction(ctx, *bl)
		if err != nil {
			return map[string]string{"error": err.Error()}
		}
		rec := secRecord{Source: "bloat", Title: bl.Name, Sub: bl.Publisher, Action: bl.Action, Done: []string{msg}}
		if len(undo) > 0 {
			rec.Undo = []json.RawMessage{undo}
			rec.CanUndo = true
		}
		secDB.addRecord(rec)
		secDB.mu.Lock()
		bl.On = false
		secDB.mu.Unlock()
		return map[string]string{"msg": msg}
	}))
	mux.HandleFunc(base+"second", secPost(func(r *http.Request, b []byte) any {
		var q struct{ ID string }
		_ = json.Unmarshal(b, &q)
		secDB.mu.Lock()
		f := secDB.byID[q.ID]
		secDB.mu.Unlock()
		if f == nil || f.Path == "" {
			return map[string]string{"error": "Nothing to check."}
		}
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
		defer cancel()
		out := map[string]any{}
		if name, ok := secDefenderScan(ctx, f.Path); ok {
			if name != "" {
				out["defender"] = "Threat: " + name
			} else {
				out["defender"] = "No threat found"
			}
		} else {
			out["defender"] = "Windows Defender is not available"
		}
		if f.SHA != "" {
			if k := secDB.apiKey(); k != "" {
				m, _, err := lookupHashes(ctx, k, []string{f.SHA}, nil)
				switch {
				case err != nil:
					out["bazaar"] = "Could not check: " + shortErr(err)
				case m[lc(f.SHA)].Verdict == "malicious":
					out["bazaar"] = "Known malware: " + m[lc(f.SHA)].Family
					out["link"] = m[lc(f.SHA)].Link
				default:
					out["bazaar"] = "Not in the known-malware database"
				}
			} else {
				out["bazaar"] = "Add a free abuse.ch key in Settings to check online"
			}
			out["vt"] = "https://www.virustotal.com/gui/file/" + f.SHA
		}
		return out
	}))
}

var keyRe = func(s string) bool {
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func validKey(k string) bool { return len(k) >= 20 && len(k) <= 128 && keyRe(k) }

func secPost(h func(r *http.Request, body []byte) any) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method", 405)
			return
		}
		b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
		if err != nil {
			http.Error(w, "bad", 400)
			return
		}
		writeJSON(w, h(r, b))
	}
}

func (in *inspector) secScan(w http.ResponseWriter, r *http.Request) {
	s, cancel, ok := in.beginStream(w, r)
	if !ok {
		return
	}
	defer in.endStream()
	defer cancel()
	fmt.Println()
	logLine("*", "Security scan started")
	res, err := runSecScan(s.ctx, func(p int, label string) { s.json("progress", map[string]any{"pct": p, "label": label}) })
	if err != nil {
		logLine("!", "Security scan failed: "+err.Error())
		s.json("fail", map[string]string{"error": err.Error()})
		return
	}
	logLine("#", fmt.Sprintf("Security scan done: %d high, %d medium, %d low", res.Counts.High, res.Counts.Med, res.Counts.Low))
	var buf bytes.Buffer
	_ = json.NewEncoder(&buf).Encode(res)
	s.send("done", bytes.TrimSpace(buf.Bytes()))
}
