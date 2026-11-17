package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestGoogleFix(t *testing.T) {
	cases := []struct {
		in, out string
		ok      bool
	}{
		{"https://www.google.de/", "https://www.google.com/?hl=en", true},
		{"https://www.google.com/search?q=wetter", "https://www.google.com/search?hl=en&q=wetter", true},
		{"https://google.com.pk/search?q=x", "https://www.google.com/search?hl=en&q=x", true},
		{"https://www.google.com/search?q=x&hl=en", "", false},
		{"https://www.google.de/search?q=x&hl=en", "https://www.google.com/search?hl=en&q=x", true},
		{"https://www.google.com/maps", "", false},
		{"https://mail.google.com/", "", false},
		{"https://notgoogle.com/", "", false},
	}
	for _, c := range cases {
		got, ok := googleFix(c.in, "en")
		if ok != c.ok || (ok && got != c.out) {
			t.Errorf("%s -> %s %v", c.in, got, ok)
		}
	}
	if got, _ := googleFix("https://www.google.de/", "ur"); got != "https://www.google.com/?hl=ur" {
		t.Error(got)
	}
}

func TestParseGoogleT(t *testing.T) {
	dec := func(s string) any { var v any; json.Unmarshal([]byte(s), &v); return v }
	if o, d, err := parseGoogleT(dec(`["Hello","de"]`), 1); err != nil || o[0] != "Hello" || d != "de" {
		t.Error(o, d, err)
	}
	if o, _, err := parseGoogleT(dec(`[["Hello","de"],["World","de"]]`), 2); err != nil || o[1] != "World" {
		t.Error(o, err)
	}
	if o, _, err := parseGoogleT(dec(`["Hello","World","Again"]`), 3); err != nil || o[2] != "Again" {
		t.Error(o, err)
	}
	if _, _, err := parseGoogleT(dec(`{"x":1}`), 1); err == nil {
		t.Error("expected error")
	}
}

func TestTranslatorMicrosoftAndFallback(t *testing.T) {
	msFail := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/auth"):
			io.WriteString(w, "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.test.token")
		case strings.HasSuffix(r.URL.Path, "/translate"):
			if msFail || r.Header.Get("Authorization") == "" || r.URL.Query().Get("to") != "en" {
				w.WriteHeader(500)
				return
			}
			var in []map[string]string
			json.NewDecoder(r.Body).Decode(&in)
			var out []map[string]any
			for _, x := range in {
				out = append(out, map[string]any{"detectedLanguage": map[string]any{"language": "de"}, "translations": []any{map[string]any{"text": "EN:" + x["Text"]}}})
			}
			json.NewEncoder(w).Encode(out)
		case strings.HasSuffix(r.URL.Path, "/t"):
			r.ParseForm()
			var out [][]string
			for _, q := range r.PostForm["q"] {
				out = append(out, []string{"G:" + q, "de"})
			}
			json.NewEncoder(w).Encode(out)
		}
	}))
	defer srv.Close()
	msAuthURL, msTranslateURL, gTranslateURL = srv.URL+"/auth", srv.URL+"/translate", srv.URL+"/t"
	tr := &translator{client: func() *http.Client { return &http.Client{Timeout: 5 * time.Second} }}
	texts := []string{"Hallo", "Welt", "Hallo", "  ", strings.Repeat("Wort ", 300)}
	got := make([]string, len(texts))
	det, err := tr.translateAll(texts, "en", func(idx []int, out []string) {
		for i, k := range idx {
			got[k] = out[i]
		}
	})
	if err != nil || det != "de" || got[0] != "EN:Hallo" || got[2] != "EN:Hallo" || got[1] != "EN:Welt" || got[3] != "" {
		t.Fatalf("ms: %v %v %q", err, det, got[:4])
	}
	msFail = true
	out, _, err := tr.translate([]string{"a", "b"}, "en")
	if err != nil || out[1] != "G:b" {
		t.Fatalf("fallback: %v %v", out, err)
	}
}

func TestHistoryStore(t *testing.T) {
	h := &historyStore{}
	now := time.Now()
	h.add("https://a.com/", "A", now)
	h.add("https://a.com/", "A2", now.Add(time.Second))
	h.add("https://b.com/", "Bee", now.Add(2*time.Second))
	if r := h.search("", 10); len(r) != 2 || r[0].URL != "https://b.com/" || r[1].Title != "A2" {
		t.Fatal(r)
	}
	if r := h.search("bee", 10); len(r) != 1 {
		t.Fatal(r)
	}
	h.remove("https://b.com/", 0)
	if r := h.search("", 10); len(r) != 1 {
		t.Fatal(r)
	}
}
