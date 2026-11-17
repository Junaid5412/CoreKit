package main

// CoreKit Browser — languages: page translation (Microsoft Translator, Google fallback),
// Google-in-your-language, and the browsing history store.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------- languages

type langInfo struct{ Code, Name string }

var uiLanguages = []langInfo{
	{"en", "English"}, {"ar", "Arabic"}, {"ur", "Urdu"}, {"hi", "Hindi"}, {"bn", "Bengali"}, {"fa", "Persian"},
	{"tr", "Turkish"}, {"fr", "French"}, {"de", "German"}, {"es", "Spanish"}, {"it", "Italian"}, {"pt", "Portuguese"},
	{"nl", "Dutch"}, {"ru", "Russian"}, {"uk", "Ukrainian"}, {"pl", "Polish"}, {"zh-Hans", "Chinese"}, {"ja", "Japanese"},
	{"ko", "Korean"}, {"id", "Indonesian"}, {"ms", "Malay"}, {"th", "Thai"}, {"vi", "Vietnamese"}, {"tl", "Filipino"},
}

var langNames = map[string]string{
	"en": "English", "ar": "Arabic", "ur": "Urdu", "hi": "Hindi", "bn": "Bengali", "fa": "Persian", "ps": "Pashto",
	"pa": "Punjabi", "tr": "Turkish", "fr": "French", "de": "German", "es": "Spanish", "it": "Italian", "pt": "Portuguese",
	"nl": "Dutch", "ru": "Russian", "uk": "Ukrainian", "pl": "Polish", "zh": "Chinese", "ja": "Japanese", "ko": "Korean",
	"id": "Indonesian", "ms": "Malay", "th": "Thai", "vi": "Vietnamese", "tl": "Filipino", "fil": "Filipino", "sv": "Swedish",
	"no": "Norwegian", "nb": "Norwegian", "da": "Danish", "fi": "Finnish", "cs": "Czech", "sk": "Slovak", "hu": "Hungarian",
	"ro": "Romanian", "bg": "Bulgarian", "el": "Greek", "he": "Hebrew", "iw": "Hebrew", "sr": "Serbian", "hr": "Croatian",
	"sl": "Slovenian", "lt": "Lithuanian", "lv": "Latvian", "et": "Estonian", "ta": "Tamil", "te": "Telugu", "ml": "Malayalam",
	"mr": "Marathi", "gu": "Gujarati", "kn": "Kannada", "ne": "Nepali", "si": "Sinhala", "sw": "Swahili", "am": "Amharic",
	"az": "Azerbaijani", "kk": "Kazakh", "uz": "Uzbek", "ka": "Georgian", "hy": "Armenian", "sq": "Albanian", "mk": "Macedonian",
}

// primaryLang: "de-DE" -> "de", "zh-Hans" -> "zh"
func primaryLang(l string) string {
	l = strings.ToLower(strings.TrimSpace(l))
	if i := strings.IndexAny(l, "-_"); i > 0 {
		l = l[:i]
	}
	switch l {
	case "iw":
		return "he"
	case "fil":
		return "tl"
	case "nb", "nn":
		return "no"
	}
	return l
}

func langName(l string) string {
	if n := langNames[primaryLang(l)]; n != "" {
		return n
	}
	if l == "" {
		return "another language"
	}
	return strings.ToUpper(l)
}

// acceptLanguage is what the browser tells websites ("en" -> "en-US").
func acceptLanguage(l string) string {
	switch primaryLang(l) {
	case "en":
		return "en-US"
	case "zh":
		return "zh-CN"
	case "pt":
		return "pt-BR"
	case "":
		return "en-US"
	}
	return l
}

// ---------------------------------------------------------------- Google in your language

var googleHostRe = regexp.MustCompile(`^(www\.)?google\.(com|[a-z]{2}|com?\.[a-z]{2})$`)

// googleFix rewrites a country Google address (google.de, google.com without hl) to
// www.google.com in the chosen language. ok=false if no change is needed.
func googleFix(raw, lang string) (string, bool) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") {
		return raw, false
	}
	host := strings.ToLower(u.Hostname())
	if !googleHostRe.MatchString(host) {
		return raw, false
	}
	switch u.Path {
	case "", "/", "/search", "/webhp", "/imghp":
	default:
		return raw, false
	}
	q := u.Query()
	hl := primaryLang(lang)
	if hl == "zh" {
		hl = "zh-CN"
	}
	if q.Get("hl") != "" && host == "www.google.com" {
		return raw, false
	}
	if q.Get("hl") == "" {
		q.Set("hl", hl)
	}
	u.Scheme, u.Host, u.RawQuery = "https", "www.google.com", q.Encode()
	if u.Path == "" {
		u.Path = "/"
	}
	return u.String(), true
}

// ---------------------------------------------------------------- translation services

var (
	msAuthURL      = "https://edge.microsoft.com/translate/auth"
	msTranslateURL = "https://api-edge.cognitive.microsofttranslator.com/translate"
	msDetectURL    = "https://api-edge.cognitive.microsofttranslator.com/detect"
	gTranslateURL  = "https://translate.googleapis.com/translate_a/t"
	gSingleURL     = "https://translate.googleapis.com/translate_a/single"
)

type translator struct {
	client func() *http.Client
	mu     sync.Mutex
	tok    string
	tokExp time.Time
}

func (tr *translator) msToken() (string, error) {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	if tr.tok != "" && time.Now().Before(tr.tokExp) {
		return tr.tok, nil
	}
	resp, err := tr.client().Get(msAuthURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if resp.StatusCode != 200 || len(b) < 20 {
		return "", fmt.Errorf("auth HTTP %d", resp.StatusCode)
	}
	tr.tok, tr.tokExp = strings.TrimSpace(string(b)), time.Now().Add(8*time.Minute)
	return tr.tok, nil
}

func msCode(l string) string {
	switch primaryLang(l) {
	case "zh":
		return "zh-Hans"
	case "tl":
		return "fil"
	case "no":
		return "nb"
	}
	return primaryLang(l)
}

func gCode(l string) string {
	switch primaryLang(l) {
	case "zh":
		return "zh-CN"
	case "he":
		return "iw"
	}
	return primaryLang(l)
}

func (tr *translator) msTranslate(texts []string, to string) ([]string, string, error) {
	tok, err := tr.msToken()
	if err != nil {
		return nil, "", err
	}
	body := make([]map[string]string, len(texts))
	for i, t := range texts {
		body[i] = map[string]string{"Text": t}
	}
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", msTranslateURL+"?api-version=3.0&to="+url.QueryEscape(msCode(to)), bytes.NewReader(b))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	resp, err := tr.client().Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 401 {
		tr.mu.Lock()
		tr.tok = ""
		tr.mu.Unlock()
	}
	if resp.StatusCode != 200 {
		return nil, "", fmt.Errorf("translator HTTP %d", resp.StatusCode)
	}
	var out []struct {
		Detected struct {
			Language string `json:"language"`
		} `json:"detectedLanguage"`
		Translations []struct {
			Text string `json:"text"`
		} `json:"translations"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&out); err != nil {
		return nil, "", err
	}
	if len(out) != len(texts) {
		return nil, "", errors.New("translator returned a different number of items")
	}
	res := make([]string, len(out))
	det := ""
	for i, o := range out {
		if len(o.Translations) == 0 {
			return nil, "", errors.New("empty translation")
		}
		res[i] = o.Translations[0].Text
		if det == "" {
			det = o.Detected.Language
		}
	}
	return res, det, nil
}

// gTranslate uses Google's public web endpoint (several q= values per request).
func (tr *translator) gTranslate(texts []string, to string) ([]string, string, error) {
	form := url.Values{}
	for _, t := range texts {
		form.Add("q", t)
	}
	req, _ := http.NewRequest("POST", gTranslateURL+"?client=gtx&sl=auto&tl="+url.QueryEscape(gCode(to)), strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := tr.client().Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, "", fmt.Errorf("google HTTP %d", resp.StatusCode)
	}
	var raw any
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&raw); err != nil {
		return nil, "", err
	}
	return parseGoogleT(raw, len(texts))
}

// parseGoogleT accepts the shapes the endpoint returns:
// "text" | ["text","de"] (single, auto) | ["a","b"] | [["a","de"],["b","de"]].
func parseGoogleT(raw any, n int) ([]string, string, error) {
	det := ""
	item := func(v any) (string, bool) {
		switch x := v.(type) {
		case string:
			return x, true
		case []any:
			if len(x) >= 1 {
				if s, ok := x[0].(string); ok {
					if len(x) >= 2 {
						if d, ok := x[1].(string); ok && det == "" {
							det = d
						}
					}
					return s, true
				}
			}
		}
		return "", false
	}
	switch x := raw.(type) {
	case string:
		if n == 1 {
			return []string{x}, det, nil
		}
	case []any:
		if n == 1 && len(x) == 2 {
			if s, ok := x[0].(string); ok {
				if d, ok := x[1].(string); ok {
					return []string{s}, d, nil
				}
			}
		}
		if len(x) == n {
			out := make([]string, n)
			for i, v := range x {
				s, ok := item(v)
				if !ok {
					return nil, "", errors.New("unexpected google response")
				}
				out[i] = s
			}
			return out, det, nil
		}
	}
	return nil, "", errors.New("unexpected google response")
}

// translate translates texts to `to`, trying Microsoft then Google.
func (tr *translator) translate(texts []string, to string) ([]string, string, error) {
	out, det, err := tr.msTranslate(texts, to)
	if err == nil {
		return out, det, nil
	}
	out, det, err2 := tr.gTranslate(texts, to)
	if err2 == nil {
		return out, det, nil
	}
	return nil, "", fmt.Errorf("%v; %v", err, err2)
}

// detect guesses the language of a text sample.
func (tr *translator) detect(sample string) string {
	if tok, err := tr.msToken(); err == nil {
		b, _ := json.Marshal([]map[string]string{{"Text": sample}})
		req, _ := http.NewRequest("POST", msDetectURL+"?api-version=3.0", bytes.NewReader(b))
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Content-Type", "application/json")
		if resp, err := tr.client().Do(req); err == nil {
			var out []struct {
				Language string  `json:"language"`
				Score    float64 `json:"score"`
			}
			json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&out)
			resp.Body.Close()
			if len(out) == 1 && out[0].Language != "" && out[0].Score >= 0.5 {
				return out[0].Language
			}
		}
	}
	resp, err := tr.client().Get(gSingleURL + "?client=gtx&sl=auto&tl=en&dt=t&q=" + url.QueryEscape(sample))
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	var raw []any
	if json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&raw) == nil && len(raw) > 2 {
		if s, ok := raw[2].(string); ok {
			return s
		}
	}
	return ""
}

// translateAll translates many page texts: de-duplicated, in batches, a few in parallel.
// apply is called for each finished batch (indices into texts).
func (tr *translator) translateAll(texts []string, to string, apply func(idx []int, out []string)) (string, error) {
	type job struct {
		uniq []string
		idx  [][]int
	}
	pos := map[string]int{}
	var uniq []string
	var where [][]int
	for i, t := range texts {
		k := strings.TrimSpace(t)
		if k == "" {
			continue
		}
		if p, ok := pos[k]; ok {
			where[p] = append(where[p], i)
			continue
		}
		pos[k] = len(uniq)
		uniq = append(uniq, k)
		where = append(where, []int{i})
	}
	var jobs []job
	cur, chars := job{}, 0
	for i, u := range uniq {
		if len(cur.uniq) > 0 && (len(cur.uniq) >= 120 || chars+len(u) > 9000) {
			jobs = append(jobs, cur)
			cur, chars = job{}, 0
		}
		if len(u) > 4800 {
			u = u[:4800]
		}
		cur.uniq = append(cur.uniq, u)
		cur.idx = append(cur.idx, where[i])
		chars += len(u)
	}
	if len(cur.uniq) > 0 {
		jobs = append(jobs, cur)
	}
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		firstErr error
		det      string
		okCount  int
	)
	sem := make(chan struct{}, 3)
	for _, j := range jobs {
		wg.Add(1)
		sem <- struct{}{}
		go func(j job) {
			defer wg.Done()
			defer func() { <-sem }()
			out, d, err := tr.translate(j.uniq, to)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				if firstErr == nil {
					firstErr = err
				}
				return
			}
			okCount++
			if det == "" {
				det = d
			}
			var idx []int
			var vals []string
			for k, list := range j.idx {
				for _, i := range list {
					idx = append(idx, i)
					vals = append(vals, out[k])
				}
			}
			apply(idx, vals)
		}(j)
	}
	wg.Wait()
	if okCount == 0 && firstErr != nil {
		return "", firstErr
	}
	return det, nil
}

// googleTranslatePage is the last resort: Google's translated-page proxy.
func googleTranslatePage(pageURL, to string) string {
	return "https://translate.google.com/translate?sl=auto&tl=" + url.QueryEscape(gCode(to)) + "&u=" + url.QueryEscape(pageURL)
}

// ---------------------------------------------------------------- page scripts

// detectScript reports the page's declared language and a text sample.
const detectScript = `JSON.stringify({l:(document.documentElement.getAttribute('lang')||(document.querySelector('meta[http-equiv="content-language" i]')||{}).content||''),s:(document.body?document.body.innerText:'').replace(/\s+/g,' ').slice(0,700),t:document.documentElement.hasAttribute('data-ck-tr')})`

// collectScript gathers text not yet translated (text nodes + a few attributes) and
// defines __ckA (apply) / __ckR (restore original).
const collectScript = `(()=>{const S=window.__ckT||(window.__ckT={items:[],done:new WeakSet(),attrs:new WeakMap()});
if(!window.__ckA){window.__ckA=(base,arr)=>{for(let i=0;i<arr.length;i++){const it=S.items[base+i];if(!it||arr[i]==null)continue;const m=it.v.match(/^(\s*)[\s\S]*?(\s*)$/);const val=m[1]+arr[i]+m[2];if(it.a)it.e.setAttribute(it.a,arr[i]);else it.n.nodeValue=val;it.tr=1}document.documentElement.setAttribute('data-ck-tr','1')};
window.__ckR=()=>{for(const it of S.items){if(!it.tr)continue;if(it.a)it.e.setAttribute(it.a,it.v);else it.n.nodeValue=it.v;it.tr=0}document.documentElement.removeAttribute('data-ck-tr');S.items=[];S.done=new WeakSet();S.attrs=new WeakMap()}}
const skip=/^(SCRIPT|STYLE|NOSCRIPT|CODE|PRE|TEXTAREA|SVG|MATH|KBD|SAMP|VAR|TEMPLATE|IFRAME|CANVAS|SELECT|OPTION)$/i;
const ok=el=>{for(let p=el;p&&p.nodeType===1;p=p.parentElement){if(skip.test(p.tagName)||p.isContentEditable||p.getAttribute('translate')==='no'||(p.classList&&p.classList.contains('notranslate')))return false}return true};
const L=/\p{L}/u,base=S.items.length,out=[];if(!document.body)return JSON.stringify({base,texts:out});
const tw=document.createTreeWalker(document.body,NodeFilter.SHOW_TEXT);let n;
while((n=tw.nextNode())&&out.length<3000){const v=n.nodeValue;if(S.done.has(n)||!v||!L.test(v)||v.trim().length<2)continue;if(!ok(n.parentElement))continue;S.done.add(n);S.items.push({n,v});out.push(v.trim())}
document.querySelectorAll('[placeholder],[title],img[alt],input[type=submit][value],input[type=button][value],[aria-label]').forEach(e=>{if(out.length>=3000||!ok(e))return;let seen=S.attrs.get(e);if(!seen){seen=new Set();S.attrs.set(e,seen)}for(const a of ['placeholder','title','alt','value','aria-label']){if(seen.has(a))continue;if(a==='value'&&!(e.type==='submit'||e.type==='button'))continue;const v=e.getAttribute(a);if(!v||!L.test(v)||v.trim().length<2)continue;seen.add(a);S.items.push({e,a,v});out.push(v.trim())}});
return JSON.stringify({base,texts:out})})()`

// ---------------------------------------------------------------- history

type histEntry struct {
	URL   string `json:"u"`
	Title string `json:"t"`
	T     int64  `json:"at"`
}

type historyStore struct {
	mu      sync.Mutex
	items   []histEntry // oldest first
	path    string
	persist bool
	dirty   bool
}

func historyPath(id string) string { return filepath.Join(profileDir(id), "history.dat") }

func loadHistory(id string, persist bool) *historyStore {
	h := &historyStore{path: historyPath(id), persist: persist}
	if !persist {
		return h
	}
	if b, err := os.ReadFile(h.path); err == nil {
		if plain, err := unprotect(b); err == nil {
			json.Unmarshal(plain, &h.items)
		}
	}
	return h
}

// add records a visit (repeat visits move to the top).
func (h *historyStore) add(u, title string, now time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if n := len(h.items); n > 0 && h.items[n-1].URL == u {
		h.items[n-1].T = now.Unix()
		if title != "" {
			h.items[n-1].Title = title
		}
		h.dirty = true
		return
	}
	h.items = append(h.items, histEntry{URL: u, Title: title, T: now.Unix()})
	if len(h.items) > 5000 {
		h.items = h.items[len(h.items)-5000:]
	}
	h.dirty = true
}

func (h *historyStore) setTitle(u, title string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for i := len(h.items) - 1; i >= 0 && i >= len(h.items)-5; i-- {
		if h.items[i].URL == u && title != "" && h.items[i].Title != title {
			h.items[i].Title = title
			h.dirty = true
			return
		}
	}
}

// search returns newest-first matches (empty q = all).
func (h *historyStore) search(q string, limit int) []histEntry {
	h.mu.Lock()
	defer h.mu.Unlock()
	q = strings.ToLower(strings.TrimSpace(q))
	var out []histEntry
	for i := len(h.items) - 1; i >= 0 && len(out) < limit; i-- {
		e := h.items[i]
		if q == "" || strings.Contains(strings.ToLower(e.Title), q) || strings.Contains(strings.ToLower(e.URL), q) {
			out = append(out, e)
		}
	}
	return out
}

func (h *historyStore) remove(u string, at int64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := h.items[:0]
	for _, e := range h.items {
		if !(e.URL == u && (at == 0 || e.T == at)) {
			out = append(out, e)
		}
	}
	h.items = out
	h.dirty = true
}

func (h *historyStore) clear() {
	h.mu.Lock()
	h.items, h.dirty = nil, true
	h.mu.Unlock()
	os.Remove(h.path)
}

func (h *historyStore) save() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.persist || !h.dirty {
		return
	}
	h.dirty = false
	b, _ := json.Marshal(h.items)
	enc, err := protect(b)
	if err != nil {
		return
	}
	if os.WriteFile(h.path+".tmp", enc, 0600) == nil {
		os.Rename(h.path+".tmp", h.path)
	}
}

func (h *historyStore) setPersist(on bool) {
	h.mu.Lock()
	h.persist, h.dirty = on, true
	h.mu.Unlock()
	if !on {
		os.Remove(h.path)
	}
}

// sortedLangs: a stable list helper for settings.
func sortedLangs(m []string) []string {
	out := append([]string(nil), m...)
	sort.Strings(out)
	return out
}
