package main

// Helper mode: `corekit --helper <command>` runs one piece of the shared Go code for the
// Android app (JSON request on stdin, JSON answer on stdout). This keeps proxy-link parsing,
// Xray configuration, tunnel/leak checks, location lookup and translation identical on
// every platform.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync/atomic"
	"time"
)

type helperReq struct {
	Link      string   `json:"link"`
	Port      int      `json:"port"`
	Country   string   `json:"country"`
	Input     string   `json:"input"`
	Engine    string   `json:"engine"`
	Lang      string   `json:"lang"`
	GoogleFix bool     `json:"googleFix"`
	URL       string   `json:"url"`
	Texts     []string `json:"texts"`
	To        string   `json:"to"`
	Sample    string   `json:"sample"`
	TZ        string   `json:"tz"`
	Cands     []string `json:"cands"`
	IP        string   `json:"ip"`
	Bypass    string   `json:"bypass"`
	Path      string   `json:"path"`
}

// helperClient reaches the internet through the tunnel's HTTP inbound when a port is given.
func helperClient(port int, timeout time.Duration) *http.Client {
	if port > 0 {
		pu, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", port+1))
		return &http.Client{Timeout: timeout, Transport: &http.Transport{Proxy: http.ProxyURL(pu)}}
	}
	return &http.Client{Timeout: timeout}
}

// Android has no /etc/resolv.conf, so Go's resolver would ask 127.0.0.1 and fail with
// "connection refused". The app passes the network's DNS servers in CK_DNS
// (comma-separated); public resolvers are the fallback (the network can change while
// the engine runs).
func helperResolver() {
	var servers []string
	for _, s := range strings.Split(os.Getenv("CK_DNS"), ",") {
		if s = strings.Trim(strings.TrimSpace(s), "[]"); s != "" && net.ParseIP(s) != nil {
			servers = append(servers, net.JoinHostPort(s, "53"))
		}
	}
	if b, err := os.ReadFile("/etc/resolv.conf"); err == nil && os.Getenv("CK_NO_RESOLV") == "" { // outside Android
		for _, l := range strings.Split(string(b), "\n") {
			if f := strings.Fields(l); len(f) >= 2 && f[0] == "nameserver" && net.ParseIP(strings.Split(f[1], "%")[0]) != nil {
				servers = append(servers, net.JoinHostPort(strings.Split(f[1], "%")[0], "53"))
			}
		}
	}
	servers = append(servers, "1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53")
	var next atomic.Uint32
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		// UDP "connects" even to a dead server, so each new try (Go retries a query with a
		// fresh Dial) starts at the next server: a stale or silent one can't block lookups
		start := int(next.Add(1)-1) % len(servers)
		var last error
		for i := range servers {
			s := servers[(start+i)%len(servers)]
			d := net.Dialer{Timeout: 3 * time.Second}
			c, err := d.DialContext(ctx, network, s)
			if err != nil {
				last = err
				continue
			}
			return c, nil // (a plain *net.UDPConn: Go only speaks UDP DNS over a PacketConn)
		}
		return nil, last
	}}
}

func runHelper(cmd string) int {
	helperResolver()
	var r helperReq
	b, _ := io.ReadAll(io.LimitReader(os.Stdin, 32<<20))
	if len(strings.TrimSpace(string(b))) > 0 {
		if err := json.Unmarshal(b, &r); err != nil {
			return helperOut(map[string]any{"error": "bad request: " + err.Error()})
		}
	}
	switch cmd {
	case "inspect": // Security › reverse view of one file (Android app)
		os.Stdout.Write(inspectJSON(r.Path))
		os.Stdout.Write([]byte("\n"))
		return 0
	case "trace": // Security › public registration records for the servers found in a file
		rep := inspectFile(r.Path, inPlat{})
		ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
		defer cancel()
		return helperOut(map[string]any{"items": traceHosts(ctx, rep.Servers)})
	case "parse":
		_, kind, name, err := parseProxy(strings.TrimSpace(r.Link))
		if err != nil {
			return helperOut(map[string]any{"error": err.Error()})
		}
		return helperOut(map[string]any{"kind": kind, "name": name})
	case "xray-config":
		out, _, _, err := parseProxy(strings.TrimSpace(r.Link))
		if err != nil {
			return helperOut(map[string]any{"error": err.Error()})
		}
		os.Stdout.Write(xrayConfig(out, r.Port))
		return 0
	case "tunnel": // IP and latency seen through the tunnel (no direct request)
		cl := helperClient(r.Port, 15*time.Second)
		var times []int
		var info map[string]string
		var last error
		for i := 0; i < 3; i++ {
			kv, ms, err := cfTrace(cl)
			if err != nil {
				last = err
				continue
			}
			info, times = kv, append(times, ms)
		}
		if info == nil {
			msg := "no connection through proxy"
			if last != nil {
				msg = shortErr(last)
			}
			return helperOut(map[string]any{"ok": false, "error": msg})
		}
		sort.Ints(times)
		return helperOut(map[string]any{"ok": true, "ip": info["ip"], "country": info["loc"], "ms": times[len(times)/2]})
	case "geo":
		g := geoLookup(r.Port, r.Country)
		return helperOut(map[string]any{"tz": g.TZ, "lat": g.Lat, "lon": g.Lon, "hasLoc": g.HasLoc, "country": g.Country})
	case "normalize":
		u := normalizeInput(r.Input, r.Engine)
		if r.GoogleFix {
			if f, ok := googleFix(u, r.Lang); ok {
				u = f
			}
		}
		return helperOut(map[string]any{"url": u})
	case "googlefix":
		f, ok := googleFix(r.URL, r.Lang)
		return helperOut(map[string]any{"url": f, "changed": ok})
	case "translate":
		tr := &translator{client: func() *http.Client { return helperClient(r.Port, 20*time.Second) }}
		out := make([]any, len(r.Texts))
		det, err := tr.translateAll(r.Texts, r.To, func(idx []int, vals []string) {
			for k, i := range idx {
				out[i] = vals[k]
			}
		})
		if err != nil {
			return helperOut(map[string]any{"error": err.Error()})
		}
		return helperOut(map[string]any{"out": out, "detected": det})
	case "detect":
		tr := &translator{client: func() *http.Client { return helperClient(r.Port, 10*time.Second) }}
		return helperOut(map[string]any{"lang": tr.detect(r.Sample)})
	case "scripts":
		return helperOut(map[string]any{"collect": collectScript, "detect": detectScript, "privacy": privacyScript,
			"webrtc": webrtcProbe, "tz": tzSpoofScript(r.TZ), "noWebrtc": noWebRTCScript,
			"adCss": adCosmeticScript, "adHosts": adDomains, "lang": langMatchScript(r.Country), "langList": langMatchList(r.Country)})
	case "leaky":
		for _, c := range r.Cands {
			if leakyCandidate(c, r.IP) {
				return helperOut(map[string]any{"leak": true})
			}
		}
		return helperOut(map[string]any{"leak": false})
	case "info":
		langs := []map[string]string{}
		for _, l := range uiLanguages {
			langs = append(langs, map[string]string{"Code": l.Code, "Name": l.Name})
		}
		engines := []map[string]string{}
		for _, e := range searchEngines {
			engines = append(engines, map[string]string{"id": e.ID, "name": e.Name, "url": e.URL})
		}
		names := map[string]string{}
		for k, v := range langNames {
			names[k] = v
		}
		return helperOut(map[string]any{"version": appVersion, "langs": langs, "engines": engines, "langNames": names, "colors": profileColors})
	}
	return helperOut(map[string]any{"error": "unknown command " + cmd})
}

func helperOut(v any) int {
	b, _ := json.Marshal(v)
	os.Stdout.Write(b)
	os.Stdout.Write([]byte("\n"))
	return 0
}

// noWebRTCScript removes WebRTC from pages (Android's web engine cannot force WebRTC
// through the proxy, so it is switched off while the proxy is on).
const noWebRTCScript = `(()=>{for(const k of ['RTCPeerConnection','webkitRTCPeerConnection','RTCDataChannel','RTCSessionDescription','RTCIceCandidate']){try{Object.defineProperty(window,k,{value:undefined,configurable:false,writable:false})}catch(e){}}try{if(navigator.mediaDevices){navigator.mediaDevices.getUserMedia=()=>Promise.reject(new DOMException('Blocked by CoreKit','NotAllowedError'))}}catch(e){}})();`

// tzSpoofScript makes pages see the given time zone (Android: no DevTools override).
func tzSpoofScript(tz string) string {
	if !validTZ(tz) {
		return ""
	}
	return strings.ReplaceAll(tzSpoofTemplate, "__TZ__", tz)
}

const tzSpoofTemplate = `(()=>{const TZ="__TZ__";try{
const DTF=Intl.DateTimeFormat;
const P=function DateTimeFormat(l,o){o=Object.assign({},o||{});if(!o.timeZone)o.timeZone=TZ;return new DTF(l,o)};
P.prototype=DTF.prototype;P.supportedLocalesOf=DTF.supportedLocalesOf;
Object.defineProperty(Intl,'DateTimeFormat',{value:P,configurable:true,writable:true});
const F=new DTF('en-US',{timeZone:TZ,hourCycle:'h23',year:'numeric',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',second:'2-digit'});
const NM=new DTF('en-US',{timeZone:TZ,timeZoneName:'long'});
const off=d=>{const t=d.getTime();if(isNaN(t))return NaN;const p={};for(const x of F.formatToParts(d))p[x.type]=x.value;return Math.round((t-Date.UTC(+p.year,+p.month-1,+p.day,+p.hour%24,+p.minute,+p.second))/60000)};
const D=Date.prototype,sh=d=>new Date(d.getTime()-off(d)*60000);
const def=(k,f)=>{try{Object.defineProperty(D,k,{value:f,configurable:true,writable:true})}catch(e){}};
def('getTimezoneOffset',function(){return off(this)});
for(const[k,u]of[['getFullYear','getUTCFullYear'],['getMonth','getUTCMonth'],['getDate','getUTCDate'],['getDay','getUTCDay'],['getHours','getUTCHours'],['getMinutes','getUTCMinutes'],['getSeconds','getUTCSeconds']])def(k,function(){return isNaN(this)?NaN:D[u].call(sh(this))});
const pad=n=>String(n).padStart(2,'0');
const gmt=d=>{const o=-off(d);return 'GMT'+(o>=0?'+':'-')+pad(Math.floor(Math.abs(o)/60))+pad(Math.abs(o)%60)};
const name=d=>{const p=NM.formatToParts(d).find(x=>x.type==='timeZoneName');return p?p.value:TZ};
const W=['Sun','Mon','Tue','Wed','Thu','Fri','Sat'],M=['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
const ds=d=>{const s=sh(d);return W[s.getUTCDay()]+' '+M[s.getUTCMonth()]+' '+pad(s.getUTCDate())+' '+s.getUTCFullYear()};
const ts=d=>{const s=sh(d);return pad(s.getUTCHours())+':'+pad(s.getUTCMinutes())+':'+pad(s.getUTCSeconds())+' '+gmt(d)+' ('+name(d)+')'};
def('toString',function(){return isNaN(this)?'Invalid Date':ds(this)+' '+ts(this)});
def('toDateString',function(){return isNaN(this)?'Invalid Date':ds(this)});
def('toTimeString',function(){return isNaN(this)?'Invalid Date':ts(this)});
for(const k of['toLocaleString','toLocaleDateString','toLocaleTimeString']){const o=D[k];def(k,function(l,opt){opt=Object.assign({},opt||{});if(!opt.timeZone)opt.timeZone=TZ;return o.call(this,l,opt)})}
}catch(e){}})();`
