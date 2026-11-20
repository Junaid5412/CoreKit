package main

// CoreKit Remote: let a device on the same Wi-Fi see and control this one (or the other
// way round). Attended only: the shared device shows a 6-digit code, every connection
// must be allowed on that device, a banner shows while it is controlled, and Stop ends
// it at once. There is no hidden or unattended mode.
//
// Wire format (TCP): [4-byte length][1-byte type][payload]
//   before pairing: type 'H' (handshake JSON) or 'X' (refusal JSON)
//   after pairing:  type 'E', payload = AES-GCM(type byte + body)
//     inner types: 'J' control JSON, 'F' screen frame (u32 w, u32 h, JPEG), 'A' frame ack, 'P' ping

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	remoteTCPPort  = 47811
	remoteUDPPort  = 47812
	remoteMaxFrame = 16 << 20
	remoteProto    = 1
)

var errNotThisHost = errors.New("not this host")

// ---------------------------------------------------------------- framing

func writeFrame(w io.Writer, typ byte, body []byte) error {
	h := make([]byte, 5)
	binary.BigEndian.PutUint32(h, uint32(len(body)+1))
	h[4] = typ
	_, err := w.Write(append(h, body...))
	return err
}

func readFrame(r io.Reader) (byte, []byte, error) {
	h := make([]byte, 4)
	if _, err := io.ReadFull(r, h); err != nil {
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(h)
	if n < 1 || n > remoteMaxFrame {
		return 0, nil, errors.New("bad frame size")
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return 0, nil, err
	}
	return b[0], b[1:], nil
}

// ---------------------------------------------------------------- an encrypted, paired connection

type rLink struct {
	c      net.Conn
	r      *bufio.Reader
	wmu    sync.Mutex
	tx, rx *aeadDir
}

func (l *rLink) send(typ byte, body []byte) error {
	l.wmu.Lock()
	defer l.wmu.Unlock()
	l.c.SetWriteDeadline(time.Now().Add(15 * time.Second))
	return writeFrame(l.c, 'E', l.tx.seal(append([]byte{typ}, body...)))
}

func (l *rLink) sendJSON(v any) error { b, _ := json.Marshal(v); return l.send('J', b) }

func (l *rLink) recv() (byte, []byte, error) {
	l.c.SetReadDeadline(time.Now().Add(25 * time.Second))
	t, b, err := readFrame(l.r)
	if err != nil {
		return 0, nil, err
	}
	if t != 'E' {
		return 0, nil, errors.New("unexpected frame")
	}
	p, err := l.rx.open(b)
	if err != nil || len(p) < 1 {
		return 0, nil, errors.New("message failed authentication")
	}
	return p[0], p[1:], nil
}

// ---------------------------------------------------------------- engine

type rPeer struct {
	Name string `json:"name"`
	Plat string `json:"plat"`
	IP   string `json:"ip"`
}

type rSession struct {
	role     string // "shared" (we are controlled) or "viewer" (we control)
	peer     rPeer
	link     *rLink
	since    time.Time
	w, h     int
	ctl      bool // the shared side can take input
	quality  atomic.Value
	inflight atomic.Int32
	tx, rx   atomic.Int64 // pictures sent (shared) / received (viewer)
	capErr   atomic.Value // shared: why the screen can't be captured (string)
	done     chan struct{}
	once     sync.Once
}

func (s *rSession) close() { s.once.Do(func() { close(s.done); s.link.c.Close() }) }

type rPending struct {
	id     string
	peer   rPeer
	answer chan bool
}

// rSub is one listener for events (the page, or the Android capture/input glue).
type rSub struct {
	ch    chan []byte   // control events
	frame atomic.Value  // latest frame event ([]byte), newer replaces older
	kick  chan struct{} // a new frame is waiting
	lite  bool          // frames as a small notice; the picture itself is fetched from "lastframe"
}

type rEngine struct {
	mu        sync.Mutex
	name      string
	plat      string
	hosting   bool
	code      string
	ln        net.Listener
	udp       *net.UDPConn
	port      int
	fails     []time.Time
	pending   *rPending
	sess      *rSession
	connCtx   context.CancelFunc
	stage     string
	a11y      bool // Android: control (accessibility) is on
	subs      map[*rSub]bool
	glue      map[*rSub]bool
	gFrame    []byte // Android: latest captured JPEG from the glue
	gW, gH    int
	gSeq      uint64
	vFrame    []byte // viewer: the latest picture received from the other device
	vW, vH    int
	vSeq      uint64
	inputs    []map[string]any // test builds: injected input
	shutdownd bool
}

var rEng = newREngine()

func newREngine() *rEngine {
	e := &rEngine{name: rDeviceName(), plat: rPlatform(), subs: map[*rSub]bool{}, glue: map[*rSub]bool{}}
	if n := strings.TrimSpace(os.Getenv("CK_NAME")); n != "" {
		e.name = n
	}
	return e
}

func newCode() string {
	n, _ := rand.Int(rand.Reader, big.NewInt(1000000))
	return fmt.Sprintf("%06d", n.Int64())
}

func randID() string { b := make([]byte, 6); rand.Read(b); return hex.EncodeToString(b) }

// ---------------------------------------------------------------- events

func (e *rEngine) subscribe(glue bool) *rSub { return e.subscribeAs(glue, false) }

func (e *rEngine) subscribeAs(glue, lite bool) *rSub {
	s := &rSub{ch: make(chan []byte, 128), kick: make(chan struct{}, 1), lite: lite}
	e.mu.Lock()
	if glue {
		e.glue[s] = true
	} else {
		e.subs[s] = true
	}
	e.mu.Unlock()
	return s
}

func (e *rEngine) unsubscribe(s *rSub) {
	e.mu.Lock()
	delete(e.subs, s)
	delete(e.glue, s)
	e.mu.Unlock()
}

func pushTo(set map[*rSub]bool, b []byte) {
	for s := range set {
		select {
		case s.ch <- b:
		default: // a stuck listener must not block the engine
		}
	}
}

func (e *rEngine) emit(v any) {
	b, _ := json.Marshal(v)
	e.mu.Lock()
	pushTo(e.subs, b)
	e.mu.Unlock()
}

func (e *rEngine) emitGlue(v any) {
	b, _ := json.Marshal(v)
	e.mu.Lock()
	pushTo(e.glue, b)
	e.mu.Unlock()
}

func (e *rEngine) emitFrame(w, h int, jpg []byte) {
	e.mu.Lock()
	e.vFrame, e.vW, e.vH = jpg, w, h
	e.vSeq++
	seq := e.vSeq
	var full, lite []byte
	for s := range e.subs {
		b := full
		if s.lite {
			if lite == nil {
				lite, _ = json.Marshal(map[string]any{"t": "frame", "w": w, "h": h, "seq": seq})
			}
			b = lite
		} else if b == nil {
			full, _ = json.Marshal(map[string]any{"t": "frame", "w": w, "h": h, "seq": seq, "d": base64.StdEncoding.EncodeToString(jpg)})
			b = full
		}
		s.frame.Store(b)
		select {
		case s.kick <- struct{}{}:
		default:
		}
	}
	e.mu.Unlock()
}

func (e *rEngine) toast(msg string, bad bool) {
	e.emit(map[string]any{"t": "toast", "msg": msg, "bad": bad})
}

func (e *rEngine) stateLocked() map[string]any {
	st := map[string]any{"t": "state", "me": rPeer{Name: e.name, Plat: e.plat, IP: localIP()}, "hosting": e.hosting, "port": e.port, "stage": e.stage, "a11y": e.a11y}
	if e.hosting {
		st["code"] = e.code
	}
	if e.pending != nil {
		st["pending"] = map[string]any{"id": e.pending.id, "peer": e.pending.peer}
	}
	if s := e.sess; s != nil {
		ce, _ := s.capErr.Load().(string)
		st["session"] = map[string]any{"role": s.role, "peer": s.peer, "since": s.since.Unix(), "w": s.w, "h": s.h, "ctl": s.ctl, "quality": s.quality.Load(), "tx": s.tx.Load(), "rx": s.rx.Load(), "capErr": ce}
	}
	return st
}

func (e *rEngine) sendState() {
	e.mu.Lock()
	st := e.stateLocked()
	e.mu.Unlock()
	e.emit(st)
}

// ---------------------------------------------------------------- sharing (being controlled)

func (e *rEngine) startHosting() error {
	e.mu.Lock()
	if e.hosting {
		e.mu.Unlock()
		return nil
	}
	e.mu.Unlock()
	rPrepareHost()
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", remoteTCPPort))
	if err != nil {
		if ln, err = net.Listen("tcp", ":0"); err != nil {
			return err
		}
	}
	udp, _ := net.ListenUDP("udp4", &net.UDPAddr{Port: remoteUDPPort})
	e.mu.Lock()
	e.hosting, e.ln, e.udp, e.port, e.code, e.fails = true, ln, udp, ln.Addr().(*net.TCPAddr).Port, newCode(), nil
	e.mu.Unlock()
	go e.acceptLoop(ln)
	if udp != nil {
		go e.discoveryResponder(udp)
	}
	logLine("+", "Remote: sharing this device")
	e.sendState()
	return nil
}

func (e *rEngine) stopHosting() {
	e.mu.Lock()
	ln, udp, p, s := e.ln, e.udp, e.pending, e.sess
	e.hosting, e.ln, e.udp, e.code, e.pending = false, nil, nil, "", nil
	e.mu.Unlock()
	if ln != nil {
		ln.Close()
	}
	if udp != nil {
		udp.Close()
	}
	if p != nil {
		select {
		case p.answer <- false:
		default:
		}
	}
	if s != nil && s.role == "shared" {
		s.link.sendJSON(map[string]any{"t": "bye", "why": "The other device stopped sharing."})
		s.close()
	}
	e.sendState()
}

func (e *rEngine) newCodeNow() {
	e.mu.Lock()
	if e.hosting {
		e.code, e.fails = newCode(), nil
	}
	e.mu.Unlock()
	e.sendState()
}

func (e *rEngine) discoveryResponder(u *net.UDPConn) {
	buf := make([]byte, 512)
	for {
		n, from, err := u.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if string(buf[:n]) != "CKR1?" {
			continue
		}
		e.mu.Lock()
		busy := e.sess != nil || e.pending != nil
		ans, _ := json.Marshal(map[string]any{"port": e.port, "name": e.name, "plat": e.plat, "busy": busy})
		e.mu.Unlock()
		u.WriteToUDP(append([]byte("CKR1!"), ans...), from)
	}
}

func (e *rEngine) acceptLoop(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go e.handleIncoming(c)
	}
}

func refuse(c net.Conn, why string) {
	b, _ := json.Marshal(map[string]string{"e": why})
	writeFrame(c, 'X', b)
	c.Close()
}

func (e *rEngine) tooManyFails() bool {
	cut := time.Now().Add(-5 * time.Minute)
	keep := e.fails[:0]
	for _, t := range e.fails {
		if t.After(cut) {
			keep = append(keep, t)
		}
	}
	e.fails = keep
	return len(e.fails) >= 8
}

func (e *rEngine) handleIncoming(c net.Conn) {
	ip, _, _ := net.SplitHostPort(c.RemoteAddr().String())
	c.SetDeadline(time.Now().Add(10 * time.Second))
	r := bufio.NewReader(c)
	t, b, err := readFrame(r)
	if err != nil || t != 'H' {
		c.Close()
		return
	}
	var h1 struct {
		V    int    `json:"v"`
		PA   string `json:"pa"`
		Name string `json:"name"`
		Plat string `json:"plat"`
	}
	if json.Unmarshal(b, &h1) != nil || h1.V != remoteProto {
		refuse(c, "version")
		return
	}
	e.mu.Lock()
	code, busy := e.code, e.sess != nil || e.pending != nil
	if e.tooManyFails() {
		e.code, e.fails = newCode(), nil
		code = e.code
		e.mu.Unlock()
		e.toast("Too many wrong codes were tried. A new code was made.", true)
		e.sendState()
		refuse(c, "locked")
		return
	}
	hosting := e.hosting
	e.mu.Unlock()
	if !hosting || code == "" {
		refuse(c, "off")
		return
	}
	if busy {
		refuse(c, "busy")
		return
	}
	pa, _ := hex.DecodeString(h1.PA)
	sp, _ := newSpake('B', code)
	keys, err := sp.finish(pa, "corekit-viewer", "corekit-shared")
	if err != nil {
		c.Close()
		return
	}
	h2, _ := json.Marshal(map[string]any{"pb": hex.EncodeToString(sp.msg), "name": e.name, "plat": e.plat, "conf": hex.EncodeToString(keys.confB)})
	if writeFrame(c, 'H', h2) != nil {
		c.Close()
		return
	}
	t, b, err = readFrame(r)
	var h3 struct {
		Conf string `json:"conf"`
	}
	got, _ := hex.DecodeString(func() string { json.Unmarshal(b, &h3); return h3.Conf }())
	if err != nil || t != 'H' || !hmac.Equal(got, keys.confA) {
		e.mu.Lock()
		e.fails = append(e.fails, time.Now())
		e.mu.Unlock()
		c.Close()
		return
	}
	tx, _ := newDir(keys.b2a)
	rx, _ := newDir(keys.a2b)
	link := &rLink{c: c, r: r, tx: tx, rx: rx}
	c.SetDeadline(time.Time{})
	peer := rPeer{Name: clip(h1.Name, 40), Plat: clip(h1.Plat, 12), IP: ip}

	// attended: the person at this device decides
	p := &rPending{id: randID(), peer: peer, answer: make(chan bool, 1)}
	e.mu.Lock()
	if e.pending != nil || e.sess != nil || !e.hosting {
		e.mu.Unlock()
		link.sendJSON(map[string]any{"t": "deny", "why": "busy"})
		c.Close()
		return
	}
	e.pending = p
	e.mu.Unlock()
	e.emit(map[string]any{"t": "request", "id": p.id, "peer": peer})
	e.emitGlue(map[string]any{"t": "request", "id": p.id, "peer": peer})
	e.sendState()
	logLine("*", "Remote: "+peer.Name+" asks to connect ("+ip+")")
	allow := false
	select {
	case allow = <-p.answer:
	case <-time.After(60 * time.Second):
	}
	e.mu.Lock()
	if e.pending == p {
		e.pending = nil
	}
	e.mu.Unlock()
	if !allow {
		link.sendJSON(map[string]any{"t": "deny"})
		c.Close()
		e.sendState()
		return
	}
	w, h := rScreenSize(e)
	s := &rSession{role: "shared", peer: peer, link: link, since: time.Now(), w: w, h: h, ctl: rCanControl(e), done: make(chan struct{})}
	s.quality.Store("auto")
	e.mu.Lock()
	e.sess = s
	e.mu.Unlock()
	link.sendJSON(map[string]any{"t": "accept", "name": e.name, "plat": e.plat, "w": w, "h": h, "ctl": s.ctl})
	e.emitGlue(map[string]any{"t": "session", "peer": peer})
	logLine("+", "Remote: "+peer.Name+" is now connected")
	e.sendState()
	go e.captureLoop(s)
	e.readLoop(s)
}

func clip(s string, n int) string {
	if r := []rune(strings.TrimSpace(s)); len(r) > n {
		return string(r[:n])
	}
	return strings.TrimSpace(s)
}

func (e *rEngine) answer(id string, allow bool) {
	e.mu.Lock()
	p := e.pending
	e.mu.Unlock()
	if p != nil && p.id == id {
		select {
		case p.answer <- allow:
		default:
		}
	}
}

// captureLoop streams the screen while the session lasts, never more than two frames
// ahead of the viewer (so a slow link drops frames instead of building a delay).
func (e *rEngine) captureLoop(s *rSession) {
	cap := rNewCapturer(e)
	defer cap.close()
	for {
		select {
		case <-s.done:
			return
		default:
		}
		q, _ := s.quality.Load().(string)
		qs := qualityOf(q)
		if s.inflight.Load() >= 2 {
			time.Sleep(15 * time.Millisecond)
			continue
		}
		start := time.Now()
		jpg, w, h, err := cap.grab(qs)
		if err != nil {
			if old, _ := s.capErr.Load().(string); old != err.Error() {
				s.capErr.Store(err.Error())
				logLine("!", "Remote: screen capture: "+err.Error())
				e.sendState()
			}
			time.Sleep(400 * time.Millisecond)
			continue
		}
		if jpg != nil {
			hdr := make([]byte, 8)
			binary.BigEndian.PutUint32(hdr, uint32(w))
			binary.BigEndian.PutUint32(hdr[4:], uint32(h))
			s.inflight.Add(1)
			if s.link.send('F', append(hdr, jpg...)) != nil {
				return
			}
			if s.tx.Add(1) == 1 {
				logLine("+", fmt.Sprintf("Remote: sending the screen (%dx%d)", w, h))
			}
			if old, _ := s.capErr.Load().(string); old != "" {
				s.capErr.Store("")
			}
		}
		if d := qs.every - time.Since(start); d > 0 {
			time.Sleep(d)
		}
	}
}

type rQuality struct {
	maxW, jpegQ int
	every       time.Duration
}

func qualityOf(q string) rQuality {
	switch q {
	case "fast":
		return rQuality{960, 45, 70 * time.Millisecond}
	case "sharp":
		return rQuality{1920, 80, 160 * time.Millisecond}
	}
	return rQuality{1366, 62, 90 * time.Millisecond}
}

// ---------------------------------------------------------------- controlling another device

type rCandidate struct {
	addr string
	peer rPeer
}

// discover finds CoreKit devices that are sharing on this network: a broadcast first,
// then (if nothing answers, e.g. broadcasts are filtered) a quick sweep of this subnet.
func discover(ctx context.Context) []rCandidate {
	var out []rCandidate
	seen := map[string]bool{}
	if u, err := net.ListenUDP("udp4", &net.UDPAddr{}); err == nil {
		dests := []string{"255.255.255.255"}
		if b := subnetBroadcast(); b != "" {
			dests = append(dests, b)
		}
		for i := 0; i < 2; i++ {
			for _, d := range dests {
				u.WriteToUDP([]byte("CKR1?"), &net.UDPAddr{IP: net.ParseIP(d), Port: remoteUDPPort})
			}
			time.Sleep(60 * time.Millisecond)
		}
		u.SetReadDeadline(time.Now().Add(900 * time.Millisecond))
		buf := make([]byte, 1024)
		for {
			n, from, err := u.ReadFromUDP(buf)
			if err != nil {
				break
			}
			if n < 5 || string(buf[:5]) != "CKR1!" {
				continue
			}
			var a struct {
				Port int    `json:"port"`
				Name string `json:"name"`
				Plat string `json:"plat"`
			}
			if json.Unmarshal(buf[5:n], &a) != nil || a.Port <= 0 {
				continue
			}
			addr := net.JoinHostPort(from.IP.String(), strconv.Itoa(a.Port))
			if !seen[addr] && !isOwn(from.IP.String(), a.Port) {
				seen[addr] = true
				out = append(out, rCandidate{addr, rPeer{Name: a.Name, Plat: a.Plat, IP: from.IP.String()}})
			}
		}
		u.Close()
	}
	if len(out) > 0 || ctx.Err() != nil {
		return out
	}
	// sweep x.y.z.1-254 on the standard port
	me := localIP()
	ip := net.ParseIP(me).To4()
	if ip == nil {
		return nil
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 64)
	for i := 1; i < 255; i++ {
		cand := fmt.Sprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], i)
		if cand == me {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(h string) {
			defer wg.Done()
			defer func() { <-sem }()
			d := net.Dialer{Timeout: 450 * time.Millisecond}
			c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(h, strconv.Itoa(remoteTCPPort)))
			if err != nil {
				return
			}
			c.Close()
			mu.Lock()
			out = append(out, rCandidate{net.JoinHostPort(h, strconv.Itoa(remoteTCPPort)), rPeer{IP: h}})
			mu.Unlock()
		}(cand)
	}
	wg.Wait()
	return out
}

func isOwn(ip string, port int) bool {
	rEng.mu.Lock()
	defer rEng.mu.Unlock()
	return rEng.hosting && port == rEng.port && ip == localIP()
}

// pair runs SPAKE2 with one candidate. errNotThisHost means its code is different.
func (e *rEngine) pair(ctx context.Context, addr, code string) (*rLink, rPeer, error) {
	d := net.Dialer{Timeout: 3 * time.Second}
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, rPeer{}, err
	}
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	r := bufio.NewReader(c)
	sp, _ := newSpake('A', code)
	h1, _ := json.Marshal(map[string]any{"v": remoteProto, "pa": hex.EncodeToString(sp.msg), "name": e.name, "plat": e.plat})
	if err := writeFrame(c, 'H', h1); err != nil {
		c.Close()
		return nil, rPeer{}, err
	}
	t, b, err := readFrame(r)
	if err != nil {
		c.Close()
		return nil, rPeer{}, err
	}
	if t == 'X' {
		var x struct {
			E string `json:"e"`
		}
		json.Unmarshal(b, &x)
		c.Close()
		switch x.E {
		case "busy":
			return nil, rPeer{}, errors.New("That device is already in a session.")
		case "locked":
			return nil, rPeer{}, errors.New("That device locked its code after too many tries. Ask for the new code.")
		case "version":
			return nil, rPeer{}, errors.New("That device runs a different CoreKit version. Update both devices.")
		}
		return nil, rPeer{}, errNotThisHost
	}
	var h2 struct {
		PB   string `json:"pb"`
		Name string `json:"name"`
		Plat string `json:"plat"`
		Conf string `json:"conf"`
	}
	if t != 'H' || json.Unmarshal(b, &h2) != nil {
		c.Close()
		return nil, rPeer{}, errNotThisHost
	}
	pb, _ := hex.DecodeString(h2.PB)
	keys, err := sp.finish(pb, "corekit-viewer", "corekit-shared")
	conf, _ := hex.DecodeString(h2.Conf)
	if err != nil || !hmac.Equal(conf, keys.confB) {
		c.Close()
		return nil, rPeer{}, errNotThisHost // a different code
	}
	h3, _ := json.Marshal(map[string]any{"conf": hex.EncodeToString(keys.confA)})
	if err := writeFrame(c, 'H', h3); err != nil {
		c.Close()
		return nil, rPeer{}, err
	}
	tx, _ := newDir(keys.a2b)
	rx, _ := newDir(keys.b2a)
	ip, _, _ := net.SplitHostPort(addr)
	c.SetDeadline(time.Time{})
	return &rLink{c: c, r: r, tx: tx, rx: rx}, rPeer{Name: clip(h2.Name, 40), Plat: clip(h2.Plat, 12), IP: ip}, nil
}

func (e *rEngine) setStage(s string) {
	e.mu.Lock()
	e.stage = s
	e.mu.Unlock()
	e.sendState()
}

// connect finds the device with this code and asks it for a session.
func (e *rEngine) connect(code, manual string) {
	code = strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, code)
	if len(code) != 6 {
		e.toast("Enter the 6-digit code shown on the other device.", true)
		return
	}
	e.mu.Lock()
	if e.sess != nil || e.connCtx != nil {
		e.mu.Unlock()
		e.toast("Finish the current session first.", true)
		return
	}
	if e.hosting && e.code == code {
		e.mu.Unlock()
		e.toast("That is this device's own code. Enter it on the other device.", true)
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	e.connCtx = cancel
	e.mu.Unlock()
	go func() {
		defer func() {
			e.mu.Lock()
			e.connCtx = nil
			e.stage = ""
			e.mu.Unlock()
			cancel()
			e.sendState()
		}()
		fail := func(msg string) {
			if ctx.Err() == nil {
				e.emit(map[string]any{"t": "connfail", "msg": msg})
			}
		}
		var cands []rCandidate
		if m := strings.TrimSpace(manual); m != "" {
			if _, _, err := net.SplitHostPort(m); err != nil {
				m = net.JoinHostPort(m, strconv.Itoa(remoteTCPPort))
			}
			h, _, _ := net.SplitHostPort(m)
			cands = []rCandidate{{m, rPeer{IP: h}}}
		} else {
			e.setStage("search")
			cands = discover(ctx)
		}
		if ctx.Err() != nil {
			return
		}
		if len(cands) == 0 {
			fail("No device is sharing on this Wi-Fi. On the other device open Remote Access and tap Start sharing, and make sure both are on the same network.")
			return
		}
		e.setStage("pair")
		var link *rLink
		var peer rPeer
		var lastErr error
		for _, cd := range cands {
			l, p, err := e.pair(ctx, cd.addr, code)
			if err == nil {
				link, peer = l, p
				break
			}
			lastErr = err
			if err != errNotThisHost && !isNetErr(err) {
				break
			}
		}
		if link == nil {
			switch {
			case ctx.Err() != nil:
			case lastErr == errNotThisHost && len(cands) == 1:
				fail("Wrong code. Check the code on " + nonEmpty(cands[0].peer.Name, "the other device") + " and try again.")
			case lastErr == errNotThisHost || isNetErr(lastErr):
				fail("No sharing device on this Wi-Fi has that code. Check the code and try again.")
			default:
				fail(lastErr.Error())
			}
			return
		}
		e.setStage("wait")
		e.emit(map[string]any{"t": "waiting", "peer": peer})
		link.c.SetReadDeadline(time.Now().Add(75 * time.Second))
		t, b, err := link.recv()
		if err != nil || t != 'J' {
			link.c.Close()
			fail("The other device did not answer.")
			return
		}
		var m struct {
			T    string `json:"t"`
			Name string `json:"name"`
			Plat string `json:"plat"`
			W    int    `json:"w"`
			H    int    `json:"h"`
			Ctl  bool   `json:"ctl"`
		}
		json.Unmarshal(b, &m)
		if m.T != "accept" {
			link.c.Close()
			fail(nonEmpty(peer.Name, "The other device") + " declined the connection.")
			return
		}
		s := &rSession{role: "viewer", peer: peer, link: link, since: time.Now(), w: m.W, h: m.H, ctl: m.Ctl, done: make(chan struct{})}
		s.quality.Store("auto")
		e.mu.Lock()
		if ctx.Err() != nil {
			e.mu.Unlock()
			link.c.Close()
			return
		}
		e.sess = s
		e.connCtx = nil
		e.stage = ""
		e.mu.Unlock()
		logLine("+", "Remote: connected to "+peer.Name)
		e.sendState()
		go e.readLoop(s)
	}()
}

func isNetErr(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) || errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed)
}

func nonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

func (e *rEngine) cancelConnect() {
	e.mu.Lock()
	c := e.connCtx
	e.mu.Unlock()
	if c != nil {
		c()
	}
}

// ---------------------------------------------------------------- the session itself

func (e *rEngine) readLoop(s *rSession) {
	why := ""
	go func() { // keep-alive, and fresh counters for the pages
		t := time.NewTicker(3 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-s.done:
				return
			case <-t.C:
				if s.link.send('P', nil) != nil {
					return
				}
				e.sendState()
			}
		}
	}()
	for {
		t, b, err := s.link.recv()
		if err != nil {
			if why == "" {
				why = "The connection was lost."
			}
			break
		}
		switch t {
		case 'F': // a screen frame (we are the viewer)
			if len(b) > 8 && s.role == "viewer" {
				w, h := int(binary.BigEndian.Uint32(b)), int(binary.BigEndian.Uint32(b[4:]))
				s.link.send('A', nil)
				s.rx.Add(1)
				e.mu.Lock()
				if s.w != w || s.h != h {
					s.w, s.h = w, h
				}
				e.mu.Unlock()
				e.emitFrame(w, h, b[8:])
			}
		case 'A':
			if s.inflight.Add(-1) < 0 {
				s.inflight.Store(0)
			}
		case 'J':
			var m map[string]any
			if json.Unmarshal(b, &m) != nil {
				continue
			}
			switch m["t"] {
			case "in": // input from the viewer (we are shared)
				if s.role == "shared" && s.ctl {
					rInject(e, m)
				}
			case "quality":
				if q, _ := m["q"].(string); q == "fast" || q == "sharp" || q == "auto" {
					s.quality.Store(q)
					if s.role == "shared" {
						rQualityChanged(e, q)
					}
				}
			case "sig": // call signalling, relayed to our page
				e.emit(map[string]any{"t": "sig", "data": m["data"]})
			case "info":
				if c, ok := m["ctl"].(bool); ok && s.role == "viewer" {
					e.mu.Lock()
					s.ctl = c
					e.mu.Unlock()
					e.sendState()
				}
			case "bye":
				why, _ = m["why"].(string)
				if why == "" {
					why = s.peer.Name + " ended the session."
				}
				s.close()
			}
		}
	}
	s.close()
	e.mu.Lock()
	if e.sess == s {
		e.sess = nil
		e.vFrame = nil
	}
	e.mu.Unlock()
	e.emit(map[string]any{"t": "bye", "why": why})
	e.emitGlue(map[string]any{"t": "capture", "on": false})
	if s.role == "shared" {
		e.emitGlue(map[string]any{"t": "session", "peer": nil})
	}
	logLine("*", "Remote: session ended")
	e.sendState()
}

func (e *rEngine) disconnect(why string) {
	e.mu.Lock()
	s := e.sess
	e.mu.Unlock()
	if s == nil {
		return
	}
	if why == "" {
		why = e.name + " ended the session."
	}
	s.link.sendJSON(map[string]any{"t": "bye", "why": why})
	time.Sleep(60 * time.Millisecond)
	s.close()
}

func (e *rEngine) session() *rSession {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.sess
}

// ---------------------------------------------------------------- commands (from the page / glue)

func (e *rEngine) command(m map[string]any) {
	str := func(k string) string { s, _ := m[k].(string); return s }
	switch str("t") {
	case "state":
		e.sendState()
	case "host":
		if on, _ := m["on"].(bool); on {
			if err := e.startHosting(); err != nil {
				e.toast("Sharing could not start: "+err.Error(), true)
			}
		} else {
			e.stopHosting()
		}
	case "newcode":
		e.newCodeNow()
	case "answer":
		allow, _ := m["allow"].(bool)
		e.answer(str("id"), allow)
	case "connect":
		e.connect(str("code"), str("ip"))
	case "cancel":
		e.cancelConnect()
	case "disconnect":
		e.disconnect("")
	case "in":
		if s := e.session(); s != nil && s.role == "viewer" {
			s.link.sendJSON(m)
		}
	case "quality":
		if s := e.session(); s != nil {
			q := str("q")
			s.quality.Store(q)
			s.link.sendJSON(map[string]any{"t": "quality", "q": q})
			e.sendState()
		}
	case "sig":
		if s := e.session(); s != nil {
			s.link.sendJSON(map[string]any{"t": "sig", "data": m["data"]})
		}
	case "glue": // Android: control (accessibility) switched on/off
		if a, ok := m["a11y"].(bool); ok {
			e.mu.Lock()
			e.a11y = a
			s := e.sess
			if s != nil && s.role == "shared" {
				s.ctl = a
			}
			e.mu.Unlock()
			if s != nil && s.role == "shared" {
				s.link.sendJSON(map[string]any{"t": "info", "ctl": a})
			}
			e.sendState()
		}
	}
}

func (e *rEngine) shutdown() {
	e.cancelConnect()
	e.disconnect("")
	e.stopHosting()
}

// ---------------------------------------------------------------- local API (page and glue)

// mountRemote adds the local API under prefix (e.g. "/<token>/api/remote/").
func mountRemote(mux *http.ServeMux, prefix string, auth func(*http.Request) bool) {
	ok := func(w http.ResponseWriter, r *http.Request) bool {
		if auth != nil && !auth(r) {
			http.Error(w, "forbidden", 403)
			return false
		}
		return true
	}
	mux.HandleFunc(prefix+"events", func(w http.ResponseWriter, r *http.Request) {
		if ok(w, r) {
			serveEvents(w, r, false)
		}
	})
	mux.HandleFunc(prefix+"lastframe", func(w http.ResponseWriter, r *http.Request) { // the newest picture, as a plain JPEG
		if !ok(w, r) {
			return
		}
		rEng.mu.Lock()
		f, fw, fh, seq := rEng.vFrame, rEng.vW, rEng.vH, rEng.vSeq
		rEng.mu.Unlock()
		w.Header().Set("Cache-Control", "no-store")
		if len(f) == 0 {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Content-Type", "image/jpeg")
		w.Header().Set("X-W", strconv.Itoa(fw))
		w.Header().Set("X-H", strconv.Itoa(fh))
		w.Header().Set("X-Seq", strconv.FormatUint(seq, 10))
		w.Header().Set("Content-Length", strconv.Itoa(len(f)))
		w.Write(f)
	})
	mux.HandleFunc(prefix+"glue", func(w http.ResponseWriter, r *http.Request) {
		if ok(w, r) {
			serveEvents(w, r, true)
		}
	})
	mux.HandleFunc(prefix+"state", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		rEng.mu.Lock()
		st := rEng.stateLocked()
		rEng.mu.Unlock()
		writeJSON(w, st)
	})
	mux.HandleFunc(prefix+"cmd", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		var m map[string]any
		if r.Method != http.MethodPost || json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&m) != nil {
			http.Error(w, "bad", 400)
			return
		}
		rEng.command(m)
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc(prefix+"frame", func(w http.ResponseWriter, r *http.Request) { // Android capture glue
		if !ok(w, r) || r.Method != http.MethodPost {
			return
		}
		b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 8<<20))
		if err != nil || len(b) < 4 {
			http.Error(w, "bad", 400)
			return
		}
		fw, _ := strconv.Atoi(r.Header.Get("X-W"))
		fh, _ := strconv.Atoi(r.Header.Get("X-H"))
		rEng.mu.Lock()
		rEng.gFrame, rEng.gW, rEng.gH = b, fw, fh
		rEng.gSeq++
		rEng.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})
}

func serveEvents(w http.ResponseWriter, r *http.Request, glue bool) {
	fl, okf := w.(http.Flusher)
	if !okf {
		http.Error(w, "stream", 500)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	s := rEng.subscribeAs(glue, r.URL.Query().Get("lite") == "1")
	defer rEng.unsubscribe(s)
	write := func(b []byte) bool {
		if _, err := fmt.Fprintf(w, "data: %s\n\n", b); err != nil {
			return false
		}
		fl.Flush()
		return true
	}
	rEng.mu.Lock()
	st, _ := json.Marshal(rEng.stateLocked())
	rEng.mu.Unlock()
	if !write(st) {
		return
	}
	ping := time.NewTicker(15 * time.Second)
	defer ping.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case b := <-s.ch:
			if !write(b) {
				return
			}
		case <-s.kick:
			if f, _ := s.frame.Swap([]byte(nil)).([]byte); len(f) > 0 && !write(f) {
				return
			}
		case <-ping.C:
			if _, err := fmt.Fprint(w, ": ping\n\n"); err != nil {
				return
			}
			fl.Flush()
		}
	}
}

// ---------------------------------------------------------------- network helpers

// localIP is this device's Wi-Fi / LAN address (no packet is sent).
func localIP() string {
	c, err := net.Dial("udp4", "10.255.255.255:1")
	if err == nil {
		defer c.Close()
		if a, ok := c.LocalAddr().(*net.UDPAddr); ok && !a.IP.IsLoopback() {
			return a.IP.String()
		}
	}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil && !n.IP.IsLoopback() && !n.IP.IsLinkLocalUnicast() {
				return n.IP.String()
			}
		}
	}
	return ""
}

// subnetBroadcast assumes the usual /24 home network when the mask can't be read.
func subnetBroadcast() string {
	ip := net.ParseIP(localIP()).To4()
	if ip == nil {
		return ""
	}
	if ifs, err := net.Interfaces(); err == nil {
		for _, i := range ifs {
			addrs, _ := i.Addrs()
			for _, a := range addrs {
				if n, ok := a.(*net.IPNet); ok && n.IP.Equal(ip) {
					b := make(net.IP, 4)
					for k := 0; k < 4; k++ {
						b[k] = ip[k] | ^n.Mask[len(n.Mask)-4+k]
					}
					return b.String()
				}
			}
		}
	}
	return fmt.Sprintf("%d.%d.%d.255", ip[0], ip[1], ip[2])
}

// runRemoteEngine is the Android mode: a long-running engine with a loopback API that
// the app forwards the page to. Prints "READY <port>" once listening.
func runRemoteEngine() int {
	helperResolver() // DNS on Android (no /etc/resolv.conf)
	tok := os.Getenv("CK_TOKEN")
	if len(tok) < 16 {
		fmt.Println("ERR token")
		return 2
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Println("ERR " + err.Error())
		return 1
	}
	mux := http.NewServeMux()
	mountRemote(mux, "/", func(r *http.Request) bool {
		k := r.Header.Get("X-CK")
		if k == "" {
			k = r.URL.Query().Get("k")
		}
		return hmac.Equal([]byte(k), []byte(tok))
	})
	fmt.Printf("READY %d\n", ln.Addr().(*net.TCPAddr).Port)
	os.Stdout.Sync()
	// stop when the app goes away (its end of our stdin closes)
	go func() { io.Copy(io.Discard, os.Stdin); rEng.shutdown(); os.Exit(0) }()
	_ = http.Serve(ln, mux)
	return 0
}

// rCapturer grabs the screen as JPEG; nil bytes mean "unchanged, nothing to send".
type rCapturer interface {
	grab(q rQuality) ([]byte, int, int, error)
	close()
}
