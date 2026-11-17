package main

// Virtual Environment: a separate Android (Android-x86, slimmed by CoreKit's build) that runs
// inside QEMU with root, no screen, just a console. The same engine runs on Windows (QEMU
// downloaded on first use, Hyper-V acceleration when available) and on Android (QEMU shipped
// in the APK, software emulation).
//
// Layout under vmRoot():
//   images/<image>.iso            downloaded system images (read-only, shared by machines)
//   images/<image>.ckt            empty data-disk template (ext4, sparse)
//   machines/<id>/machine.json    name, image, RAM, CPUs
//   machines/<id>/data.img        the machine's /data (apps, files) – sparse
//   qemu/                         Windows only: the emulator

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ------------------------------------------------------------------ catalogue

type vmImage struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Android string `json:"android"`
	Note    string `json:"note"`
	URL     string `json:"-"`
	SHA256  string `json:"-"`
	Size    int64  `json:"size"`
	TplURL  string `json:"-"`
	TplSHA  string `json:"-"`
	MinRAM  int    `json:"minRam"`
}

const vmRelease = "https://github.com/Junaid5412/CoreKit/releases/download/vm-images/"

// vmCatalogue lists the images CoreKit can download. Hashes are pinned: a changed or
// corrupted download is refused.
var vmCatalogue = []vmImage{
	{ID: "android9-lite", Name: "Android 9 Lite", Android: "9", Note: "64-bit · root · recommended",
		URL: vmRelease + "android9-lite.iso", SHA256: vmPin["android9-lite.iso"], Size: vmSize["android9-lite.iso"],
		TplURL: vmRelease + "data8g.ckt", TplSHA: vmPin["data8g.ckt"], MinRAM: 1536},
}

// set from the vm-images release (see tools/vm); empty pins mean "not published yet"
var vmPin = map[string]string{}
var vmSize = map[string]int64{}

func vmImageByID(id string) *vmImage {
	for i := range vmCatalogue {
		if vmCatalogue[i].ID == id {
			return &vmCatalogue[i]
		}
	}
	return nil
}

// ------------------------------------------------------------------ paths & host

func vmRoot() string {
	if d := os.Getenv("CK_VMDIR"); d != "" {
		return d
	}
	if runtime.GOOS == "windows" {
		if d := os.Getenv("LOCALAPPDATA"); d != "" {
			return filepath.Join(d, "CoreKit", "VirtualEnv")
		}
	}
	h, _ := os.UserHomeDir()
	return filepath.Join(h, ".corekit", "virtualenv")
}

type vmQemu struct {
	exe   string
	env   []string
	pre   []string // arguments before ours (e.g. -L share)
	accel string
}

// vmFindQemu says how to run the emulator here, or why it can't.
func vmFindQemu() (*vmQemu, error) {
	if exe := os.Getenv("CK_QEMU"); exe != "" { // Android: shipped in the APK
		q := &vmQemu{exe: exe, accel: "tcg,thread=multi,tb-size=512"}
		if lib := os.Getenv("CK_QEMU_LIB"); lib != "" {
			q.env = append(q.env, "LD_LIBRARY_PATH="+lib)
		}
		if sh := os.Getenv("CK_QEMU_SHARE"); sh != "" {
			q.pre = append(q.pre, "-L", sh)
		}
		tmp := filepath.Join(vmRoot(), "tmp")
		os.MkdirAll(tmp, 0700)
		q.env = append(q.env, "TMPDIR="+tmp, "HOME="+vmRoot())
		return q, nil
	}
	return vmPlatformQemu()
}

// ------------------------------------------------------------------ machines

type vmMachine struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Image   string `json:"image"`
	RAM     int    `json:"ram"`
	CPUs    int    `json:"cpus"`
	Created int64  `json:"created"`
	LastRun int64  `json:"lastRun"`
}

type vmRun struct {
	m       *vmMachine
	cmd     *exec.Cmd
	cancel  context.CancelFunc
	state   string // starting, booting, running, stopping
	detail  string
	started time.Time
	bootSec int
	con     net.Conn
	auto    *vmAuto
	term    *vmRing
	exited  chan struct{}
	accel   string
	ip      string
	qmpPort int
	resumed bool
}

type vmDL struct {
	State string `json:"state"` // "", downloading, verifying, done, error
	Got   int64  `json:"got"`
	Total int64  `json:"total"`
	Err   string `json:"err,omitempty"`
	Speed int64  `json:"speed"`
	stop  context.CancelFunc
}

type vmJob struct {
	ID     string `json:"id"`
	VM     string `json:"vm"`
	Title  string `json:"title"`
	State  string `json:"state"` // running, done, error
	Detail string `json:"detail"`
	Pct    int    `json:"pct"`
	When   int64  `json:"when"`
}

type vmEngine struct {
	mu   sync.Mutex
	runs map[string]*vmRun
	dls  map[string]*vmDL
	jobs []*vmJob
}

var vmEng = &vmEngine{runs: map[string]*vmRun{}, dls: map[string]*vmDL{}}

func vmMachinesDir() string { return filepath.Join(vmRoot(), "machines") }
func vmImagesDir() string   { return filepath.Join(vmRoot(), "images") }

func vmList() []*vmMachine {
	var out []*vmMachine
	ents, _ := os.ReadDir(vmMachinesDir())
	for _, e := range ents {
		b, err := os.ReadFile(filepath.Join(vmMachinesDir(), e.Name(), "machine.json"))
		if err != nil {
			continue
		}
		var m vmMachine
		if json.Unmarshal(b, &m) == nil && m.ID == e.Name() {
			out = append(out, &m)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Created < out[j].Created })
	return out
}

func vmGet(id string) *vmMachine {
	if !vmIDok.MatchString(id) {
		return nil
	}
	for _, m := range vmList() {
		if m.ID == id {
			return m
		}
	}
	return nil
}

var vmIDok = regexp.MustCompile(`^[a-z0-9]{6,20}$`)

func vmSave(m *vmMachine) error {
	d := filepath.Join(vmMachinesDir(), m.ID)
	if err := os.MkdirAll(d, 0700); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(m, "", "  ")
	return os.WriteFile(filepath.Join(d, "machine.json"), b, 0600)
}

func vmImagePath(id string) string { return filepath.Join(vmImagesDir(), id+".iso") }
func vmTplPath(id string) string   { return filepath.Join(vmImagesDir(), id+".ckt") }
func vmHaveImage(id string) bool {
	st, err := os.Stat(vmImagePath(id))
	_, err2 := os.Stat(vmTplPath(id))
	return err == nil && err2 == nil && st.Size() > 0
}

// vmDefaults picks RAM and CPU counts that leave the host usable.
func vmDefaults(img *vmImage) (ram, cpus int) {
	total := hostRAMMB()
	ram = 2048
	if total > 0 && total < 7000 {
		ram = 1536
	}
	if img != nil && ram < img.MinRAM {
		ram = img.MinRAM
	}
	cpus = runtime.NumCPU() / 2
	if cpus < 1 {
		cpus = 1
	}
	if cpus > 4 {
		cpus = 4
	}
	return
}

// hostRAMMB reads total memory (Linux/Android /proc/meminfo; Windows via its own file).
func hostRAMMB() int {
	if runtime.GOOS == "windows" {
		return vmHostRAMWindows()
	}
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	for _, l := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(l, "MemTotal:") {
			f := strings.Fields(l)
			if len(f) >= 2 {
				kb, _ := strconv.Atoi(f[1])
				return kb / 1024
			}
		}
	}
	return 0
}

// ------------------------------------------------------------------ data disk template

// The template is gzip("CKT1", u64 size, {u64 offset, u32 length, bytes}..., u32 0):
// only the blocks of an empty ext4 file system that aren't zero. Written back as a
// sparse file it takes a few MB on disk until apps fill it.
func vmWriteDisk(tpl, dst string) error {
	f, err := os.Open(tpl)
	if err != nil {
		return err
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	r := bufio.NewReader(zr)
	var magic [4]byte
	if _, err := io.ReadFull(r, magic[:]); err != nil || string(magic[:]) != "CKT1" {
		return errors.New("bad disk template")
	}
	var size uint64
	if err := binary.Read(r, binary.LittleEndian, &size); err != nil || size == 0 || size > 1<<40 {
		return errors.New("bad disk template")
	}
	tmp := dst + ".part"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	vmMakeSparse(out)
	if err := out.Truncate(int64(size)); err != nil {
		out.Close()
		return err
	}
	buf := make([]byte, 1<<20)
	for {
		var off uint64
		var n uint32
		if err := binary.Read(r, binary.LittleEndian, &off); err != nil {
			out.Close()
			return errors.New("bad disk template")
		}
		if err := binary.Read(r, binary.LittleEndian, &n); err != nil {
			out.Close()
			return errors.New("bad disk template")
		}
		if n == 0 {
			break
		}
		if off+uint64(n) > size {
			out.Close()
			return errors.New("bad disk template")
		}
		for n > 0 {
			k := int(n)
			if k > len(buf) {
				k = len(buf)
			}
			if _, err := io.ReadFull(r, buf[:k]); err != nil {
				out.Close()
				return err
			}
			if _, err := out.WriteAt(buf[:k], int64(off)); err != nil {
				out.Close()
				return err
			}
			off += uint64(k)
			n -= uint32(k)
		}
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}

// ------------------------------------------------------------------ downloads

func (e *vmEngine) download(imgID string) error {
	img := vmImageByID(imgID)
	if img == nil {
		return errors.New("unknown image")
	}
	if img.SHA256 == "" {
		return errors.New("this image is not published yet")
	}
	e.mu.Lock()
	if d := e.dls[imgID]; d != nil && (d.State == "downloading" || d.State == "verifying") {
		e.mu.Unlock()
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	d := &vmDL{State: "downloading", Total: img.Size, stop: cancel}
	e.dls[imgID] = d
	e.mu.Unlock()
	go func() {
		err := vmFetch(ctx, img.TplURL, img.TplSHA, vmTplPath(imgID), nil)
		if err == nil {
			err = vmFetch(ctx, img.URL, img.SHA256, vmImagePath(imgID), func(got, total int64, verifying bool, speed int64) {
				e.mu.Lock()
				d.Got, d.Speed = got, speed
				if total > 0 {
					d.Total = total
				}
				if verifying {
					d.State = "verifying"
				}
				e.mu.Unlock()
			})
		}
		e.mu.Lock()
		if err != nil {
			if ctx.Err() != nil {
				d.State, d.Err = "", ""
			} else {
				d.State, d.Err = "error", err.Error()
			}
		} else {
			d.State = "done"
			d.Got = d.Total
		}
		e.mu.Unlock()
		if err == nil {
			logLine("+", "Virtual Environment: "+img.Name+" downloaded")
		}
	}()
	return nil
}

// getEmulator downloads QEMU where it isn't shipped with CoreKit (Windows).
func (e *vmEngine) getEmulator() error {
	e.mu.Lock()
	if d := e.dls["emulator"]; d != nil && (d.State == "downloading" || d.State == "verifying") {
		e.mu.Unlock()
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	d := &vmDL{State: "downloading", stop: cancel}
	e.dls["emulator"] = d
	e.mu.Unlock()
	go func() {
		err := vmGetEmulator(ctx, func(got, total int64, verifying bool, speed int64) {
			e.mu.Lock()
			d.Got, d.Total, d.Speed = got, total, speed
			if verifying {
				d.State = "verifying"
			}
			e.mu.Unlock()
		})
		e.mu.Lock()
		if err != nil {
			d.State, d.Err = "error", err.Error()
		} else {
			d.State = "done"
		}
		e.mu.Unlock()
	}()
	return nil
}

// vmFetch downloads url to dst (resuming a .part file) and checks its SHA-256.
func vmFetch(ctx context.Context, url, sum, dst string, prog func(got, total int64, verifying bool, speed int64)) error {
	if sum == "" {
		return errors.New("no checksum")
	}
	if st, err := os.Stat(dst); err == nil && st.Size() > 0 {
		return nil // verified when it was saved
	}
	os.MkdirAll(filepath.Dir(dst), 0700)
	part := dst + ".part"
	var have int64
	if st, err := os.Stat(part); err == nil {
		have = st.Size()
	}
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	req.Header.Set("User-Agent", "CoreKit/"+appVersion)
	if have > 0 {
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-", have))
	}
	cl := &http.Client{Timeout: 0}
	resp, err := cl.Do(req)
	if err != nil {
		return fmt.Errorf("no connection (%v)", shortErr(err))
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		have = 0
	case http.StatusPartialContent:
	case http.StatusRequestedRangeNotSatisfiable:
		have = 0
		os.Remove(part)
		return errors.New("download restarted, please try again")
	default:
		return fmt.Errorf("server said %s", resp.Status)
	}
	total := have + resp.ContentLength
	flags := os.O_CREATE | os.O_WRONLY
	if have == 0 {
		flags |= os.O_TRUNC
	} else {
		flags |= os.O_APPEND
	}
	f, err := os.OpenFile(part, flags, 0600)
	if err != nil {
		return err
	}
	buf := make([]byte, 256<<10)
	got, last, lastGot := have, time.Now(), have
	var speed int64
	for {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			if _, werr := f.Write(buf[:n]); werr != nil {
				f.Close()
				return fmt.Errorf("could not save (%v) – is storage full?", shortErr(werr))
			}
			got += int64(n)
			if dt := time.Since(last); dt > 700*time.Millisecond {
				speed = int64(float64(got-lastGot) / dt.Seconds())
				last, lastGot = time.Now(), got
				if prog != nil {
					prog(got, total, false, speed)
				}
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			f.Close()
			return fmt.Errorf("download interrupted (%v)", shortErr(rerr))
		}
	}
	if err := f.Close(); err != nil {
		return err
	}
	if prog != nil {
		prog(got, total, true, 0)
	}
	h := sha256.New()
	rf, err := os.Open(part)
	if err != nil {
		return err
	}
	_, err = io.Copy(h, rf)
	rf.Close()
	if err != nil {
		return err
	}
	if hex.EncodeToString(h.Sum(nil)) != strings.ToLower(sum) {
		os.Remove(part)
		return errors.New("the download was damaged, please try again")
	}
	return os.Rename(part, dst)
}

// ------------------------------------------------------------------ console ring buffer

type vmRing struct {
	mu   sync.Mutex
	buf  []byte
	base int64 // stream offset of buf[0]
	max  int
}

func newRing(max int) *vmRing { return &vmRing{max: max} }

func (r *vmRing) write(p []byte) {
	r.mu.Lock()
	r.buf = append(r.buf, p...)
	if over := len(r.buf) - r.max; over > 0 {
		r.buf = append([]byte(nil), r.buf[over:]...)
		r.base += int64(over)
	}
	r.mu.Unlock()
}

// since returns everything after stream offset n (or the oldest kept part) and the new end.
func (r *vmRing) since(n int64) ([]byte, int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	end := r.base + int64(len(r.buf))
	if n < r.base {
		n = r.base
	}
	if n > end {
		n = end
	}
	return append([]byte(nil), r.buf[n-r.base:]...), end
}

func (r *vmRing) tail(k int) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if k > len(r.buf) {
		k = len(r.buf)
	}
	return string(r.buf[len(r.buf)-k:])
}

// ------------------------------------------------------------------ automation shell (ttyS1)

// vmAuto runs commands in a hidden root shell on the second serial port: one at a time,
// each followed by a marker line so we know where its output ends.
type vmAuto struct {
	mu   sync.Mutex
	c    net.Conn
	r    *bufio.Reader
	seq  int
	dead bool
}

func (a *vmAuto) run(cmd string, timeout time.Duration) (string, int, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.dead {
		return "", -1, errors.New("the virtual Android is not ready")
	}
	a.seq++
	mark := fmt.Sprintf("__CKA%d_%d_", a.seq, time.Now().UnixNano()%1e9)
	a.c.SetWriteDeadline(time.Now().Add(5 * time.Second))
	// the quotes split the marker, so only the shell's output (never an echoed command) matches
	if _, err := a.c.Write([]byte(cmd + " ; echo \"" + mark + "\"\"END=$?\"\n")); err != nil {
		a.dead = true
		return "", -1, err
	}
	a.c.SetReadDeadline(time.Now().Add(timeout))
	defer a.c.SetReadDeadline(time.Time{})
	var out bytes.Buffer
	for {
		line, err := a.r.ReadString('\n')
		if i := strings.Index(line, mark+"END="); i >= 0 {
			out.WriteString(line[:i])
			rc, _ := strconv.Atoi(strings.TrimSpace(line[i+len(mark)+4:]))
			return strings.TrimRight(strings.ReplaceAll(out.String(), "\r", ""), "\n"), rc, nil
		}
		out.WriteString(line)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				// drain what is left of this command later; mark the shell busy-safe
				a.r = bufio.NewReader(a.c)
				return out.String(), -1, errors.New("timed out")
			}
			a.dead = true
			return out.String(), -1, err
		}
		if out.Len() > 8<<20 {
			return out.String(), -1, errors.New("too much output")
		}
	}
}

// ------------------------------------------------------------------ start / stop

func vmFreePort() int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0
	}
	p := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return p
}

func vmDial(port int, wait time.Duration) (net.Conn, error) {
	end := time.Now().Add(wait)
	for {
		c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
		if err == nil {
			return c, nil
		}
		if time.Now().After(end) {
			return nil, err
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// vmBootFiles pulls kernel and initrd out of the image (once) next to it.
func vmBootFiles(imgID string) (kernel, initrd string, err error) {
	dir := filepath.Join(vmImagesDir(), imgID+".boot")
	kernel, initrd = filepath.Join(dir, "kernel"), filepath.Join(dir, "initrd.img")
	if _, e1 := os.Stat(kernel); e1 == nil {
		if _, e2 := os.Stat(initrd); e2 == nil {
			return
		}
	}
	os.MkdirAll(dir, 0700)
	f, err := os.Open(vmImagePath(imgID))
	if err != nil {
		return "", "", err
	}
	defer f.Close()
	for _, name := range []string{"kernel", "initrd.img"} {
		data, err := isoReadFile(f, name)
		if err != nil {
			return "", "", fmt.Errorf("image is damaged (%s: %v)", name, err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			return "", "", err
		}
	}
	return
}

func (e *vmEngine) start(id string) error {
	m := vmGet(id)
	if m == nil {
		return errors.New("no such virtual device")
	}
	e.mu.Lock()
	if r := e.runs[id]; r != nil {
		e.mu.Unlock()
		return nil
	}
	e.mu.Unlock()
	if !vmHaveImage(m.Image) {
		return errors.New("download the system image first")
	}
	q, err := vmFindQemu()
	if err != nil {
		return err
	}
	kernel, initrd, err := vmBootFiles(m.Image)
	if err != nil {
		return err
	}
	disk := filepath.Join(vmMachinesDir(), id, "data.img")
	if _, err := os.Stat(disk); err != nil {
		if err := vmWriteDisk(vmTplPath(m.Image), disk); err != nil {
			return fmt.Errorf("could not create the storage: %v", err)
		}
	}
	p0, p1, p2 := vmFreePort(), vmFreePort(), vmFreePort()
	if p0 == 0 || p1 == 0 || p2 == 0 || p0 == p1 || p1 == p2 || p0 == p2 {
		return errors.New("no free local port")
	}
	snap, _ := vmSnapFor(m)
	cpu := "max"
	accel := q.accel
	args := append([]string{}, q.pre...)
	args = append(args,
		"-name", "CoreKit-"+m.Name,
		"-accel", strings.SplitN(accel, ";", 2)[0],
	)
	if strings.Contains(accel, ";") { // fallback accelerator(s)
		for _, a := range strings.Split(accel, ";")[1:] {
			args = append(args, "-accel", a)
		}
	}
	if strings.HasPrefix(accel, "kvm") || strings.HasPrefix(accel, "whpx") {
		cpu = "max"
	}
	args = append(args,
		"-cpu", cpu,
		"-m", strconv.Itoa(m.RAM), "-smp", strconv.Itoa(m.CPUs),
		"-kernel", kernel, "-initrd", initrd,
		"-append", "root=/dev/ram0 androidboot.selinux=permissive console=ttyS0 androidboot.console=ttyS0 SRC= DATA=vda nomodeset quiet",
		"-drive", "file="+vmImagePath(m.Image)+",media=cdrom,readonly=on",
		"-drive", "file="+disk+",format=raw,if=virtio,cache=writeback,discard=unmap,detect-zeroes=unmap",
		"-display", "none", "-vga", "std",
		"-netdev", "user,id=n0", "-device", "virtio-net-pci,netdev=n0",
		"-serial", fmt.Sprintf("tcp:127.0.0.1:%d,server=on,wait=off", p0),
		"-serial", fmt.Sprintf("tcp:127.0.0.1:%d,server=on,wait=off", p1),
		"-qmp", fmt.Sprintf("tcp:127.0.0.1:%d,server=on,wait=off", p2),
		"-monitor", "none", "-no-reboot",
	)
	if snap != "" {
		args = append(args, "-incoming", vmFileURI(snap))
	}
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, q.exe, args...)
	cmd.Env = append(os.Environ(), q.env...)
	logf, _ := os.OpenFile(filepath.Join(vmMachinesDir(), id, "qemu.log"), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	cmd.Stdout, cmd.Stderr = logf, logf
	vmHideWindow(cmd)
	if err := cmd.Start(); err != nil {
		cancel()
		if logf != nil {
			logf.Close()
		}
		return fmt.Errorf("the emulator could not start (%v)", shortErr(err))
	}
	r := &vmRun{m: m, cmd: cmd, cancel: cancel, state: "starting", detail: "Starting the emulator", started: time.Now(),
		term: newRing(512 << 10), exited: make(chan struct{}), accel: strings.SplitN(accel, ",", 2)[0], qmpPort: p2, resumed: snap != ""}
	if r.resumed {
		r.detail = "Loading the saved state"
	}
	e.mu.Lock()
	e.runs[id] = r
	e.mu.Unlock()
	m.LastRun = time.Now().Unix()
	vmSave(m)
	logLine("*", "Virtual Environment: starting "+m.Name)
	go func() {
		err := cmd.Wait()
		if logf != nil {
			logf.Close()
		}
		e.mu.Lock()
		if e.runs[id] == r {
			delete(e.runs, id)
		}
		e.mu.Unlock()
		if r.con != nil {
			r.con.Close()
		}
		if r.auto != nil {
			r.auto.c.Close()
		}
		close(r.exited)
		msg := "stopped"
		if _, err2 := os.Stat(vmSnapPath(id)); err2 == nil && !r.resumed {
			msg = "saved"
		}
		if r.resumed && r.state != "running" && r.state != "stopping" {
			vmDropSnap(id) // a save that doesn't load is useless; next start boots normally
			msg = "could not load its saved state; start it again for a normal start"
		} else if err != nil && r.state != "stopping" {
			msg = "stopped unexpectedly"
			tail, _ := os.ReadFile(filepath.Join(vmMachinesDir(), id, "qemu.log"))
			if len(tail) > 0 {
				msg += ": " + strings.TrimSpace(lastLine(string(tail)))
			}
		}
		r.term.write([]byte("\r\n\x1b[90m[CoreKit] Virtual device " + msg + ".\x1b[0m\r\n"))
		vmLastExit.Store(id, msg)
		logLine("*", "Virtual Environment: "+m.Name+" "+msg)
	}()
	go e.boot(r, p0, p1)
	return nil
}

var vmLastExit sync.Map

func lastLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.LastIndex(s, "\n"); i >= 0 {
		s = s[i+1:]
	}
	if len(s) > 160 {
		s = s[:160]
	}
	return s
}

func (r *vmRun) set(state, detail string) {
	vmEng.mu.Lock()
	r.state, r.detail = state, detail
	vmEng.mu.Unlock()
}

var vmPrompt = regexp.MustCompile(`console:/ [#$] ?$`)

// boot connects the console, waits for the shell, starts the hidden automation shell
// on ttyS1, waits for Android to finish starting, then sets up the network.
func (e *vmEngine) boot(r *vmRun, p0, p1 int) {
	c, err := vmDial(p0, 20*time.Second)
	if err != nil {
		r.set("starting", "The emulator did not open its console")
		return
	}
	r.con = c
	if r.resumed {
		r.set("booting", "Loading the saved state")
	} else {
		r.set("booting", "Starting Linux")
	}
	sawPrompt := make(chan struct{})
	go func() {
		buf := make([]byte, 8192)
		var once sync.Once
		for {
			n, err := c.Read(buf)
			if n > 0 {
				r.term.write(buf[:n])
				if vmPrompt.MatchString(strings.TrimRight(r.term.tail(64), "\r\n")) {
					once.Do(func() { close(sawPrompt) })
				}
			}
			if err != nil {
				return
			}
		}
	}()
	if r.resumed {
		if !e.afterResume(r) {
			return
		}
		r.resumed = false
		ac, err := vmDial(p1, 10*time.Second)
		if err != nil {
			r.set("booting", "CoreKit could not attach to the device")
			return
		}
		a := &vmAuto{c: ac, r: bufio.NewReader(ac)}
		a.run("true", 5*time.Second)
		r.auto = a
		c.Write([]byte("\n"))
		// the clock stood still while it was saved
		a.run(fmt.Sprintf("toybox date -u %s >/dev/null 2>&1", time.Now().UTC().Format("010215042006.05")), 5*time.Second)
		r.ip = vmNetUp(a)
		r.bootSec = int(time.Since(r.started).Seconds())
		r.set("running", "")
		logLine("+", fmt.Sprintf("Virtual Environment: %s resumed (%ds)", r.m.Name, r.bootSec))
		return
	}
	// nudge the console until the shell prompt shows
	tick := time.NewTicker(3 * time.Second)
	defer tick.Stop()
wait:
	for {
		select {
		case <-sawPrompt:
			break wait
		case <-r.exited:
			return
		case <-tick.C:
			c.Write([]byte("\n"))
		}
	}
	r.set("booting", "Starting Android")
	// hidden root shell for CoreKit on the second serial port
	// (fed through a pipe, so it is not an interactive shell: no prompts in the output)
	c.Write([]byte("setsid sh -c 'stty -F /dev/ttyS1 -echo; cat /dev/ttyS1 | sh >/dev/ttyS1 2>&1' & clear\n"))
	ac, err := vmDial(p1, 10*time.Second)
	if err != nil {
		r.set("booting", "CoreKit could not attach to the device")
		return
	}
	a := &vmAuto{c: ac, r: bufio.NewReader(ac)}
	time.Sleep(700 * time.Millisecond)
	a.run("true", 5*time.Second) // flush
	r.auto = a
	for {
		select {
		case <-r.exited:
			return
		default:
		}
		out, _, err := a.run("getprop sys.boot_completed", 10*time.Second)
		if err == nil && strings.TrimSpace(out) == "1" {
			break
		}
		if a.dead {
			return
		}
		el := int(time.Since(r.started).Seconds())
		r.set("booting", fmt.Sprintf("Starting Android (%d:%02d)", el/60, el%60))
		time.Sleep(3 * time.Second)
	}
	r.bootSec = int(time.Since(r.started).Seconds())
	// no setup wizard in the slim image: mark the device as set up
	a.run("settings put global device_provisioned 1; settings put secure user_setup_complete 1", 60*time.Second)
	r.set("booting", "Connecting the network")
	r.ip = vmNetUp(a)
	r.set("running", "")
	logLine("+", fmt.Sprintf("Virtual Environment: %s is ready (%ds)", r.m.Name, r.bootSec))
}

var vmInet = regexp.MustCompile(`inet (\d+\.\d+\.\d+\.\d+)`)

// vmGuestIP returns the guest's IPv4 address (Android shows the virtual network as Wi-Fi).
func vmGuestIP(a *vmAuto) string {
	out, _, _ := a.run("ip -4 -o addr show | grep -v ' lo '", 8*time.Second)
	if m := vmInet.FindStringSubmatch(out); m != nil {
		return m[1]
	}
	return ""
}

// vmNetUp waits for Android to bring up its network (QEMU's built-in NAT: guest
// 10.0.2.15, host 10.0.2.2, DNS 10.0.2.3) and sets it up by hand if it doesn't.
func vmNetUp(a *vmAuto) string {
	for i := 0; i < 20; i++ {
		if ip := vmGuestIP(a); ip != "" {
			return ip
		}
		time.Sleep(3 * time.Second)
	}
	a.run("ip addr add 10.0.2.15/24 dev eth0 2>/dev/null; ip link set eth0 up; ip route add default via 10.0.2.2 dev eth0 2>/dev/null;"+
		" ndc network create 100 >/dev/null 2>&1; ndc network interface add 100 eth0 >/dev/null 2>&1;"+
		" ndc network route add 100 eth0 0.0.0.0/0 10.0.2.2 >/dev/null 2>&1; ndc resolver setnetdns 100 '' 10.0.2.3 >/dev/null 2>&1;"+
		" ndc network default set 100 >/dev/null 2>&1; setprop net.dns1 10.0.2.3", 15*time.Second)
	return vmGuestIP(a)
}

func (e *vmEngine) stop(id string, force bool) error {
	e.mu.Lock()
	r := e.runs[id]
	if r == nil {
		e.mu.Unlock()
		return nil
	}
	r.state, r.detail = "stopping", "Shutting down"
	e.mu.Unlock()
	vmDropSnap(id)
	go func() {
		if !force && r.auto != nil && !r.auto.dead {
			r.auto.run("sync; reboot -p", 3*time.Second)
			select {
			case <-r.exited:
				return
			case <-time.After(20 * time.Second):
			}
		}
		r.cancel()
	}()
	return nil
}

func (e *vmEngine) shutdownAll() {
	e.mu.Lock()
	var rs []*vmRun
	for _, r := range e.runs {
		rs = append(rs, r)
	}
	e.mu.Unlock()
	for _, r := range rs {
		e.stop(r.m.ID, false)
	}
	for _, r := range rs {
		select {
		case <-r.exited:
		case <-time.After(25 * time.Second):
			r.cancel()
		}
	}
}

func (e *vmEngine) running(id string) *vmRun {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.runs[id]
}

// ------------------------------------------------------------------ apps

// vmServeFile lets the guest fetch one file from us through QEMU's NAT (10.0.2.2:port).
func vmServeFile(path string) (port int, done chan error, err error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, nil, err
	}
	done = make(chan error, 1)
	go func() {
		defer l.Close()
		l.(*net.TCPListener).SetDeadline(time.Now().Add(3 * time.Minute))
		c, err := l.Accept()
		if err != nil {
			done <- err
			return
		}
		defer c.Close()
		f, err := os.Open(path)
		if err != nil {
			done <- err
			return
		}
		defer f.Close()
		_, err = io.Copy(c, f)
		if tc, ok := c.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
		done <- err
	}()
	return l.Addr().(*net.TCPAddr).Port, done, nil
}

func (e *vmEngine) addJob(vm, title string) *vmJob {
	j := &vmJob{ID: randID(), VM: vm, Title: title, State: "running", When: time.Now().Unix()}
	e.mu.Lock()
	e.jobs = append(e.jobs, j)
	if len(e.jobs) > 30 {
		e.jobs = e.jobs[len(e.jobs)-30:]
	}
	e.mu.Unlock()
	return j
}

func (e *vmEngine) jobSet(j *vmJob, state, detail string, pct int) {
	e.mu.Lock()
	j.State, j.Detail, j.Pct = state, detail, pct
	e.mu.Unlock()
}

// install copies one app (all of its APK files) into the running virtual Android.
func (e *vmEngine) install(id, label string, files []string) (*vmJob, error) {
	r := e.running(id)
	if r == nil || r.state != "running" || r.auto == nil {
		return nil, errors.New("start the virtual device first")
	}
	if len(files) == 0 || len(files) > 40 {
		return nil, errors.New("no app files")
	}
	var total int64
	for _, f := range files {
		st, err := os.Stat(f)
		if err != nil || st.IsDir() || !strings.HasSuffix(strings.ToLower(f), ".apk") {
			return nil, errors.New("this app's files could not be read")
		}
		total += st.Size()
	}
	if label == "" {
		label = filepath.Base(files[0])
	}
	j := e.addJob(id, "Installing "+label)
	go func() {
		a := r.auto
		a.run("rm -rf /data/local/tmp/ck && mkdir -p /data/local/tmp/ck", 10*time.Second)
		var sent int64
		var names []string
		for i, f := range files {
			port, done, err := vmServeFile(f)
			if err != nil {
				e.jobSet(j, "error", "Could not share the file", 0)
				return
			}
			name := fmt.Sprintf("/data/local/tmp/ck/%d.apk", i)
			e.jobSet(j, "running", fmt.Sprintf("Copying (%d of %d)", i+1, len(files)), int(sent*80/maxI64(total, 1)))
			_, rc, err := a.run(fmt.Sprintf("toybox nc 10.0.2.2 %d </dev/null > %s", port, name), 10*time.Minute)
			if derr := <-done; err != nil || rc != 0 || derr != nil {
				e.jobSet(j, "error", "Copying into the virtual device failed. Is its network up?", 0)
				return
			}
			st, _ := os.Stat(f)
			sent += st.Size()
			names = append(names, name)
		}
		e.jobSet(j, "running", "Installing", 85)
		var out string
		var rc int
		if len(names) == 1 {
			out, rc, _ = a.run("pm install -r -g "+names[0]+" 2>&1", 6*time.Minute)
		} else {
			cmd := fmt.Sprintf("S=$(pm install-create -r -g -S %d | toybox sed -n 's/.*\\[\\([0-9]*\\)\\].*/\\1/p'); ", total)
			for i, n := range names {
				st, _ := os.Stat(files[i])
				cmd += fmt.Sprintf("pm install-write -S %d $S part%d %s >/dev/null || echo FAILWRITE; ", st.Size(), i, n)
			}
			cmd += "pm install-commit $S 2>&1"
			out, rc, _ = a.run(cmd, 8*time.Minute)
		}
		a.run("rm -rf /data/local/tmp/ck", 10*time.Second)
		if rc == 0 && strings.Contains(out, "Success") {
			e.jobSet(j, "done", "Installed", 100)
			logLine("+", "Virtual Environment: installed "+label)
			return
		}
		e.jobSet(j, "error", vmInstallError(out), 0)
	}()
	return j, nil
}

func maxI64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func vmInstallError(out string) string {
	switch {
	case strings.Contains(out, "NO_MATCHING_ABIS"):
		return "This app has no Intel/ARM-compatible code for this device. Turn on ARM app support and try again."
	case strings.Contains(out, "OLDER_SDK"), strings.Contains(out, "INSTALL_FAILED_OLDER_SDK"):
		return "This app needs a newer Android than the virtual device has."
	case strings.Contains(out, "INSUFFICIENT_STORAGE"):
		return "The virtual device is out of storage."
	case strings.Contains(out, "UPDATE_INCOMPATIBLE"):
		return "A different version of this app is already installed. Remove it first."
	}
	m := regexp.MustCompile(`INSTALL_[A-Z_]+`).FindString(out)
	if m != "" {
		return "Install failed: " + m
	}
	return "Install failed."
}

// apps lists the apps the user installed in the virtual device.
func (e *vmEngine) apps(id string) ([]map[string]string, error) {
	r := e.running(id)
	if r == nil || r.auto == nil || r.state != "running" {
		return nil, errors.New("not running")
	}
	out, _, err := r.auto.run("pm list packages -3", 30*time.Second)
	if err != nil {
		return nil, err
	}
	list := []map[string]string{}
	for _, l := range strings.Split(out, "\n") {
		l = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(l), "package:"))
		if l != "" && vmPkgOk.MatchString(l) {
			list = append(list, map[string]string{"pkg": l})
		}
	}
	sort.Slice(list, func(i, j int) bool { return list[i]["pkg"] < list[j]["pkg"] })
	return list, nil
}

var vmPkgOk = regexp.MustCompile(`^[A-Za-z0-9_.]{2,200}$`)

// ------------------------------------------------------------------ HTTP API

func vmMachineJSON(m *vmMachine) map[string]any {
	j := map[string]any{"id": m.ID, "name": m.Name, "image": m.Image, "ram": m.RAM, "cpus": m.CPUs, "created": m.Created, "lastRun": m.LastRun, "state": "off"}
	if img := vmImageByID(m.Image); img != nil {
		j["android"] = img.Android
		j["imageName"] = img.Name
	}
	dp := filepath.Join(vmMachinesDir(), m.ID, "data.img")
	if st, err := os.Stat(dp); err == nil {
		if u := vmDiskUsedPath(dp); u >= 0 {
			j["used"] = u
		} else {
			j["used"] = diskUsed(st)
		}
	}
	if _, meta := vmSnapFor(m); meta != nil && vmEng.running(m.ID) == nil {
		j["saved"] = meta.Saved
		j["savedSize"] = meta.Size
	}
	if v, ok := vmLastExit.Load(m.ID); ok {
		j["lastExit"] = v
	}
	if r := vmEng.running(m.ID); r != nil {
		vmEng.mu.Lock()
		j["state"], j["detail"], j["accel"], j["ip"], j["bootSec"] = r.state, r.detail, r.accel, r.ip, r.bootSec
		j["uptime"] = int(time.Since(r.started).Seconds())
		vmEng.mu.Unlock()
	}
	return j
}

func vmState() map[string]any {
	imgs := []map[string]any{}
	for _, im := range vmCatalogue {
		x := map[string]any{"id": im.ID, "name": im.Name, "android": im.Android, "note": im.Note, "size": im.Size,
			"have": vmHaveImage(im.ID), "published": im.SHA256 != ""}
		vmEng.mu.Lock()
		if d := vmEng.dls[im.ID]; d != nil {
			x["dl"] = map[string]any{"state": d.State, "got": d.Got, "total": d.Total, "err": d.Err, "speed": d.Speed}
		}
		vmEng.mu.Unlock()
		imgs = append(imgs, x)
	}
	ms := []map[string]any{}
	for _, m := range vmList() {
		ms = append(ms, vmMachineJSON(m))
	}
	_, qerr := vmFindQemu()
	host := map[string]any{"ram": hostRAMMB(), "cpus": runtime.NumCPU(), "os": runtime.GOOS, "emulator": qerr == nil, "free": vmFreeSpace()}
	if qerr != nil {
		host["emulatorErr"] = qerr.Error()
	}
	vmPlatformHost(host)
	vmEng.mu.Lock()
	if d := vmEng.dls["emulator"]; d != nil {
		host["emulatorDl"] = map[string]any{"state": d.State, "got": d.Got, "total": d.Total, "err": d.Err, "speed": d.Speed}
	}
	jobs := append([]*vmJob{}, vmEng.jobs...)
	vmEng.mu.Unlock()
	r, c := vmDefaults(nil)
	return map[string]any{"images": imgs, "machines": ms, "host": host, "jobs": jobs, "defaults": map[string]int{"ram": r, "cpus": c}}
}

func mountVM(mux *http.ServeMux, prefix string, auth func(*http.Request) bool) {
	ok := func(w http.ResponseWriter, r *http.Request) bool {
		if auth != nil && !auth(r) {
			http.Error(w, "forbidden", 403)
			return false
		}
		return true
	}
	fail := func(w http.ResponseWriter, err error) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(400)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
	}
	body := func(r *http.Request) map[string]any {
		var m map[string]any
		json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1<<20)).Decode(&m)
		if m == nil {
			m = map[string]any{}
		}
		return m
	}
	str := func(m map[string]any, k string) string { s, _ := m[k].(string); return s }
	num := func(m map[string]any, k string) int { f, _ := m[k].(float64); return int(f) }

	mux.HandleFunc(prefix+"state", func(w http.ResponseWriter, r *http.Request) {
		if ok(w, r) {
			writeJSON(w, vmState())
		}
	})
	mux.HandleFunc(prefix+"term", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		run := vmEng.running(r.URL.Query().Get("id"))
		since, _ := strconv.ParseInt(r.URL.Query().Get("since"), 10, 64)
		if run == nil {
			writeJSON(w, map[string]any{"t": "", "n": since, "off": true})
			return
		}
		data, n := run.term.since(since)
		writeJSON(w, map[string]any{"t": string(bytes.ToValidUTF8(data, []byte("?"))), "n": n})
	})
	mux.HandleFunc(prefix+"cmd", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) || r.Method != http.MethodPost {
			return
		}
		m := body(r)
		id := str(m, "id")
		var err error
		res := map[string]any{"ok": true}
		switch str(m, "t") {
		case "download":
			err = vmEng.download(str(m, "image"))
		case "stopAll":
			go vmEng.shutdownAll()
		case "getEmulator":
			err = vmEng.getEmulator()
		case "enableFast":
			err = vmEnableWHPX()
			res["restart"] = true
		case "cancelDownload":
			vmEng.mu.Lock()
			if d := vmEng.dls[str(m, "image")]; d != nil && d.stop != nil {
				d.stop()
			}
			vmEng.mu.Unlock()
		case "deleteImage":
			img := str(m, "image")
			if vmImageByID(img) == nil {
				err = errors.New("unknown image")
				break
			}
			for _, x := range vmList() {
				if x.Image == img && vmEng.running(x.ID) != nil {
					err = errors.New("stop the virtual devices that use it first")
				}
			}
			if err == nil {
				os.Remove(vmImagePath(img))
				os.Remove(vmImagePath(img) + ".part")
				os.Remove(vmTplPath(img))
				os.RemoveAll(filepath.Join(vmImagesDir(), img+".boot"))
				vmEng.mu.Lock()
				delete(vmEng.dls, img)
				vmEng.mu.Unlock()
			}
		case "create":
			img := vmImageByID(str(m, "image"))
			if img == nil {
				err = errors.New("pick a system")
				break
			}
			name := strings.TrimSpace(str(m, "name"))
			if name == "" {
				name = img.Name
			}
			if len([]rune(name)) > 40 {
				name = string([]rune(name)[:40])
			}
			dr, dc := vmDefaults(img)
			ram, cpus := num(m, "ram"), num(m, "cpus")
			if ram < 1024 || ram > 16384 {
				ram = dr
			}
			if cpus < 1 || cpus > 8 {
				cpus = dc
			}
			mm := &vmMachine{ID: strings.ToLower(randID()), Name: name, Image: img.ID, RAM: ram, CPUs: cpus, Created: time.Now().Unix()}
			if err = vmSave(mm); err == nil {
				res["id"] = mm.ID
			}
		case "update":
			mm := vmGet(id)
			if mm == nil {
				err = errors.New("no such virtual device")
				break
			}
			if n := strings.TrimSpace(str(m, "name")); n != "" {
				if len([]rune(n)) > 40 {
					n = string([]rune(n)[:40])
				}
				mm.Name = n
			}
			if v := num(m, "ram"); v >= 1024 && v <= 16384 {
				mm.RAM = v
			}
			if v := num(m, "cpus"); v >= 1 && v <= 8 {
				mm.CPUs = v
			}
			err = vmSave(mm)
		case "start":
			err = vmEng.start(id)
		case "stop":
			err = vmEng.stop(id, false)
		case "suspend":
			err = vmEng.suspend(id)
		case "discardSave":
			if vmEng.running(id) == nil {
				vmDropSnap(id)
			}
		case "kill":
			err = vmEng.stop(id, true)
		case "reset", "delete":
			if vmGet(id) == nil {
				err = errors.New("no such virtual device")
				break
			}
			if vmEng.running(id) != nil {
				err = errors.New("stop it first")
				break
			}
			vmDropSnap(id)
			if str(m, "t") == "reset" {
				err = os.Remove(filepath.Join(vmMachinesDir(), id, "data.img"))
				if os.IsNotExist(err) {
					err = nil
				}
			} else {
				err = os.RemoveAll(filepath.Join(vmMachinesDir(), id))
			}
		case "input":
			if run := vmEng.running(id); run != nil && run.con != nil {
				s := str(m, "s")
				if len(s) > 64<<10 {
					s = s[:64<<10]
				}
				_, err = run.con.Write([]byte(s))
			}
		case "install":
			var files []string
			if arr, okk := m["files"].([]any); okk {
				for _, f := range arr {
					if s, ok2 := f.(string); ok2 {
						files = append(files, s)
					}
				}
			}
			var j *vmJob
			j, err = vmEng.install(id, str(m, "label"), files)
			if j != nil {
				res["job"] = j.ID
			}
		case "apps":
			var list []map[string]string
			list, err = vmEng.apps(id)
			res["apps"] = list
		case "uninstall", "launch", "freeze", "unfreeze":
			pkg := str(m, "pkg")
			run := vmEng.running(id)
			if !vmPkgOk.MatchString(pkg) || run == nil || run.auto == nil {
				err = errors.New("not running")
				break
			}
			c := map[string]string{"uninstall": "pm uninstall " + pkg, "launch": "monkey -p " + pkg + " -c android.intent.category.LAUNCHER 1",
				"freeze": "pm disable-user " + pkg, "unfreeze": "pm enable " + pkg}[str(m, "t")]
			var out string
			out, _, err = run.auto.run(c+" 2>&1", 90*time.Second)
			res["out"] = out
		case "arm":
			run := vmEng.running(id)
			if run == nil || run.auto == nil || run.state != "running" {
				err = errors.New("start the virtual device first")
				break
			}
			j := vmEng.addJob(id, "ARM app support")
			res["job"] = j.ID
			go func() {
				vmEng.jobSet(j, "running", "Downloading and turning on ARM support", 30)
				out, rc, _ := run.auto.run("enable_nativebridge 2>&1; setprop persist.sys.nativebridge 1; getprop ro.dalvik.vm.native.bridge", 10*time.Minute)
				if rc == 0 && !strings.Contains(strings.ToLower(out), "fail") {
					vmEng.jobSet(j, "done", "ARM apps can now run (restart the device if one still fails)", 100)
				} else {
					vmEng.jobSet(j, "error", "Could not turn on ARM support: "+lastLine(out), 0)
				}
			}()
		default:
			err = errors.New("unknown command")
		}
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, res)
	})
	// Windows/desktop: an APK chosen in the page is uploaded here first
	mux.HandleFunc(prefix+"upload", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) || r.Method != http.MethodPost {
			return
		}
		name := filepath.Base(strings.ReplaceAll(r.URL.Query().Get("name"), "\\", "/"))
		if !strings.HasSuffix(strings.ToLower(name), ".apk") {
			fail(w, errors.New("pick an .apk file"))
			return
		}
		dir := filepath.Join(vmRoot(), "uploads")
		os.MkdirAll(dir, 0700)
		dst := filepath.Join(dir, randID()+".apk")
		f, err := os.Create(dst)
		if err != nil {
			fail(w, err)
			return
		}
		_, err = io.Copy(f, http.MaxBytesReader(w, r.Body, 4<<30))
		f.Close()
		if err != nil {
			os.Remove(dst)
			fail(w, errors.New("upload failed"))
			return
		}
		writeJSON(w, map[string]string{"path": dst})
	})
}
