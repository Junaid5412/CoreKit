package main

// Quick resume: instead of shutting Android down, CoreKit can save the whole running
// virtual device (memory + CPU state) to a file through QEMU's monitor (QMP) and start
// from it later in seconds, skipping the long software boot.

import (
	"bufio"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type vmQMP struct {
	c net.Conn
	r *bufio.Reader
}

func vmQMPDial(port int) (*vmQMP, error) {
	c, err := vmDial(port, 10*time.Second)
	if err != nil {
		return nil, err
	}
	q := &vmQMP{c: c, r: bufio.NewReader(c)}
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := q.r.ReadString('\n'); err != nil { // greeting
		c.Close()
		return nil, err
	}
	if _, err := q.do("qmp_capabilities", nil); err != nil {
		c.Close()
		return nil, err
	}
	return q, nil
}

// do runs one QMP command and returns its "return" value (events are skipped).
func (q *vmQMP) do(cmd string, args map[string]any) (json.RawMessage, error) {
	m := map[string]any{"execute": cmd}
	if args != nil {
		m["arguments"] = args
	}
	b, _ := json.Marshal(m)
	q.c.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := q.c.Write(append(b, '\n')); err != nil {
		return nil, err
	}
	q.c.SetReadDeadline(time.Now().Add(30 * time.Second))
	for {
		line, err := q.r.ReadBytes('\n')
		if err != nil {
			return nil, err
		}
		var resp struct {
			Return json.RawMessage `json:"return"`
			Error  *struct {
				Desc string `json:"desc"`
			} `json:"error"`
			Event string `json:"event"`
		}
		if json.Unmarshal(line, &resp) != nil || resp.Event != "" {
			continue
		}
		if resp.Error != nil {
			return nil, errors.New(resp.Error.Desc)
		}
		return resp.Return, nil
	}
}

func (q *vmQMP) close() { q.c.Close() }

type vmSnapMeta struct {
	Image   string `json:"image"`
	RAM     int    `json:"ram"`
	CPUs    int    `json:"cpus"`
	Version string `json:"version"` // emulator build: a different one can't load the save
	Saved   int64  `json:"saved"`
	Size    int64  `json:"size"`
}

func vmSnapPath(id string) string     { return filepath.Join(vmMachinesDir(), id, "state.snap") }
func vmSnapMetaPath(id string) string { return filepath.Join(vmMachinesDir(), id, "state.json") }

func vmDropSnap(id string) {
	os.Remove(vmSnapPath(id))
	os.Remove(vmSnapPath(id) + ".part")
	os.Remove(vmSnapMetaPath(id))
}

// vmSnapFor returns a saved state that still fits the machine, or "".
func vmSnapFor(m *vmMachine) (string, *vmSnapMeta) {
	b, err := os.ReadFile(vmSnapMetaPath(m.ID))
	if err != nil {
		return "", nil
	}
	var meta vmSnapMeta
	if json.Unmarshal(b, &meta) != nil || meta.Image != m.Image || meta.RAM != m.RAM || meta.CPUs != m.CPUs || meta.Version != vmQemuID() {
		vmDropSnap(m.ID)
		return "", nil
	}
	if st, err := os.Stat(vmSnapPath(m.ID)); err != nil || st.Size() == 0 {
		vmDropSnap(m.ID)
		return "", nil
	}
	return vmSnapPath(m.ID), &meta
}

func vmFileURI(p string) string { return "file:" + filepath.ToSlash(p) }

// suspend saves the running device to disk and stops the emulator.
func (e *vmEngine) suspend(id string) error {
	r := e.running(id)
	if r == nil {
		return errors.New("not running")
	}
	if r.state != "running" || r.qmpPort == 0 {
		return errors.New("wait until it has finished starting")
	}
	r.set("stopping", "Saving")
	go func() {
		err := e.doSuspend(r)
		if err != nil {
			vmDropSnap(id)
			logLine("!", "Virtual Environment: could not save "+r.m.Name+": "+err.Error())
			r.term.write([]byte("\r\n\x1b[91m[CoreKit] Saving failed (" + err.Error() + "); shutting down instead.\x1b[0m\r\n"))
			e.stop(id, false)
			return
		}
		logLine("+", "Virtual Environment: "+r.m.Name+" saved for quick resume")
	}()
	return nil
}

func (e *vmEngine) doSuspend(r *vmRun) error {
	q, err := vmQMPDial(r.qmpPort)
	if err != nil {
		return err
	}
	defer q.close()
	if r.auto != nil {
		// drop file caches: the save gets smaller and faster
		r.set("stopping", "Preparing to save")
		r.auto.run("sync; echo 3 > /proc/sys/vm/drop_caches", 3*time.Minute)
	}
	if _, err := q.do("stop", nil); err != nil {
		return err
	}
	part := vmSnapPath(r.m.ID) + ".part"
	os.Remove(part)
	if _, err := q.do("migrate", map[string]any{"uri": vmFileURI(part)}); err != nil {
		q.do("cont", nil)
		return err
	}
	for {
		select {
		case <-r.exited:
			return errors.New("the emulator closed")
		case <-time.After(700 * time.Millisecond):
		}
		raw, err := q.do("query-migrate", nil)
		if err != nil {
			return err
		}
		var st struct {
			Status string `json:"status"`
			RAM    struct {
				Transferred int64 `json:"transferred"`
				Total       int64 `json:"total"`
				Remaining   int64 `json:"remaining"`
			} `json:"ram"`
			Err string `json:"error-desc"`
		}
		json.Unmarshal(raw, &st)
		switch st.Status {
		case "completed":
			fi, err := os.Stat(part)
			if err != nil {
				return err
			}
			if err := os.Rename(part, vmSnapPath(r.m.ID)); err != nil {
				return err
			}
			meta, _ := json.Marshal(vmSnapMeta{Image: r.m.Image, RAM: r.m.RAM, CPUs: r.m.CPUs, Version: vmQemuID(), Saved: time.Now().Unix(), Size: fi.Size()})
			os.WriteFile(vmSnapMetaPath(r.m.ID), meta, 0600)
			r.set("stopping", "Saved")
			q.do("quit", nil)
			select {
			case <-r.exited:
			case <-time.After(10 * time.Second):
				r.cancel()
			}
			return nil
		case "failed", "cancelled":
			q.do("cont", nil)
			if st.Err == "" {
				st.Err = st.Status
			}
			return errors.New(st.Err)
		default:
			if st.RAM.Total > 0 {
				pct := int((st.RAM.Total - st.RAM.Remaining) * 100 / st.RAM.Total)
				r.set("stopping", fmt.Sprintf("Saving (%d%%)", pct))
			}
		}
	}
}

// resumed: after QEMU loaded a saved state, wait until the guest runs, then drop the file
// (Android's storage moves on from here, so the save can't be used twice).
func (e *vmEngine) afterResume(r *vmRun) bool {
	q, err := vmQMPDial(r.qmpPort)
	if err != nil {
		return false
	}
	defer q.close()
	end := time.Now().Add(10 * time.Minute)
	for time.Now().Before(end) {
		raw, err := q.do("query-status", nil)
		if err != nil {
			return false
		}
		var st struct {
			Status string `json:"status"`
		}
		json.Unmarshal(raw, &st)
		if st.Status == "running" {
			vmDropSnap(r.m.ID)
			return true
		}
		if st.Status == "paused" || st.Status == "postmigrate" { // saved while paused: continue it
			q.do("cont", nil)
		}
		if strings.Contains(st.Status, "fail") || st.Status == "internal-error" {
			return false
		}
		r.set("booting", "Loading the saved state")
		select {
		case <-r.exited:
			return false
		case <-time.After(500 * time.Millisecond):
		}
	}
	return false
}

var (
	vmQemuIDOnce sync.Once
	vmQemuIDVal  string
)

// vmQemuID identifies the emulator build (size + hash of its first MB): saved states only
// load in the exact build that made them.
func vmQemuID() string {
	vmQemuIDOnce.Do(func() {
		q, err := vmFindQemu()
		if err != nil {
			return
		}
		f, err := os.Open(q.exe)
		if err != nil {
			return
		}
		defer f.Close()
		st, _ := f.Stat()
		h := sha256.New()
		io.CopyN(h, f, 1<<20)
		vmQemuIDVal = fmt.Sprintf("%d-%x", st.Size(), h.Sum(nil)[:8])
	})
	return vmQemuIDVal
}
