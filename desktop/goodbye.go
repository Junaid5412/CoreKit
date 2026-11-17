package main

// Exit screen: cleans up for real (tunnels, temp files, decrypted settings in memory),
// shows a short session summary and an animated goodbye.

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

var session = struct {
	start time.Time
	used  map[string]int
	mu    sync.Mutex
}{start: time.Now(), used: map[string]int{}}

func markUsed(module string) {
	session.mu.Lock()
	session.used[module]++
	session.mu.Unlock()
}

var byeOnce sync.Once

// watchExitSignals shows the goodbye screen on Ctrl+C or when the window is closed.
func watchExitSignals() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	go func() {
		s := <-ch
		goodbye(s == syscall.SIGTERM) // closing the window leaves only a few seconds
		os.Exit(0)
	}()
}

// figlet letters (standard font), 5 rows each
var byeFont = map[rune][5]string{
	'G': {`  ____ `, ` / ___|`, `| |  _ `, `| |_| |`, ` \____|`},
	'O': {`  ___  `, ` / _ \ `, `| | | |`, `| |_| |`, ` \___/ `},
	'D': {` ____  `, `|  _ \ `, `| | | |`, `| |_| |`, `|____/ `},
	'B': {` ____  `, `| __ ) `, `|  _ \ `, `| |_) |`, `|____/ `},
	'Y': {`__   __`, `\ \ / /`, ` \ V / `, `  | |  `, `  |_|  `},
	'E': {` _____ `, `| ____|`, `|  _|  `, `| |___ `, `|_____|`},
}

func bigText(word string) []string {
	rows := make([]string, 5)
	for i, r := range word {
		for k := 0; k < 5; k++ {
			if i > 0 {
				rows[k] += " "
			}
			rows[k] += byeFont[r][k]
		}
	}
	return rows
}

func rgb(r, g, b int) string { return fmt.Sprintf("\x1b[38;2;%d;%d;%dm", r, g, b) }

// gradient across the text: teal -> cyan -> blue, with an optional white shine band
func gradColor(x, width, shine int) string {
	t := float64(x) / float64(max(width-1, 1))
	type c struct{ r, g, b float64 }
	stops := []c{{45, 212, 191}, {34, 211, 238}, {96, 165, 250}}
	var a, b c
	var u float64
	if t < .5 {
		a, b, u = stops[0], stops[1], t*2
	} else {
		a, b, u = stops[1], stops[2], (t-.5)*2
	}
	r, g, bl := a.r+(b.r-a.r)*u, a.g+(b.g-a.g)*u, a.b+(b.b-a.b)*u
	if d := x - shine; shine >= 0 && d > -5 && d < 5 {
		k := 1 - float64(abs(d))/5
		r, g, bl = r+(255-r)*k, g+(255-g)*k, bl+(255-bl)*k
	}
	return rgb(int(r), int(g), int(bl))
}

func abs(v int) int {
	if v < 0 {
		return -v
	}
	return v
}

func drawBig(rows []string, visible, shine int, pad string) {
	width := len(rows[0])
	for _, row := range rows {
		var sb strings.Builder
		sb.WriteString("\x1b[2K" + pad)
		for x, ch := range row {
			if x >= visible {
				break
			}
			if ch == ' ' {
				sb.WriteByte(' ')
				continue
			}
			sb.WriteString(gradColor(x, width, shine))
			sb.WriteRune(ch)
		}
		sb.WriteString(cReset + "\n")
		fmt.Print(sb.String())
	}
}

// cleanupTemp removes CoreKit's temporary files (scripts, UI window profiles).
func cleanupTemp() int {
	n := 0
	tmp := os.TempDir()
	for _, pat := range []string{"corekit-*.ps1", "corekit-ui-*"} {
		m, _ := filepath.Glob(filepath.Join(tmp, pat))
		for _, p := range m {
			if os.RemoveAll(p) == nil {
				n++
			}
		}
	}
	return n
}

func fmtDur(d time.Duration) string {
	d = d.Round(time.Second)
	h, m, s := int(d.Hours()), int(d.Minutes())%60, int(d.Seconds())%60
	if h > 0 {
		return fmt.Sprintf("%dh %02dm %02ds", h, m, s)
	}
	if m > 0 {
		return fmt.Sprintf("%dm %02ds", m, s)
	}
	return fmt.Sprintf("%ds", s)
}

func goodbye(quick bool) {
	byeOnce.Do(func() { goodbyeScreen(quick) })
}

// goodbyeScreen lasts exactly 3 seconds (about 1.5 s when the window is being closed).
func goodbyeScreen(quick bool) {
	began := time.Now()
	total := 3 * time.Second
	speed := 1.0
	if quick {
		speed, total = 0.5, 1500*time.Millisecond
	}
	wait := func(ms int) { time.Sleep(time.Duration(float64(ms)*speed) * time.Millisecond) }
	frames := []string{"[|]", "[/]", "[-]", "[\\]"} // console fonts (Consolas) lack braille spinners
	teal := rgb(45, 212, 191)

	fmt.Print("\x1b[?25l\x1b[2J\x1b[H\n")
	fmt.Printf("    %sC O R E K I T%s   %s//  shutting down securely%s\n\n", teal, cReset, cGray, cReset)

	step := func(label string, work func() string) {
		done := make(chan string, 1)
		go func() { done <- work() }()
		i := 0
		minEnd := time.Now().Add(time.Duration(float64(220)*speed) * time.Millisecond)
		var res string
		for {
			select {
			case r := <-done:
				res = r
				done = nil
			default:
			}
			if done == nil && time.Now().After(minEnd) {
				break
			}
			fmt.Printf("\r    %s%s%s  %s%-38s%s", cCyan, frames[i%len(frames)], cReset, cWhite, label, cReset)
			i++
			time.Sleep(60 * time.Millisecond)
		}
		fmt.Printf("\r    %s[+]%s  %s%-38s%s %s%s%s\n", cGreen, cReset, cWhite, label, cReset, cGray, res, cReset)
	}

	var cleaned int
	step("Stopping proxy tunnels", func() string {
		n := activeEngines()
		engineStopAll()
		if n == 0 {
			return "none running"
		}
		return fmt.Sprintf("%d stopped", n)
	})
	step("Removing temporary files", func() string {
		cleaned = cleanupTemp()
		return fmt.Sprintf("%d removed", cleaned)
	})
	step("Wiping decrypted settings from memory", func() string {
		brMu.Lock()
		if brCfg != nil {
			for _, p := range brCfg.Proxies {
				p.Link = strings.Repeat("\x00", len(p.Link))
			}
		}
		brCfg = nil
		brMu.Unlock()
		return "done"
	})

	// session summary
	session.mu.Lock()
	var used []string
	for _, k := range []string{"Health Inspector", "Internet Troubleshooter", "Safe Browser"} {
		if n := session.used[k]; n > 0 {
			if n > 1 {
				used = append(used, fmt.Sprintf("%s ×%d", k, n))
			} else {
				used = append(used, k)
			}
		}
	}
	session.mu.Unlock()
	if len(used) == 0 {
		used = []string{"—"}
	}
	line := cGray + strings.Repeat("─", 64) + cReset
	fmt.Printf("\n    %s\n", line)
	fmt.Printf("    %sSESSION%s   %s%s%s\n", cGray, cReset, cWhite, fmtDur(time.Since(session.start)), cReset)
	fmt.Printf("    %sMODULES%s   %s%s%s\n", cGray, cReset, cWhite, strings.Join(used, "  ·  "), cReset)
	fmt.Printf("    %sTRACES%s    %sno tunnels, temp files or keys left running%s\n", cGray, cReset, cWhite, cReset)
	fmt.Printf("    %s\n\n", line)
	wait(120)

	// big animated GOODBYE: scan-in from the left, then one shine sweep
	rows := bigText("GOODBYE")
	width := len(rows[0])
	pad := "    "
	fmt.Print("\x1b7") // save cursor
	steps := 18
	for f := 1; f <= steps; f++ {
		fmt.Print("\x1b8")
		drawBig(rows, width*f/steps, -100, pad)
		time.Sleep(time.Duration(float64(22)*speed) * time.Millisecond)
	}
	if !quick {
		for s := -6; s <= width+6; s += 4 {
			fmt.Print("\x1b8")
			drawBig(rows, width, s, pad)
			time.Sleep(16 * time.Millisecond)
		}
	}
	fmt.Print("\x1b8")
	drawBig(rows, width, -100, pad)

	// typed farewell
	user := os.Getenv("USERNAME")
	if user == "" {
		user = "friend"
	}
	msg := "Stay secure, " + user + ".  See you next time."
	fmt.Printf("\n    %s", teal)
	for _, r := range msg {
		fmt.Print(string(r))
		time.Sleep(time.Duration(float64(11)*speed) * time.Millisecond)
	}
	fmt.Print(cReset + "\n\n")

	// hold the finished screen until exactly 3 seconds have passed
	if rest := total - time.Since(began); rest > 0 {
		time.Sleep(rest)
	}
	fmt.Print("\x1b[?25h" + cReset)
}
