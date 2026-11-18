package main

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	cReset  = "\x1b[0m"
	cGreen  = "\x1b[92m"
	cDGreen = "\x1b[32m"
	cCyan   = "\x1b[96m"
	cWhite  = "\x1b[97m"
	cGray   = "\x1b[90m"
	cRed    = "\x1b[91m"
	cYellow = "\x1b[93m"
)

var banner = []string{
	`  ____    ___    ____    _____   _  __  ___   _____`,
	` / ___|  / _ \  |  _ \  | ____| | |/ / |_ _| |_   _|`,
	`| |     | | | | | |_) | |  _|   | ' /   | |    | |`,
	`| |___  | |_| | |  _ <  | |___  | . \   | |    | |`,
	` \____|  \___/  |_| \_\ |_____| |_|\_\ |___|   |_|`,
}

var logMu sync.Mutex

func rule() { fmt.Printf("   %s%s%s\n", cDGreen, strings.Repeat("=", 72), cReset) }

func info(k, v, col string) {
	fmt.Printf("    %s%-7s :%s %s%s%s\n", cGray, k, cReset, col, v, cReset)
}

func drawMenu() {
	fmt.Print("\x1b[2J\x1b[H\x1b[?25l")
	fmt.Println()
	for _, l := range banner {
		fmt.Printf("    %s%s%s\n", cGreen, l, cReset)
	}
	fmt.Printf("        %sS Y S T E M   T O O L K I T    //    v %s%s\n\n", cCyan, strings.Join(strings.Split(appVersion, ""), " "), cReset)
	rule()
	host, _ := os.Hostname()
	info("HOST", host, cWhite)
	info("USER", os.Getenv("USERNAME"), cWhite)
	info("OS", osName(), cWhite)
	if isAdmin() {
		info("PRIV", "ADMINISTRATOR  (full access)", cGreen)
	} else {
		info("PRIV", "LIMITED  (re-open and click Yes)", cYellow)
	}
	info("TIME", time.Now().Format("02 Jan 2006  15:04"), cWhite)
	rule()
	fmt.Printf("\n    %sSELECT MODULE%s\n\n", cGray, cReset)
	item("1", "HEALTH INSPECTOR", "Full hardware scan + health score")
	item("2", "INTERNET TROUBLESHOOTER", "Diagnose & fix Wi-Fi, DNS, HTTPS + speed test")
	item("3", "SAFE BROWSER", "Own browser: vertical tabs, profiles, proxy / VPN (VLESS, SOCKS5...)")
	item("4", "ACTIVITY LOG", "Who used this PC & when: sign-ins, programs, file changes, deletions")
	item("5", "REMOTE ACCESS", "Control a phone/PC on the same Wi-Fi with a code, or share this PC; calls")
	item("0", "EXIT", "Close the toolkit")
	fmt.Printf("\n    %s-- more modules coming soon --%s\n\n", cGray, cReset)
	user := "user"
	if isAdmin() {
		user = "root"
	}
	fmt.Printf("    %s%s@corekit:~#%s \x1b[?25h", cGreen, user, cReset)
}

func item(n, name, desc string) {
	fmt.Printf("    %s[%s%s%s]%s  %s%-26s%s%s%s\n", cDGreen, cGreen, n, cDGreen, cReset, cWhite, name, cReset, cGray+desc, cReset)
}

func boot(module string) {
	type row struct{ label, status, col string }
	priv, pcol := "ROOT", cGreen
	if !isAdmin() {
		priv, pcol = "LIMITED", cYellow
	}
	rows := []row{
		{"Loading module :: " + module, "OK", cGreen},
		{"Checking privileges", priv, pcol},
		{"Preparing diagnostic engine", "OK", cGreen},
		{"Starting interface", "OK", cGreen},
	}
	fmt.Println()
	for _, r := range rows {
		fmt.Printf("    %s[*] %s%s", cDGreen, r.label+" "+strings.Repeat(".", 46-len(r.label)), cReset)
		time.Sleep(110 * time.Millisecond)
		fmt.Printf(" %s[ %s ]%s\n", r.col, r.status, cReset)
	}
	fmt.Printf("\n    %s[>] Window open. Close it to return to this menu.%s\n\n", cCyan, cReset)
}

// logLine prints a scan log line coming from the collector.
func logLine(kind, text string) {
	col := cGray
	switch kind {
	case "+":
		col = cGreen
	case "!":
		col = cRed
	case "~":
		col = cYellow
	case "#":
		col = cCyan
	}
	logMu.Lock()
	fmt.Printf("    %s%s%s  %s[%s] %s%s\n", cGray, time.Now().Format("15:04:05"), cReset, col, kind, text, cReset)
	logMu.Unlock()
}
