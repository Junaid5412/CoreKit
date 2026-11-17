//go:build !windows

package main

import (
	"bufio"
	"bytes"
	"context"
	_ "embed"
	"fmt"
	"os"
	"strings"
	"time"
)

//go:embed testdata/sample.json
var sampleJSON []byte

//go:embed testdata/net_sample.json
var netSampleJSON []byte

func initConsole() {}
func readKey() byte {
	b, err := bufio.NewReader(os.Stdin).ReadByte()
	if err != nil {
		return '0'
	}
	return b
}
func isAdmin() bool  { return true }
func osName() string { return "Test host (non-Windows)" }

type appWindow struct{}

func (a *appWindow) exited() bool    { return true }
func (a *appWindow) cleanup()        {}
func (a *appWindow) keepTag() string { return "" }

func launchWindow(url string) *appWindow {
	fmt.Println("URL " + url)
	if p := os.Getenv("PCHI_URLFILE"); p != "" {
		os.WriteFile(p, []byte(url), 0644)
	}
	return nil
}
func openDefaultBrowser(url string) {}
func revealFile(path string)        {}
func openTarget(what string)        { logLine("#", "open "+what) }

var fixedRan bool

func init() { speedImpl = mockSpeed }

func mockSpeed(ctx context.Context, prog func(phase string, pct int, mbps float64)) speedResult {
	for i := 0; i <= 10; i++ {
		prog("Download", 87+i*7/10, 60+float64(i)*2.5)
		time.Sleep(90 * time.Millisecond)
	}
	for i := 0; i <= 10; i++ {
		prog("Upload", 94+i*5/10, 15+float64(i))
		time.Sleep(70 * time.Millisecond)
	}
	return speedResult{OK: true, Down: 84.6, Up: 24.9, Ping: 18.4, Jitter: 3.2, Server: "Cloudflare DOH"}
}

// mock PowerShell runner for UI testing on non-Windows hosts
func runPS(ctx context.Context, script []byte, args []string, cb func(kind, a, b string)) ([]byte, error) {
	joined := strings.Join(args, " ")
	if bytes.Equal(script, netPS) && strings.Contains(joined, "-Mode fix") {
		acts := ""
		for i, a := range args {
			if a == "-Actions" && i+1 < len(args) {
				acts = args[i+1]
			}
		}
		out := []string{}
		for i, a := range strings.Split(acts, ",") {
			cb("P", fmt.Sprint(i*100/len(strings.Split(acts, ","))), a)
			cb("L", "*", "Running: "+a)
			time.Sleep(300 * time.Millisecond)
			cb("L", "+", "Done: "+a)
			out = append(out, fmt.Sprintf(`{"id":%q,"ok":true,"msg":"Done: %s"}`, a, a))
		}
		fixedRan = true
		return []byte(`{"results":[` + strings.Join(out, ",") + `],"reboot":` + fmt.Sprint(strings.Contains(acts, "reset-stack")) + `}`), nil
	}
	steps := []string{"System", "Processor", "Memory", "Graphics", "Storage", "Battery", "Display", "Devices", "Stability", "Security"}
	data := sampleJSON
	if bytes.Equal(script, netPS) {
		steps = []string{"Network adapters", "Wi-Fi", "Router", "Internet", "Captive portal & clock", "Proxy, hosts & VPN", "DNS benchmark: Current", "DNS benchmark: Cloudflare", "Testing www.google.com", "Analysing"}
		data = netSampleJSON
		if fixedRan {
			data = []byte(strings.Replace(string(netSampleJSON), `"issues":[`, `"issues":[],"_old":[`, 1))
		}
	}
	for i, s := range steps {
		cb("P", fmt.Sprint(3+i*80/len(steps)), s)
		cb("L", "*", s)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
	return data, nil
}
