package main

import (
	_ "embed"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/Junaid5412/corekit/ui"
)

var indexHTML = ui.Health

//go:embed scripts/collector.ps1
var collectorPS []byte

var netHTML = ui.Net

//go:embed scripts/net.ps1
var netPS []byte

var logsHTML = ui.Logs

var remoteHTML = ui.Remote
var vmHTML = ui.VM

//go:embed scripts/activity.ps1
var activityPS []byte

//go:embed scripts/activity_restore.ps1
var activityRestorePS []byte

// appVersion is set at build time from the VERSION file (-ldflags "-X main.appVersion=...").
var appVersion = "dev"

func main() {
	serveOnly := flag.String("serve", "", "start a module UI directly: health | net (testing)")
	browser := flag.String("browser", "\x00", "open CoreKit Browser with a profile id")
	waitPID := flag.Int("wait", 0, "wait for this process to exit first")
	reset := flag.Bool("reset", false, "reset the profile identity before opening")
	keepPw := flag.Bool("keep-pw", false, "keep saved passwords when resetting")
	noElevate := flag.Bool("no-elevate", false, "do not ask for administrator rights")
	pick := flag.Bool("pick", false, "open CoreKit Browser's profile picker")
	helper := flag.String("helper", "", "run one shared-code command for the Android app (JSON on stdin/stdout)")
	remoteEngine := flag.Bool("remote", false, "run the Remote Access engine for the Android app")
	flag.Parse()
	if *helper != "" {
		os.Exit(runHelper(*helper))
	}
	if *remoteEngine {
		os.Exit(runRemoteEngine())
	}
	if *pick {
		runPicker()
		return
	}
	if *browser != "\x00" {
		runBrowser(*browser, *waitPID, *reset, *keepPw)
		return
	}
	if *serveOnly == "" && !*noElevate && relaunchElevated() {
		return
	}
	initConsole()
	watchExitSignals()
	if *serveOnly != "" {
		runInspector(*serveOnly)
		return
	}
	for {
		drawMenu()
		k := readKey()
		fmt.Printf("%s%c%s\n", cWhite, printable(k), cReset)
		switch k {
		case '1':
			markUsed("Health Inspector")
			boot("health-inspector")
			runInspector("health")
			fmt.Printf("\n    %s[*]%s Module closed.\n", cDGreen, cReset)
			time.Sleep(600 * time.Millisecond)
		case '2':
			markUsed("Internet Troubleshooter")
			boot("internet-troubleshooter")
			runInspector("net")
			fmt.Printf("\n    %s[*]%s Module closed.\n", cDGreen, cReset)
			time.Sleep(600 * time.Millisecond)
		case '4':
			markUsed("Activity Log")
			boot("activity-log")
			runInspector("logs")
			fmt.Printf("\n    %s[*]%s Module closed.\n", cDGreen, cReset)
			time.Sleep(600 * time.Millisecond)
		case '5':
			markUsed("Remote Access")
			boot("remote-access")
			runInspector("remote")
			rEng.shutdown()
			fmt.Printf("\n    %s[*]%s Module closed. Sharing stopped.\n", cDGreen, cReset)
			time.Sleep(600 * time.Millisecond)
		case '3':
			markUsed("Safe Browser")
			logLine("*", "Launching CoreKit Browser")
			if name, err := launchBrowserWindow(); err != nil {
				logLine("!", "Could not open the browser: "+err.Error())
				time.Sleep(2500 * time.Millisecond)
			} else {
				logLine("+", "CoreKit Browser opened: "+name)
				time.Sleep(1300 * time.Millisecond)
			}
		case '0', 27, 'q', 'Q':
			goodbye(false)
			os.Exit(0)
		default:
			fmt.Printf("    %s[!] Unknown command. Press 1-6 or 0.%s\n", cRed, cReset)
			time.Sleep(900 * time.Millisecond)
		}
	}
}

func printable(b byte) rune {
	if b < 32 || b > 126 {
		return ' '
	}
	return rune(b)
}
