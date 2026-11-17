//go:build !windows

package main

import (
	"fmt"
	"os"
)

func relaunchElevated() bool { return false }

func launchBrowserWindow() (string, error) {
	p := pickProfile("")
	return p.Name, launchUnelevated(os.Args[0], []string{"--browser", p.ID}, 0)
}

func runPicker() { runBrowser("", 0, false, false) }

// runBrowser on non-Windows builds only serves the browser's pages for UI testing.
func runBrowser(id string, waitPID int, reset, keepPw bool) {
	srv, err := startSBServer(func() string { return "google" })
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("UI    " + srv.UIURL())
	fmt.Println("START " + srv.StartURL())
	fmt.Println("PICK  " + srv.PickerURL())
	select {}
}
