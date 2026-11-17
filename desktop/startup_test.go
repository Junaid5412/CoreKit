package main

import "testing"

func TestStartupModes(t *testing.T) {
	p := &brProfile{Search: "google"}
	if p.startMode() != "restore" {
		t.Fatal("default must keep data and continue where left off")
	}
	p.KeepHistory = false // the old "leave no trace" default no longer clears data
	if p.startMode() != "restore" {
		t.Fatal("old profiles must not start clearing data")
	}
	p.setStartup("page", "example.com")
	if p.startMode() != "page" || p.StartURL == "" || p.StartURL == "example.com" {
		t.Fatalf("page: %q %q", p.startMode(), p.StartURL)
	}
	p.setStartup("page", "  ")
	if p.startMode() != "newtab" {
		t.Fatal("a page without an address falls back to a new tab")
	}
	p.setStartup("clear", "")
	if p.startMode() != "clear" {
		t.Fatal("clear")
	}
	p.setStartup("bogus", "")
	if p.startMode() != "clear" {
		t.Fatal("unknown modes are ignored")
	}
}
