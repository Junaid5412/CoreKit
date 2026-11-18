// Package ui holds the web interface shared by every CoreKit platform
// (Windows and Linux embed it in the binary; Android packages it as app assets).
package ui

import _ "embed"

var (
	//go:embed health.html
	Health []byte
	//go:embed net.html
	Net []byte
	//go:embed browser.html
	Browser []byte
	//go:embed start.html
	Start []byte
	//go:embed picker.html
	Picker []byte
	//go:embed logs.html
	Logs []byte
	//go:embed remote.html
	Remote []byte
	//go:embed vm.html
	VM []byte
)
