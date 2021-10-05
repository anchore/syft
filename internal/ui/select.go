package ui

import (
	"io"
	"os"
	"runtime"

	"golang.org/x/crypto/ssh/terminal"
)

// TODO: build tags to exclude options from windows

// Select is responsible for determining the specific UI function given select user option, the current platform
// config values, and environment status (such as a TTY being present). A writer is provided to capture the output
// of the final SBOM report.
func Select(verbose, quiet bool, reportWriter io.Writer) UI {
	var ui UI

	isStdoutATty := terminal.IsTerminal(int(os.Stdout.Fd()))
	isStderrATty := terminal.IsTerminal(int(os.Stderr.Fd()))
	notATerminal := !isStderrATty && !isStdoutATty

	switch {
	case runtime.GOOS == "windows" || verbose || quiet || notATerminal || !isStderrATty:
		ui = NewLoggerUI(reportWriter)
	default:
		ui = NewEphemeralTerminalUI(reportWriter)
	}

	return ui
}
