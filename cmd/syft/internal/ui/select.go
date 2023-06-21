//go:build linux || darwin || netbsd
// +build linux darwin netbsd

package ui

import (
	"os"
	"runtime"

	"golang.org/x/term"

	"github.com/anchore/clio"
	handler "github.com/anchore/syft/cmd/syft/cli/ui"
)

// Select is responsible for determining the specific UI function given select user option, the current platform
// config values, and environment status (such as a TTY being present). The first UI in the returned slice of UIs
// is intended to be used and the UIs that follow are meant to be attempted only in a fallback posture when there
// are environmental problems (e.g. cannot write to the terminal). A writer is provided to capture the output of
// the final SBOM report.
func Select(verbose, quiet bool) (uis []clio.UI) {
	isStdoutATty := term.IsTerminal(int(os.Stdout.Fd()))
	isStderrATty := term.IsTerminal(int(os.Stderr.Fd()))
	notATerminal := !isStderrATty && !isStdoutATty

	switch {
	case runtime.GOOS == "windows" || verbose || quiet || notATerminal || !isStderrATty:
		uis = append(uis, None(quiet))
	default:
		// TODO: it may make sense in the future to pass handler options into select
		h := handler.New(handler.DefaultHandlerConfig())
		uis = append(uis, New(h, verbose, quiet))
	}

	return uis
}
