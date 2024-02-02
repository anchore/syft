package ui

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

type Action struct {
	Msg string
}

func (a Action) Start() {
	fmt.Printf("  •  %s%s%s\n", purple+italic, a.Msg, reset)
}

func (a Action) Skip(newMsg ...string) {
	if len(newMsg) > 0 {
		// clear the line
		goToPreviousLineStart()
		// add a little extra to account for ansi escape codes (hack)
		fmt.Printf("%s\n", strings.Repeat(" ", len(a.Msg)+10))
		a.Msg = newMsg[0]
	}
	goToPreviousLineStart()
	formatSkip(a.Msg)
}

func (a Action) Done(err error) {
	goToPreviousLineStart()
	if err != nil {
		fmt.Printf("  %s✗%s  %s%s%s\n", red+bold, reset, red, a.Msg, reset)

		var exitError *exec.ExitError
		if errors.As(err, &exitError) && len(exitError.Stderr) > 0 {
			fmt.Printf("  %s├──%s  %s%s%s\n", grey, reset, red, err, reset)
			fmt.Printf("  %s└──%s  %s%s%s\n", grey, reset, red, "stderr:", reset)
			fmt.Println(string(exitError.Stderr))
		} else {
			fmt.Printf("  %s└──%s  %s%s%s\n", grey, reset, red, err, reset)
		}
		return
	}
	fmt.Printf("  %s✔%s  %s\n", green+bold, reset, a.Msg)
}

func formatSkip(msg string) {
	fmt.Printf("  %s⏭%s  %s%s%s\n", bold, reset, grey, msg, reset)
}
