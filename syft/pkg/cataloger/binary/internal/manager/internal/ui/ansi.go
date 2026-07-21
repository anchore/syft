package ui

import "fmt"

const (
	grey   = "\033[90m"
	reset  = "\033[0m"
	bold   = "\033[1m"
	red    = "\033[31m"
	italic = "\033[3m"
	purple = "\033[95m" // hi variant
	green  = "\033[32m"
)

func goToPreviousLineStart() {
	fmt.Printf("\033[F")
}
