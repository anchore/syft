package ui

import (
	"fmt"
	"strings"
)

type Title struct {
	Name, Version string
}

func (t Title) Start() {
	t.start()
	fmt.Println()
}

func (t Title) start() {
	fmt.Printf("%s%s@%s%s", bold, t.Name, t.Version, reset)
}

func (t Title) Update(msg string) {
	goToPreviousLineStart()
	t.start()
	fmt.Print(strings.Repeat(" ", 35-(len(t.Name)+len(t.Version))))
	fmt.Printf("  %s⚠%s  %s%s%s\n", bold, reset, italic+grey, msg, reset)
}

func (t Title) Skip(msg string) {
	goToPreviousLineStart()
	t.start()
	fmt.Print(strings.Repeat(" ", 35-(len(t.Name)+len(t.Version))))
	formatSkip(msg)
}
