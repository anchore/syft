package monitor

import (
	"io"

	"github.com/wagoodman/go-progress"
)

type ShellProgress struct {
	io.Reader
	*progress.Manual
}

type Title struct {
	Default      string
	WhileRunning string
	OnSuccess    string
}

type GenericTask struct {
	Title   Title
	Context string
}
