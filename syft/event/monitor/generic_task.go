package monitor

import (
	"io"

	"github.com/wagoodman/go-progress"
)

type ShellProgress struct {
	io.Reader
	progress.Progressable
}

type Title struct {
	Default      string
	WhileRunning string
	OnSuccess    string
}

type GenericTask struct {

	// required fields

	Title Title

	// optional format fields

	HideOnSuccess      bool
	HideStageOnSuccess bool

	// optional fields

	ID       string
	ParentID string
	Context  string
}
