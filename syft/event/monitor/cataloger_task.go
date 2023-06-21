package monitor

import (
	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/go-progress"

	"github.com/anchore/syft/internal/bus"
	"github.com/anchore/syft/syft/event"
)

// TODO: this should be refactored to support read-only/write-only access using idioms of the progress lib

type CatalogerTask struct {
	prog *progress.Manual
	// Title
	Title string
	// TitleOnCompletion a string to use as title when completed
	TitleOnCompletion string
	// SubStatus indicates this progress should be rendered as a sub-item
	SubStatus bool
	// RemoveOnCompletion indicates this progress line will be removed when completed
	RemoveOnCompletion bool
	// value is the value to display -- not public as SetValue needs to be called to initialize this progress
	value string
}

func (e *CatalogerTask) init() {
	e.prog = progress.NewManual(-1)

	bus.Publish(partybus.Event{
		Type:   event.CatalogerTaskStarted,
		Source: e,
	})
}

func (e *CatalogerTask) SetCompleted() {
	if e.prog != nil {
		e.prog.SetCompleted()
	}
}

func (e *CatalogerTask) SetValue(value string) {
	if e.prog == nil {
		e.init()
	}
	e.value = value
}

func (e *CatalogerTask) GetValue() string {
	return e.value
}

func (e *CatalogerTask) GetMonitor() *progress.Manual {
	return e.prog
}
