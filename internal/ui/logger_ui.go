package ui

import (
	"github.com/anchore/syft/internal/log"
	syftEvent "github.com/anchore/syft/syft/event"
	"github.com/wagoodman/go-partybus"
)

type loggerUI struct {
	unsubscribe func() error
}

func NewLoggerUI() UI {
	return &loggerUI{}
}

func (l *loggerUI) Setup(unsubscribe func() error) error {
	l.unsubscribe = unsubscribe
	return nil
}

func (l loggerUI) Handle(event partybus.Event) error {
	// ignore all events except for the final event
	if event.Type != syftEvent.PresenterReady {
		return nil
	}

	if err := handleCatalogerPresenterReady(event); err != nil {
		log.Warnf("unable to show catalog image finished event: %+v", err)
	}

	// this is the last expected event, stop listening to events
	return l.unsubscribe()
}

func (l loggerUI) Teardown(_ bool) error {
	return nil
}
