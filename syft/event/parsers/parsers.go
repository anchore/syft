/*
Package parsers provides parser helpers to extract payloads for each event type that the syft library publishes onto the event bus.
*/
package parsers

import (
	"fmt"

	"github.com/wagoodman/go-progress"

	"github.com/anchore/syft/syft/cataloger"
	"github.com/anchore/syft/syft/event"
	"github.com/anchore/syft/syft/presenter"
	"github.com/wagoodman/go-partybus"
)

type ErrBadPayload struct {
	Type  partybus.EventType
	Field string
	Value interface{}
}

func (e *ErrBadPayload) Error() string {
	return fmt.Sprintf("event='%s' has bad event payload field='%v': '%+v'", string(e.Type), e.Field, e.Value)
}

func newPayloadErr(t partybus.EventType, field string, value interface{}) error {
	return &ErrBadPayload{
		Type:  t,
		Field: field,
		Value: value,
	}
}

func checkEventType(actual, expected partybus.EventType) error {
	if actual != expected {
		return newPayloadErr(expected, "Type", actual)
	}
	return nil
}

func ParseCatalogerStarted(e partybus.Event) (*cataloger.Monitor, error) {
	if err := checkEventType(e.Type, event.CatalogerStarted); err != nil {
		return nil, err
	}

	monitor, ok := e.Value.(cataloger.Monitor)
	if !ok {
		return nil, newPayloadErr(e.Type, "Value", e.Value)
	}

	return &monitor, nil
}

func ParseCatalogerFinished(e partybus.Event) (presenter.Presenter, error) {
	if err := checkEventType(e.Type, event.CatalogerFinished); err != nil {
		return nil, err
	}

	pres, ok := e.Value.(presenter.Presenter)
	if !ok {
		return nil, newPayloadErr(e.Type, "Value", e.Value)
	}

	return pres, nil
}

func ParseAppUpdateAvailable(e partybus.Event) (string, error) {
	if err := checkEventType(e.Type, event.AppUpdateAvailable); err != nil {
		return "", err
	}

	newVersion, ok := e.Value.(string)
	if !ok {
		return "", newPayloadErr(e.Type, "Value", e.Value)
	}

	return newVersion, nil
}

func ParseImportStarted(e partybus.Event) (string, progress.StagedProgressable, error) {
	if err := checkEventType(e.Type, event.ImportStarted); err != nil {
		return "", nil, err
	}

	imgName, ok := e.Source.(string)
	if !ok {
		return "", nil, newPayloadErr(e.Type, "Source", e.Source)
	}

	prog, ok := e.Value.(progress.StagedProgressable)
	if !ok {
		return "", nil, newPayloadErr(e.Type, "Value", e.Value)
	}

	return imgName, prog, nil
}
