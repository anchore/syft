package parsers

import (
	"fmt"

	"github.com/anchore/imgbom/imgbom/cataloger"
	"github.com/anchore/imgbom/imgbom/event"
	"github.com/anchore/imgbom/imgbom/presenter"
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
