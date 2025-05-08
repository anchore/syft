/*
Package parsers provides parser helpers to extract payloads for each event type that the syft library publishes onto the event bus.
*/
package parsers

import (
	"fmt"
	"io"

	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/go-progress"

	"github.com/anchore/syft/syft/event"
	"github.com/anchore/syft/syft/event/monitor"
)

type ErrBadPayload struct {
	Type  partybus.EventType
	Field string
	Value interface{}
}

func (e *ErrBadPayload) Error() string {
	return fmt.Sprintf("event='%s' has bad event payload field=%q: %q", string(e.Type), e.Field, e.Value)
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

func ParseFileIndexingStarted(e partybus.Event) (string, progress.StagedProgressable, error) {
	if err := checkEventType(e.Type, event.FileIndexingStarted); err != nil {
		return "", nil, err
	}

	path, ok := e.Source.(string)
	if !ok {
		return "", nil, newPayloadErr(e.Type, "Source", e.Source)
	}

	prog, ok := e.Value.(progress.StagedProgressable)
	if !ok {
		return "", nil, newPayloadErr(e.Type, "Value", e.Value)
	}

	return path, prog, nil
}

func ParseCatalogerTaskStarted(e partybus.Event) (progress.StagedProgressable, *monitor.GenericTask, error) {
	if err := checkEventType(e.Type, event.CatalogerTaskStarted); err != nil {
		return nil, nil, err
	}

	var mon progress.StagedProgressable

	source, ok := e.Source.(monitor.GenericTask)
	if !ok {
		return nil, nil, newPayloadErr(e.Type, "Source", e.Source)
	}

	mon, ok = e.Value.(progress.StagedProgressable)
	if !ok {
		mon = nil
	}

	return mon, &source, nil
}

func ParseAttestationStartedEvent(e partybus.Event) (io.Reader, progress.Progressable, *monitor.GenericTask, error) {
	if err := checkEventType(e.Type, event.AttestationStarted); err != nil {
		return nil, nil, nil, err
	}

	source, ok := e.Source.(monitor.GenericTask)
	if !ok {
		return nil, nil, nil, newPayloadErr(e.Type, "Source", e.Source)
	}

	sp, ok := e.Value.(*monitor.ShellProgress)
	if !ok {
		return nil, nil, nil, newPayloadErr(e.Type, "Value", e.Value)
	}

	return sp.Reader, sp.Progressable, &source, nil
}

// CLI event types

type UpdateCheck struct {
	New     string
	Current string
}

func ParseCLIAppUpdateAvailable(e partybus.Event) (*UpdateCheck, error) {
	if err := checkEventType(e.Type, event.CLIAppUpdateAvailable); err != nil {
		return nil, err
	}

	updateCheck, ok := e.Value.(UpdateCheck)
	if !ok {
		return nil, newPayloadErr(e.Type, "Value", e.Value)
	}

	return &updateCheck, nil
}

func ParseCLIReport(e partybus.Event) (string, string, error) {
	if err := checkEventType(e.Type, event.CLIReport); err != nil {
		return "", "", err
	}

	context, ok := e.Source.(string)
	if !ok {
		// this is optional
		context = ""
	}

	report, ok := e.Value.(string)
	if !ok {
		return "", "", newPayloadErr(e.Type, "Value", e.Value)
	}

	return context, report, nil
}

func ParseCLINotification(e partybus.Event) (string, string, error) {
	if err := checkEventType(e.Type, event.CLINotification); err != nil {
		return "", "", err
	}

	context, ok := e.Source.(string)
	if !ok {
		// this is optional
		context = ""
	}

	notification, ok := e.Value.(string)
	if !ok {
		return "", "", newPayloadErr(e.Type, "Value", e.Value)
	}

	return context, notification, nil
}
