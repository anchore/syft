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
	"github.com/anchore/syft/syft/file/cataloger/secrets"
	"github.com/anchore/syft/syft/pkg/cataloger"
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

func ParsePackageCatalogerStarted(e partybus.Event) (*cataloger.Monitor, error) {
	if err := checkEventType(e.Type, event.PackageCatalogerStarted); err != nil {
		return nil, err
	}

	monitor, ok := e.Value.(cataloger.Monitor)
	if !ok {
		return nil, newPayloadErr(e.Type, "Value", e.Value)
	}

	return &monitor, nil
}

func ParseSecretsCatalogingStarted(e partybus.Event) (*secrets.Monitor, error) {
	if err := checkEventType(e.Type, event.SecretsCatalogerStarted); err != nil {
		return nil, err
	}

	monitor, ok := e.Value.(secrets.Monitor)
	if !ok {
		return nil, newPayloadErr(e.Type, "Value", e.Value)
	}

	return &monitor, nil
}

func ParseFileMetadataCatalogingStarted(e partybus.Event) (progress.StagedProgressable, error) {
	if err := checkEventType(e.Type, event.FileMetadataCatalogerStarted); err != nil {
		return nil, err
	}

	prog, ok := e.Value.(progress.StagedProgressable)
	if !ok {
		return nil, newPayloadErr(e.Type, "Value", e.Value)
	}

	return prog, nil
}

func ParseFileDigestsCatalogingStarted(e partybus.Event) (progress.StagedProgressable, error) {
	if err := checkEventType(e.Type, event.FileDigestsCatalogerStarted); err != nil {
		return nil, err
	}

	prog, ok := e.Value.(progress.StagedProgressable)
	if !ok {
		return nil, newPayloadErr(e.Type, "Value", e.Value)
	}

	return prog, nil
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

func ParseCatalogerTaskStarted(e partybus.Event) (*monitor.CatalogerTask, error) {
	if err := checkEventType(e.Type, event.CatalogerTaskStarted); err != nil {
		return nil, err
	}

	source, ok := e.Source.(*monitor.CatalogerTask)
	if !ok {
		return nil, newPayloadErr(e.Type, "Source", e.Source)
	}

	return source, nil
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

func ParseCLIExit(e partybus.Event) (func() error, error) {
	if err := checkEventType(e.Type, event.CLIExit); err != nil {
		return nil, err
	}

	fn, ok := e.Value.(func() error)
	if !ok {
		return nil, newPayloadErr(e.Type, "Value", e.Value)
	}

	return fn, nil
}

func ParseCLIAppUpdateAvailable(e partybus.Event) (string, error) {
	if err := checkEventType(e.Type, event.CLIAppUpdateAvailable); err != nil {
		return "", err
	}

	newVersion, ok := e.Value.(string)
	if !ok {
		return "", newPayloadErr(e.Type, "Value", e.Value)
	}

	return newVersion, nil
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
