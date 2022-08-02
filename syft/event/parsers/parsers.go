/*
Package parsers provides parser helpers to extract payloads for each event type that the syft library publishes onto the event bus.
*/
package parsers

import (
	"fmt"

	"github.com/anchore/syft/syft/event"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg/cataloger"
	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/go-progress"
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

func ParseSecretsCatalogingStarted(e partybus.Event) (*file.SecretsMonitor, error) {
	if err := checkEventType(e.Type, event.SecretsCatalogerStarted); err != nil {
		return nil, err
	}

	monitor, ok := e.Value.(file.SecretsMonitor)
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

func ParseExit(e partybus.Event) (func() error, error) {
	if err := checkEventType(e.Type, event.Exit); err != nil {
		return nil, err
	}

	fn, ok := e.Value.(func() error)
	if !ok {
		return nil, newPayloadErr(e.Type, "Value", e.Value)
	}

	return fn, nil
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

	host, ok := e.Source.(string)
	if !ok {
		return "", nil, newPayloadErr(e.Type, "Source", e.Source)
	}

	prog, ok := e.Value.(progress.StagedProgressable)
	if !ok {
		return "", nil, newPayloadErr(e.Type, "Value", e.Value)
	}

	return host, prog, nil
}

func ParseUploadAttestation(e partybus.Event) (progress.StagedProgressable, error) {
	if err := checkEventType(e.Type, event.UploadAttestation); err != nil {
		return nil, err
	}

	prog, ok := e.Value.(progress.StagedProgressable)
	if !ok {
		return nil, newPayloadErr(e.Type, "Value", e.Value)
	}

	return prog, nil
}
