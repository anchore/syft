/*
Package event provides event types for all events that the syft library published onto the event bus. By convention, for each event
defined here there should be a corresponding event parser defined in the parsers/ child package.
*/
package event

import (
	"github.com/wagoodman/go-partybus"
)

const (
	typePrefix    = "syft"
	cliTypePrefix = typePrefix + "-cli"

	// Events from the syft library

	// FileIndexingStarted is a partybus event that occurs when the directory resolver begins indexing a filesystem
	FileIndexingStarted partybus.EventType = typePrefix + "-file-indexing-started-event"

	// AttestationStarted is a partybus event that occurs when starting an SBOM attestation process
	AttestationStarted partybus.EventType = typePrefix + "-attestation-started-event"

	// CatalogerTaskStarted is a partybus event that occurs when starting a task within a cataloger
	CatalogerTaskStarted partybus.EventType = typePrefix + "-cataloger-task-started"

	// PullSourceStarted is a partybus event that occurs when starting to pull a source (does not overlap with stereoscope image pull events,
	// this covers any additional sources such as snap and git repos).
	PullSourceStarted partybus.EventType = typePrefix + "-pull-source-started"

	// Events exclusively for the CLI

	// CLIAppUpdateAvailable is a partybus event that occurs when an application update is available
	CLIAppUpdateAvailable partybus.EventType = cliTypePrefix + "-app-update-available"

	// CLIReport is a partybus event that occurs when an analysis result is ready for final presentation to stdout
	CLIReport partybus.EventType = cliTypePrefix + "-report"

	// CLINotification is a partybus event that occurs when auxiliary information is ready for presentation to stderr
	CLINotification partybus.EventType = cliTypePrefix + "-notification"
)
