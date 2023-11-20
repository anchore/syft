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

	// PackageCatalogerStarted is a partybus event that occurs when the package cataloging has begun
	PackageCatalogerStarted partybus.EventType = typePrefix + "-package-cataloger-started-event"

	// FileMetadataCatalogerStarted is a partybus event that occurs when the file metadata cataloging has begun
	FileMetadataCatalogerStarted partybus.EventType = typePrefix + "-file-metadata-cataloger-started-event"

	// FileDigestsCatalogerStarted is a partybus event that occurs when the file digests cataloging has begun
	FileDigestsCatalogerStarted partybus.EventType = typePrefix + "-file-digests-cataloger-started-event"

	// FileIndexingStarted is a partybus event that occurs when the directory resolver begins indexing a filesystem
	FileIndexingStarted partybus.EventType = typePrefix + "-file-indexing-started-event"

	// AttestationStarted is a partybus event that occurs when starting an SBOM attestation process
	AttestationStarted partybus.EventType = typePrefix + "-attestation-started-event"

	// CatalogerTaskStarted is a partybus event that occurs when starting a task within a cataloger
	CatalogerTaskStarted partybus.EventType = typePrefix + "-cataloger-task-started"

	// Events exclusively for the CLI

	// CLIAppUpdateAvailable is a partybus event that occurs when an application update is available
	CLIAppUpdateAvailable partybus.EventType = cliTypePrefix + "-app-update-available"

	// CLIReport is a partybus event that occurs when an analysis result is ready for final presentation to stdout
	CLIReport partybus.EventType = cliTypePrefix + "-report"

	// CLINotification is a partybus event that occurs when auxiliary information is ready for presentation to stderr
	CLINotification partybus.EventType = cliTypePrefix + "-notification"
)
