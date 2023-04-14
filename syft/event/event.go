/*
Package event provides event types for all events that the syft library published onto the event bus. By convention, for each event
defined here there should be a corresponding event parser defined in the parsers/ child package.
*/
package event

import "github.com/wagoodman/go-partybus"

const (
	// AppUpdateAvailable is a partybus event that occurs when an application update is available
	AppUpdateAvailable partybus.EventType = "syft-app-update-available"

	// PackageCatalogerStarted is a partybus event that occurs when the package cataloging has begun
	PackageCatalogerStarted partybus.EventType = "syft-package-cataloger-started-event"

	//nolint:gosec
	// SecretsCatalogerStarted is a partybus event that occurs when the secrets cataloging has begun
	SecretsCatalogerStarted partybus.EventType = "syft-secrets-cataloger-started-event"

	// FileMetadataCatalogerStarted is a partybus event that occurs when the file metadata cataloging has begun
	FileMetadataCatalogerStarted partybus.EventType = "syft-file-metadata-cataloger-started-event"

	// FileDigestsCatalogerStarted is a partybus event that occurs when the file digests cataloging has begun
	FileDigestsCatalogerStarted partybus.EventType = "syft-file-digests-cataloger-started-event"

	// FileIndexingStarted is a partybus event that occurs when the directory resolver begins indexing a filesystem
	FileIndexingStarted partybus.EventType = "syft-file-indexing-started-event"

	// Exit is a partybus event that occurs when an analysis result is ready for final presentation
	Exit partybus.EventType = "syft-exit-event"

	// ImportStarted is a partybus event that occurs when an SBOM upload process has begun
	ImportStarted partybus.EventType = "syft-import-started-event"

	// AttestationStarted is a partybus event that occurs when starting an SBOM attestation process
	AttestationStarted partybus.EventType = "syft-attestation-started-event"

	// CatalogerTaskStarted is a partybus event that occurs when starting a task within a cataloger
	CatalogerTaskStarted partybus.EventType = "syft-cataloger-task-started"
)
