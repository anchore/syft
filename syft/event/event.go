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
	PackageCatalogerStarted partybus.EventType = "syft-cataloger-started-event"

	// PresenterReady is a partybus event that occurs when an analysis result is ready for final presentation
	PresenterReady partybus.EventType = "syft-presenter-ready-event"

	// ImportStarted is a partybus event that occurs when an SBOM upload process has begun
	ImportStarted partybus.EventType = "syft-import-started-event"
)
