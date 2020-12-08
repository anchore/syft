/*
Package event provides event types for all events that the syft library published onto the event bus. By convention, for each event
defined here there should be a corresponding event parser defined in the parsers/ child package.
*/
package event

import "github.com/wagoodman/go-partybus"

const (
	// AppUpdateAvailable is a partybus event that occurs when an application update is available
	AppUpdateAvailable partybus.EventType = "syft-app-update-available"

	// CatalogerStarted is a partybus event that occurs when the package cataloging has begun
	CatalogerStarted partybus.EventType = "syft-cataloger-started-event"

	// CatalogerFinished is a partybus event that occurs when the package cataloging has completed
	CatalogerFinished partybus.EventType = "syft-cataloger-finished-event"

	// ImportStarted is a partybus event that occurs when an SBOM upload process has begun
	ImportStarted partybus.EventType = "syft-import-started-event"
)
