/*
Package event provides event types for all events that the syft library published onto the event bus. By convention, for each event
defined here there should be a corresponding event parser defined in the parsers/ child package.
*/
package event

import "github.com/wagoodman/go-partybus"

const (
	AppUpdateAvailable partybus.EventType = "syft-app-update-available"
	CatalogerStarted   partybus.EventType = "syft-cataloger-started-event"
	CatalogerFinished  partybus.EventType = "syft-cataloger-finished-event"
)
