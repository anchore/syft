package event

import "github.com/wagoodman/go-partybus"

const (
	AppUpdateAvailable partybus.EventType = "syft-app-update-available"
	CatalogerStarted   partybus.EventType = "syft-cataloger-started-event"
	CatalogerFinished  partybus.EventType = "syft-cataloger-finished-event"
)
