package event

import "github.com/wagoodman/go-partybus"

const (
	AppUpdateAvailable partybus.EventType = "app-update-available"
	CatalogerStarted   partybus.EventType = "cataloger-started-event"
	CatalogerFinished  partybus.EventType = "cataloger-finished-event"
)
