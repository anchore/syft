package ui

import (
	"github.com/wagoodman/go-partybus"
)

// UI is a function that takes a channel of errors from the main() worker and a event bus subscription and is
// responsible for displaying pertinent events to the user, on the screen or otherwise.
type UI func(<-chan error, *partybus.Subscription) error
