/*
Package bus provides access to a singleton instance of an event bus (provided by the calling application). The event bus
is intended to allow for the syft library to publish events which library consumers can subscribe to. These events
can provide static information, but also have an object as a payload for which the consumer can poll for updates.
This is akin to a logger, except instead of only allowing strings to be logged, rich objects that can be interacted with.

Note that the singleton instance is only allowed to publish events and not subscribe to them --this is intentional.
Internal library interactions should continue to use traditional in-execution-path approaches for data sharing
(e.g. function returns and channels) and not depend on bus subscriptions for critical interactions (e.g. one part of the
lib publishes an event and another part of the lib subscribes and reacts to that event). The bus is provided only as a
means for consumers to observe events emitted from the library (such as to provide a rich UI) and not to allow
consumers to augment or otherwise change execution.
*/
package bus

import "github.com/wagoodman/go-partybus"

var publisher partybus.Publisher

// Set sets the singleton event bus publisher. This is optional; if no bus is provided, the library will
// behave no differently than if a bus had been provided.
func Set(p partybus.Publisher) {
	publisher = p
}

func Get() partybus.Publisher {
	return publisher
}

// Publish an event onto the bus. If there is no bus set by the calling application, this does nothing.
func Publish(e partybus.Event) {
	if publisher != nil {
		publisher.Publish(e)
	}
}
