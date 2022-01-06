package ui

import (
	"fmt"

	syftEventParsers "github.com/anchore/syft/syft/event/parsers"
	"github.com/wagoodman/go-partybus"
)

// handleExit is a UI function for processing the Exit bus event,
// and calling the given function to output the contents.
func handleExit(event partybus.Event) error {
	// show the report to stdout
	fn, err := syftEventParsers.ParseExit(event)
	if err != nil {
		return fmt.Errorf("bad CatalogerFinished event: %w", err)
	}

	if err := fn(); err != nil {
		return fmt.Errorf("unable to show package catalog report: %v", err)
	}
	return nil
}
