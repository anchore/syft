package ui

import (
	"fmt"

	syftEventParsers "github.com/anchore/syft/syft/event/parsers"
	"github.com/wagoodman/go-partybus"
)

// handleCatalogerPresenterReady is a UI function for processing the CatalogerFinished bus event, displaying the catalog
// via the given presenter to stdout.
func handleCatalogerPresenterReady(event partybus.Event) error {
	// show the report to stdout
	fn, err := syftEventParsers.ParsePresenterReady(event)
	if err != nil {
		return fmt.Errorf("bad CatalogerFinished event: %w", err)
	}

	if err := fn(); err != nil {
		return fmt.Errorf("unable to show package catalog report: %v", err)
	}
	return nil
}
