package ui

import (
	"fmt"
	"io"

	syftEventParsers "github.com/anchore/syft/syft/event/parsers"
	"github.com/wagoodman/go-partybus"
)

// handleCatalogerPresenterReady is a UI function for processing the CatalogerFinished bus event, displaying the catalog
// via the given presenter to stdout.
func handleCatalogerPresenterReady(event partybus.Event, reportOutput io.Writer) error {
	// show the report to stdout
	pres, err := syftEventParsers.ParsePresenterReady(event)
	if err != nil {
		return fmt.Errorf("bad CatalogerFinished event: %w", err)
	}

	if err := pres.Present(reportOutput); err != nil {
		return fmt.Errorf("unable to show package catalog report: %w", err)
	}
	return nil
}
