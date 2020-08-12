package common

import (
	"fmt"
	"os"

	syftEventParsers "github.com/anchore/syft/syft/event/parsers"
	"github.com/wagoodman/go-partybus"
)

// CatalogerFinishedHandler is a UI function for processing the CatalogerFinished bus event, displaying the catalog
// via the given presenter to stdout.
func CatalogerFinishedHandler(event partybus.Event) error {
	// show the report to stdout
	pres, err := syftEventParsers.ParseCatalogerFinished(event)
	if err != nil {
		return fmt.Errorf("bad CatalogerFinished event: %w", err)
	}

	if err := pres.Present(os.Stdout); err != nil {
		return fmt.Errorf("unable to show package catalog report: %w", err)
	}
	return nil
}
