package common

import (
	"context"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/anchore/syft/internal"
	"github.com/gookit/color"
	"github.com/wagoodman/jotframe/pkg/frame"

	syftEventParsers "github.com/anchore/syft/syft/event/parsers"
	"github.com/wagoodman/go-partybus"
)

// CatalogerPresenterReady is a UI function for processing the CatalogerFinished bus event, displaying the catalog
// via the given presenter to stdout.
func CatalogerPresenterReady(event partybus.Event) error {
	// show the report to stdout
	pres, err := syftEventParsers.ParsePresenterReady(event)
	if err != nil {
		return fmt.Errorf("bad CatalogerFinished event: %w", err)
	}

	if err := pres.Present(os.Stdout); err != nil {
		return fmt.Errorf("unable to show package catalog report: %w", err)
	}
	return nil
}

// appUpdateAvailableHandler is a UI handler function to display a new application version to the top of the screen.
func AppUpdateAvailableHandler(_ context.Context, fr *frame.Frame, event partybus.Event, _ *sync.WaitGroup) error {
	newVersion, err := syftEventParsers.ParseAppUpdateAvailable(event)
	if err != nil {
		return fmt.Errorf("bad AppUpdateAvailable event: %w", err)
	}

	line, err := fr.Prepend()
	if err != nil {
		return err
	}

	message := color.Magenta.Sprintf("New version of %s is available: %s", internal.ApplicationName, newVersion)
	_, _ = io.WriteString(line, message)

	return nil
}
