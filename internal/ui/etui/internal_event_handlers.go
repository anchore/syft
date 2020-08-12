package etui

import (
	"context"
	"fmt"
	"io"
	"sync"

	"github.com/anchore/syft/internal"
	syftEventParsers "github.com/anchore/syft/syft/event/parsers"
	"github.com/gookit/color"
	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/jotframe/pkg/frame"
)

// appUpdateAvailableHandler is a UI handler function to display a new application version to the top of the screen.
func appUpdateAvailableHandler(_ context.Context, fr *frame.Frame, event partybus.Event, _ *sync.WaitGroup) error {
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
