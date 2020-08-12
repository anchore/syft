/*
Package etui provides an "ephemeral" terminal user interface to display the application state dynamically.
The terminal is placed into raw mode and the cursor is manipulated to allow for a dynamic, multi-line
UI (provided by the jotframe lib), for this reason all other application mechanisms that write to the screen
must be suppressed before starting (such as logs); since bytes in the device and in application memory combine to make
a shared state, bytes coming from elsewhere to the screen will disrupt this state.

This UI is primarily driven off of events from the event bus, creating single-line terminal widgets to represent a
published element on the event bus, typically polling the element for the latest state. This allows for the UI to
control update frequency to the screen, provide "liveness" indications that are interpolated between bus events,
and overall loosely couple the bus events from screen interactions.

By convention, all elements published on the bus should be treated as read-only, and publishers on the bus should
attempt to enforce this when possible by wrapping complex objects with interfaces to prescribe interactions. Also by
convention, each new event that the UI should respond to should be added either in this package as a handler function,
or in the shared ui package as a function on the main handler object. All handler functions should be completed
processing an event before the ETUI exits (coordinated with a sync.WaitGroup)
*/
package etui

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"sync"

	"github.com/anchore/syft/internal/logger"

	"github.com/anchore/syft/internal/ui/common"
	"github.com/anchore/syft/ui"

	"github.com/anchore/syft/internal/log"
	syftEvent "github.com/anchore/syft/syft/event"
	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/jotframe/pkg/frame"
)

// TODO: specify per-platform implementations with build tags (needed when windows is supported by syft)

// setupScreen creates a new jotframe object to manage specific screen lines dynamically, preparing the screen device
// as needed (i.e. setting the terminal to raw mode).
func setupScreen(output *os.File) *frame.Frame {
	config := frame.Config{
		PositionPolicy: frame.PolicyFloatForward,
		// only report output to stderr, reserve report output for stdout
		Output: output,
	}

	fr, err := frame.New(config)
	if err != nil {
		log.Errorf("failed to create screen object: %+v", err)
		return nil
	}
	return fr
}

// nolint:funlen,gocognit
// OutputToEphemeralTUI is a UI function that provides a terminal UI experience without a separate, in-application
// screen buffer. All logging is suppressed, buffered to a string, and output after the ETUI has been torn down.
func OutputToEphemeralTUI(workerErrs <-chan error, subscription *partybus.Subscription) error {
	output := os.Stderr

	// prep the logger to not clobber the screen from now on (logrus only)
	logBuffer := bytes.NewBufferString("")
	logWrapper, ok := log.Log.(*logger.LogrusLogger)
	if ok {
		logWrapper.Logger.SetOutput(logBuffer)
	}

	// hide cursor
	_, _ = fmt.Fprint(output, "\x1b[?25l")
	// show cursor
	defer fmt.Fprint(output, "\x1b[?25h")

	fr := setupScreen(output)
	if fr == nil {
		return fmt.Errorf("unable to setup screen")
	}
	var isClosed bool
	defer func() {
		if !isClosed {
			fr.Close()
			frame.Close()
			// flush any errors to the screen before the report
			logWrapper, ok := log.Log.(*logger.LogrusLogger)
			if ok {
				fmt.Fprint(logWrapper.Output, logBuffer.String())
			} else {
				fmt.Fprint(output, logBuffer.String())
			}
		}
		logWrapper, ok := log.Log.(*logger.LogrusLogger)
		if ok {
			logWrapper.Logger.SetOutput(output)
		}
	}()

	var err error
	var wg = &sync.WaitGroup{}
	events := subscription.Events()
	ctx := context.Background()
	syftUIHandler := ui.NewHandler()

eventLoop:
	for {
		select {
		case err := <-workerErrs:
			// TODO: we should show errors more explicitly in the ETUI
			if err != nil {
				return err
			}
		case e, ok := <-events:
			if !ok {
				break eventLoop
			}
			switch {
			case syftUIHandler.RespondsTo(e):
				if err = syftUIHandler.Handle(ctx, fr, e, wg); err != nil {
					log.Errorf("unable to show %s event: %+v", e.Type, err)
				}

			case e.Type == syftEvent.AppUpdateAvailable:
				if err = appUpdateAvailableHandler(ctx, fr, e, wg); err != nil {
					log.Errorf("unable to show %s event: %+v", e.Type, err)
				}

			case e.Type == syftEvent.CatalogerFinished:
				// we may have other background processes still displaying progress, wait for them to
				// finish before discontinuing dynamic content and showing the final report
				wg.Wait()
				fr.Close()
				// TODO: there is a race condition within frame.Close() that sometimes leads to an extra blank line being output
				frame.Close()
				isClosed = true

				// flush any errors to the screen before the report
				logWrapper, ok := log.Log.(*logger.LogrusLogger)
				if ok {
					fmt.Fprint(logWrapper.Output, logBuffer.String())
				} else {
					fmt.Fprint(output, logBuffer.String())
				}

				if err := common.CatalogerFinishedHandler(e); err != nil {
					log.Errorf("unable to show %s event: %+v", e.Type, err)
				}

				// this is the last expected event
				break eventLoop
			}
		case <-ctx.Done():
			if ctx.Err() != nil {
				log.Errorf("cancelled (%+v)", err)
			}
			break eventLoop
		}
	}

	return nil
}
