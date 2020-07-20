package etui

import (
	"context"
	"fmt"
	"os"
	"sync"

	imgbomEvent "github.com/anchore/imgbom/imgbom/event"
	"github.com/anchore/imgbom/internal/log"
	"github.com/anchore/imgbom/internal/ui/common"
	stereoscopeEvent "github.com/anchore/stereoscope/pkg/event"
	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/jotframe/pkg/frame"
)

// TODO: specify per-platform implementations with build tags

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
func OutputToEphemeralTUI(workerErrs <-chan error, subscription *partybus.Subscription) error {
	output := os.Stderr

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
			frame.Close()
		}
	}()

	var err error
	var wg = &sync.WaitGroup{}
	events := subscription.Events()
	ctx := context.Background()

eventLoop:
	for {
		select {
		case err := <-workerErrs:
			if err != nil {
				return err
			}
		case e, ok := <-events:
			if !ok {
				break eventLoop
			}
			switch e.Type {
			case imgbomEvent.AppUpdateAvailable:
				err = appUpdateAvailableHandler(ctx, fr, e, wg)
				if err != nil {
					log.Errorf("unable to show AppUpdateAvailable event: %+v", err)
				}

			case stereoscopeEvent.ReadImage:
				err = imageReadHandler(ctx, fr, e, wg)
				if err != nil {
					log.Errorf("unable to show ReadImage event: %+v", err)
				}

			case stereoscopeEvent.FetchImage:
				err = imageFetchHandler(ctx, fr, e, wg)
				if err != nil {
					log.Errorf("unable to show FetchImage event: %+v", err)
				}

			case imgbomEvent.CatalogerStarted:
				err = catalogerStartedHandler(ctx, fr, e, wg)
				if err != nil {
					log.Errorf("unable to show CatalogerStarted event: %+v", err)
				}
			case imgbomEvent.CatalogerFinished:
				// we may have other background processes still displaying progress, wait for them to
				// finish before discontinuing dynamic content and showing the final report
				wg.Wait()
				frame.Close()
				isClosed = true
				fmt.Println()

				err := common.CatalogerFinishedHandler(e)
				if err != nil {
					log.Errorf("unable to show CatalogerFinished event: %+v", err)
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
