package ui

import (
	imgbomEvent "github.com/anchore/imgbom/imgbom/event"
	"github.com/anchore/imgbom/internal/log"
	"github.com/anchore/imgbom/internal/ui/common"
	"github.com/wagoodman/go-partybus"
)

func LoggerUI(workerErrs <-chan error, subscription *partybus.Subscription) error {
	events := subscription.Events()
eventLoop:
	for {
		select {
		case err := <-workerErrs:
			if err != nil {
				return err
			}
		case e, ok := <-events:
			if !ok {
				// event bus closed...
				break eventLoop
			}

			// ignore all events except for the final event
			if e.Type == imgbomEvent.CatalogerFinished {
				err := common.CatalogerFinishedHandler(e)
				if err != nil {
					log.Errorf("unable to show catalog image finished event: %+v", err)
				}

				// this is the last expected event
				break eventLoop
			}
		}
	}

	return nil
}
