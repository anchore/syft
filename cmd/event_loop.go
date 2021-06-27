package cmd

import (
	"errors"
	"os"

	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/ui"
	"github.com/hashicorp/go-multierror"
	"github.com/wagoodman/go-partybus"
)

// eventLoop listens to worker errors (from execution path), worker events (from a partybus subscription), and
// signal interrupts. Is responsible for handling each event relative to a given UI an to coordinate eventing until
// an eventual graceful exit.
func eventLoop(workerErrs <-chan error, signals <-chan os.Signal, subscription *partybus.Subscription, ux ui.UI) error {
	events := subscription.Events()
	if err := setupUI(subscription.Unsubscribe, ux); err != nil {
		return err
	}

	var retErr error

	for {
		if workerErrs == nil && events == nil {
			break
		}
		select {
		case err, isOpen := <-workerErrs:
			if !isOpen {
				workerErrs = nil
				continue
			}
			if err != nil {
				retErr = err
			}
		case e, isOpen := <-events:
			if !isOpen {
				events = nil
				continue
			}

			if err := ux.Handle(e); err != nil {
				if errors.Is(err, partybus.ErrUnsubscribe) {
					log.Warnf("unable to unsubscribe from the event bus")
					events = nil
				} else {
					retErr = multierror.Append(retErr, err)
					// TODO: should we unsubscribe? should we try to halt execution? or continue?
				}
			}
		case <-signals:
			// ignore further results from any event source and exit ASAP, but ensure that all cache is cleaned up.
			// we ignore further errors since cleaning up the tmp directories will affect running catalogers that are
			// reading/writing from/to their nested temp dirs. This is acceptable since we are bailing without result.
			events = nil
			workerErrs = nil
			syft.Cleanup()
		}
	}

	if err := ux.Teardown(); err != nil {
		retErr = multierror.Append(retErr, err)
	}

	return retErr
}

func setupUI(unsubscribe func() error, ux ui.UI) error {
	if err := ux.Setup(unsubscribe); err != nil {
		ux = ui.NewLoggerUI()
		if err := ux.Setup(unsubscribe); err != nil {
			// something is very wrong, bail.
			return err
		}
		log.Errorf("unable to setup given UI, falling back to logger: %+v", err)
	}
	return nil
}
