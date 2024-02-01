package ui

import (
	"bufio"
	"io"
	"os"
	"sync"

	"github.com/wagoodman/go-partybus"

	"github.com/anchore/clio"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/event"
	syftEventParsers "github.com/anchore/syft/syft/event/parsers"
)

var _ clio.UI = (*NoUI)(nil)

type NoUI struct {
	out            io.Writer
	err            io.Writer
	finalizeEvents []partybus.Event
	subscription   partybus.Unsubscribable
	quiet          bool
	wg             *sync.WaitGroup
}

func None(out io.Writer, quiet bool) *NoUI {
	return &NoUI{
		out:   out,
		err:   os.Stderr,
		quiet: quiet,
		wg:    &sync.WaitGroup{},
	}
}

func (n *NoUI) Setup(subscription partybus.Unsubscribable) error {
	n.subscription = subscription
	return nil
}

func (n *NoUI) Handle(e partybus.Event) error {
	switch e.Type {
	case event.CLIReport, event.CLINotification:
		// keep these for when the UI is terminated to show to the screen (or perform other events)
		n.finalizeEvents = append(n.finalizeEvents, e)

	case event.AttestationStarted:
		n.handleAttestationStarted(e)
	}
	return nil
}

func (n NoUI) Teardown(force bool) error {
	if !force {
		n.wg.Wait()
	}
	return writeEvents(n.out, n.err, n.quiet, n.finalizeEvents...)
}

func (n *NoUI) handleAttestationStarted(e partybus.Event) {
	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		reader, _, _, err := syftEventParsers.ParseAttestationStartedEvent(e)
		if err != nil {
			log.WithFields("error", err).Warn("unable to parse event")
			return
		}

		s := bufio.NewScanner(reader)

		for s.Scan() {
			text := s.Text()
			log.Info("[COSIGN]", text)
		}
	}()
}
