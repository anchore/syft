package ui

import (
	"fmt"
	"io"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/hashicorp/go-multierror"
	"github.com/wagoodman/go-partybus"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/event"
	"github.com/anchore/syft/syft/event/parsers"
)

func writeEvents(out, err io.Writer, quiet bool, events ...partybus.Event) error {
	handles := []struct {
		event        partybus.EventType
		respectQuiet bool
		writer       io.Writer
		dispatch     func(writer io.Writer, events ...partybus.Event) error
	}{
		{
			event:        event.CLIReport,
			respectQuiet: false,
			writer:       out,
			dispatch:     writeReports,
		},
		{
			event:        event.CLINotification,
			respectQuiet: true,
			writer:       err,
			dispatch:     writeNotifications,
		},
		{
			event:        event.CLIAppUpdateAvailable,
			respectQuiet: true,
			writer:       err,
			dispatch:     writeAppUpdate,
		},
	}

	var errs error
	for _, h := range handles {
		if quiet && h.respectQuiet {
			continue
		}

		for _, e := range events {
			if e.Type != h.event {
				continue
			}

			if err := h.dispatch(h.writer, e); err != nil {
				errs = multierror.Append(errs, err)
			}
		}
	}
	return errs
}

func writeReports(writer io.Writer, events ...partybus.Event) error {
	var reports []string
	for _, e := range events {
		_, report, err := parsers.ParseCLIReport(e)
		if err != nil {
			log.WithFields("error", err).Warn("failed to gather final report")
			continue
		}

		// remove all whitespace padding from the end of the report
		reports = append(reports, strings.TrimRight(report, "\n ")+"\n")
	}

	// prevent the double new-line at the end of the report
	report := strings.Join(reports, "\n")

	if _, err := fmt.Fprint(writer, report); err != nil {
		return fmt.Errorf("failed to write final report to stdout: %w", err)
	}
	return nil
}

func writeNotifications(writer io.Writer, events ...partybus.Event) error {
	// 13 = high intensity magenta (ANSI 16 bit code)
	style := lipgloss.NewStyle().Foreground(lipgloss.Color("13"))

	for _, e := range events {
		_, notification, err := parsers.ParseCLINotification(e)
		if err != nil {
			log.WithFields("error", err).Warn("failed to parse notification")
			continue
		}

		if _, err := fmt.Fprintln(writer, style.Render(notification)); err != nil {
			// don't let this be fatal
			log.WithFields("error", err).Warn("failed to write final notifications")
		}
	}
	return nil
}

func writeAppUpdate(writer io.Writer, events ...partybus.Event) error {
	// 13 = high intensity magenta (ANSI 16 bit code) + italics
	style := lipgloss.NewStyle().Foreground(lipgloss.Color("13")).Italic(true)

	for _, e := range events {
		updateCheck, err := parsers.ParseCLIAppUpdateAvailable(e)
		if err != nil {
			log.WithFields("error", err).Warn("failed to parse app update notification")
			continue
		}

		if updateCheck.Current == updateCheck.New {
			log.Tracef("update check event with identical versions: %s", updateCheck.Current)
			continue
		}

		notice := fmt.Sprintf("A newer version of syft is available for download: %s (installed version is %s)", updateCheck.New, updateCheck.Current)

		if _, err := fmt.Fprintln(writer, style.Render(notice)); err != nil {
			// don't let this be fatal
			log.WithFields("error", err).Warn("failed to write app update notification")
		}
	}
	return nil
}
