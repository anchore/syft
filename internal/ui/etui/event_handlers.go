package etui

import (
	"context"
	"fmt"
	"io"
	"sync"
	"time"

	imgbomEventParsers "github.com/anchore/imgbom/imgbom/event/parsers"
	stereoEventParsers "github.com/anchore/stereoscope/pkg/event/parsers"
	"github.com/gookit/color"
	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/go-progress"
	"github.com/wagoodman/go-progress/format"
	"github.com/wagoodman/jotframe/pkg/frame"
)

const maxBarWidth = 50
const statusSet = SpinnerDotSet // SpinnerCircleOutlineSet
const completedStatus = "✔"     //"●"
const tileFormat = color.Bold
const statusTitleTemplate = " %s %-28s "

var auxInfoFormat = color.HEX("#777777")

func startProcess() (format.Simple, *Spinner) {
	width, _ := frame.GetTerminalSize()
	barWidth := int(0.25 * float64(width))
	if barWidth > maxBarWidth {
		barWidth = maxBarWidth
	}
	formatter := format.NewSimpleWithTheme(barWidth, format.HeavyNoBarTheme, format.ColorCompleted, format.ColorTodo)
	spinner := NewSpinner(statusSet)

	return formatter, &spinner
}

func imageFetchHandler(ctx context.Context, fr *frame.Frame, event partybus.Event, wg *sync.WaitGroup) error {
	_, prog, err := stereoEventParsers.ParseFetchImage(event)
	if err != nil {
		return fmt.Errorf("bad FetchImage event: %w", err)
	}

	line, err := fr.Append()
	if err != nil {
		return err
	}

	wg.Add(1)

	go func() {
		defer wg.Done()
		formatter, spinner := startProcess()
		stream := progress.Stream(ctx, prog, 150*time.Millisecond)
		title := tileFormat.Sprint("Fetching image...")

		for p := range stream {
			progStr, err := formatter.Format(p)
			spin := color.Magenta.Sprint(spinner.Next())
			if err != nil {
				_, _ = io.WriteString(line, fmt.Sprintf("Error: %+v", err))
			} else {
				auxInfo := auxInfoFormat.Sprintf("[%s]", prog.Stage())
				_, _ = io.WriteString(line, fmt.Sprintf(statusTitleTemplate+"%s %s", spin, title, progStr, auxInfo))
			}
		}

		spin := color.Green.Sprint(completedStatus)
		title = tileFormat.Sprint("Fetched image")
		_, _ = io.WriteString(line, fmt.Sprintf(statusTitleTemplate, spin, title))
	}()
	return err
}

func imageReadHandler(ctx context.Context, fr *frame.Frame, event partybus.Event, wg *sync.WaitGroup) error {
	_, prog, err := stereoEventParsers.ParseReadImage(event)
	if err != nil {
		return fmt.Errorf("bad ReadImage event: %w", err)
	}

	line, err := fr.Append()
	if err != nil {
		return err
	}

	wg.Add(1)

	go func() {
		defer wg.Done()
		formatter, spinner := startProcess()
		stream := progress.Stream(ctx, prog, 150*time.Millisecond)
		title := tileFormat.Sprint("Reading image...")

		for p := range stream {
			progStr, err := formatter.Format(p)
			spin := color.Magenta.Sprint(spinner.Next())
			if err != nil {
				_, _ = io.WriteString(line, fmt.Sprintf("Error: %+v", err))
			} else {
				_, _ = io.WriteString(line, fmt.Sprintf(statusTitleTemplate+"%s", spin, title, progStr))
			}
		}

		spin := color.Green.Sprint(completedStatus)
		title = tileFormat.Sprint("Read image")
		_, _ = io.WriteString(line, fmt.Sprintf(statusTitleTemplate, spin, title))
	}()

	return nil
}

func catalogerStartedHandler(ctx context.Context, fr *frame.Frame, event partybus.Event, wg *sync.WaitGroup) error {
	monitor, err := imgbomEventParsers.ParseCatalogerStarted(event)
	if err != nil {
		return fmt.Errorf("bad CatalogerStarted event: %w", err)
	}

	line, err := fr.Append()
	if err != nil {
		return err
	}

	wg.Add(1)

	go func() {
		defer wg.Done()
		_, spinner := startProcess()
		stream := progress.StreamMonitors(ctx, []progress.Monitorable{monitor.FilesProcessed, monitor.PackagesDiscovered}, 50*time.Millisecond)
		title := tileFormat.Sprint("Cataloging image...")

		for p := range stream {
			spin := color.Magenta.Sprint(spinner.Next())
			auxInfo := auxInfoFormat.Sprintf("[packages %d]", p[1])
			_, _ = io.WriteString(line, fmt.Sprintf(statusTitleTemplate+"%s", spin, title, auxInfo))
		}

		spin := color.Green.Sprint(completedStatus)
		title = tileFormat.Sprint("Cataloged image")
		auxInfo := auxInfoFormat.Sprintf("[%d packages]", monitor.PackagesDiscovered.Current())
		_, _ = io.WriteString(line, fmt.Sprintf(statusTitleTemplate+"%s", spin, title, auxInfo))
	}()

	return nil
}

func appUpdateAvailableHandler(_ context.Context, fr *frame.Frame, event partybus.Event, _ *sync.WaitGroup) error {
	newVersion, err := imgbomEventParsers.ParseAppUpdateAvailable(event)
	if err != nil {
		return fmt.Errorf("bad AppUpdateAvailable event: %w", err)
	}

	line, err := fr.Prepend()
	if err != nil {
		return err
	}

	message := color.Magenta.Sprintf("New Update Available: %s", newVersion)
	_, _ = io.WriteString(line, message)

	return nil
}
