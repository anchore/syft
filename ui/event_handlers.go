package ui

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	stereoEventParsers "github.com/anchore/stereoscope/pkg/event/parsers"
	"github.com/anchore/stereoscope/pkg/image/docker"
	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/ui/components"
	syftEventParsers "github.com/anchore/syft/syft/event/parsers"
	"github.com/dustin/go-humanize"
	"github.com/gookit/color"
	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/go-progress"
	"github.com/wagoodman/go-progress/format"
	"github.com/wagoodman/jotframe/pkg/frame"
)

const maxBarWidth = 50
const statusSet = components.SpinnerDotSet
const completedStatus = "✔"
const tileFormat = color.Bold
const interval = 150 * time.Millisecond

// StatusTitleColumn is the column index in a given row where status text will be displayed.
const StatusTitleColumn = 31

var (
	auxInfoFormat            = color.HEX("#777777")
	dockerPullCompletedColor = color.HEX("#fcba03")
	dockerPullDownloadColor  = color.HEX("#777777")
	dockerPullExtractColor   = color.White
	dockerPullStageChars     = strings.Split("▁▃▄▅▆▇█", "")
	statusTitleTemplate      = fmt.Sprintf(" %%s %%-%ds ", StatusTitleColumn)
)

// startProcess is a helper function for providing common elements for long-running UI elements (such as a
// progress bar formatter and status spinner)
func startProcess() (format.Simple, *components.Spinner) {
	width, _ := frame.GetTerminalSize()
	barWidth := int(0.25 * float64(width))
	if barWidth > maxBarWidth {
		barWidth = maxBarWidth
	}
	formatter := format.NewSimpleWithTheme(barWidth, format.HeavyNoBarTheme, format.ColorCompleted, format.ColorTodo)
	spinner := components.NewSpinner(statusSet)

	return formatter, &spinner
}

// formatDockerPullPhase returns a single character that represents the status of a layer pull.
func formatDockerPullPhase(phase docker.PullPhase, inputStr string) string {
	switch phase {
	case docker.WaitingPhase:
		// ignore any progress related to waiting
		return " "
	case docker.PullingFsPhase, docker.DownloadingPhase:
		return dockerPullDownloadColor.Sprint(inputStr)
	case docker.DownloadCompletePhase:
		return dockerPullDownloadColor.Sprint(dockerPullStageChars[len(dockerPullStageChars)-1])
	case docker.ExtractingPhase:
		return dockerPullExtractColor.Sprint(inputStr)
	case docker.VerifyingChecksumPhase, docker.PullCompletePhase:
		return dockerPullCompletedColor.Sprint(inputStr)
	case docker.AlreadyExistsPhase:
		return dockerPullCompletedColor.Sprint(dockerPullStageChars[len(dockerPullStageChars)-1])
	default:
		return inputStr
	}
}

// nolint:funlen
// formatDockerImagePullStatus writes the docker image pull status summarized into a single line for the given state.
func formatDockerImagePullStatus(pullStatus *docker.PullStatus, spinner *components.Spinner, line *frame.Line) {
	var size, current uint64

	title := tileFormat.Sprint("Pulling image")

	layers := pullStatus.Layers()
	status := make(map[docker.LayerID]docker.LayerState)
	completed := make([]string, len(layers))

	// fetch the current state
	for idx, layer := range layers {
		completed[idx] = " "
		status[layer] = pullStatus.Current(layer)
	}

	numCompleted := 0
	for idx, layer := range layers {
		prog := status[layer].PhaseProgress
		current := prog.Current()
		size := prog.Size()

		if progress.IsCompleted(prog) {
			input := dockerPullStageChars[len(dockerPullStageChars)-1]
			completed[idx] = formatDockerPullPhase(status[layer].Phase, input)
		} else if current != 0 {
			var ratio float64
			switch {
			case current == 0 || size < 0:
				ratio = 0
			case current >= size:
				ratio = 1
			default:
				ratio = float64(current) / float64(size)
			}

			i := int(ratio * float64(len(dockerPullStageChars)-1))
			input := dockerPullStageChars[i]
			completed[idx] = formatDockerPullPhase(status[layer].Phase, input)
		}

		if progress.IsErrCompleted(status[layer].DownloadProgress.Error()) {
			numCompleted++
		}
	}

	for _, layer := range layers {
		prog := status[layer].DownloadProgress
		size += uint64(prog.Size())
		current += uint64(prog.Current())
	}

	var progStr, auxInfo string
	if len(layers) > 0 {
		render := strings.Join(completed, "")
		prefix := dockerPullCompletedColor.Sprintf("%d Layers", len(layers))
		auxInfo = auxInfoFormat.Sprintf("[%s / %s]", humanize.Bytes(current), humanize.Bytes(size))
		if len(layers) == numCompleted {
			auxInfo = auxInfoFormat.Sprintf("[%s] Extracting...", humanize.Bytes(size))
		}

		progStr = fmt.Sprintf("%s▕%s▏", prefix, render)
	}

	spin := color.Magenta.Sprint(spinner.Next())
	_, _ = io.WriteString(line, fmt.Sprintf(statusTitleTemplate+"%s%s", spin, title, progStr, auxInfo))
}

// PullDockerImageHandler periodically writes a formatted line widget representing a docker image pull event.
func PullDockerImageHandler(ctx context.Context, fr *frame.Frame, event partybus.Event, wg *sync.WaitGroup) error {
	_, pullStatus, err := stereoEventParsers.ParsePullDockerImage(event)
	if err != nil {
		return fmt.Errorf("bad %s event: %w", event.Type, err)
	}

	line, err := fr.Append()
	if err != nil {
		return err
	}
	wg.Add(1)

	_, spinner := startProcess()

	go func() {
		defer wg.Done()

	loop:
		for {
			select {
			case <-ctx.Done():
				break loop
			case <-time.After(interval):
				formatDockerImagePullStatus(pullStatus, spinner, line)
				if pullStatus.Complete() {
					break loop
				}
			}
		}

		if pullStatus.Complete() {
			spin := color.Green.Sprint(completedStatus)
			title := tileFormat.Sprint("Pulled image")
			_, _ = io.WriteString(line, fmt.Sprintf(statusTitleTemplate, spin, title))
		}
	}()
	return err
}

// FetchImageHandler periodically writes a the image save and write-to-disk process in the form of a progress bar.
func FetchImageHandler(ctx context.Context, fr *frame.Frame, event partybus.Event, wg *sync.WaitGroup) error {
	_, prog, err := stereoEventParsers.ParseFetchImage(event)
	if err != nil {
		return fmt.Errorf("bad %s event: %w", event.Type, err)
	}

	line, err := fr.Append()
	if err != nil {
		return err
	}
	wg.Add(1)

	formatter, spinner := startProcess()
	stream := progress.Stream(ctx, prog, interval)
	title := tileFormat.Sprint("Loading image")

	formatFn := func(p progress.Progress) {
		progStr, err := formatter.Format(p)
		spin := color.Magenta.Sprint(spinner.Next())
		if err != nil {
			_, _ = io.WriteString(line, fmt.Sprintf("Error: %+v", err))
		} else {
			auxInfo := auxInfoFormat.Sprintf("[%s]", prog.Stage())
			_, _ = io.WriteString(line, fmt.Sprintf(statusTitleTemplate+"%s %s", spin, title, progStr, auxInfo))
		}
	}

	go func() {
		defer wg.Done()

		formatFn(progress.Progress{})
		for p := range stream {
			formatFn(p)
		}

		spin := color.Green.Sprint(completedStatus)
		title = tileFormat.Sprint("Loaded image")
		_, _ = io.WriteString(line, fmt.Sprintf(statusTitleTemplate, spin, title))
	}()
	return err
}

func UploadAttestationHandler(ctx context.Context, fr *frame.Frame, event partybus.Event, wg *sync.WaitGroup) error {
	prog, err := syftEventParsers.ParseUploadAttestation(event)
	if err != nil {
		return fmt.Errorf("bad %s event: %w", event.Type, err)
	}

	line, err := fr.Append()
	if err != nil {
		return err
	}
	wg.Add(1)

	formatter, spinner := startProcess()
	stream := progress.Stream(ctx, prog, interval)
	title := tileFormat.Sprint("Uploading attestation")

	formatFn := func(p progress.Progress) {
		progStr, err := formatter.Format(p)
		spin := color.Magenta.Sprint(spinner.Next())
		if err != nil {
			_, _ = io.WriteString(line, fmt.Sprintf("Error: %+v", err))
		} else {
			auxInfo := auxInfoFormat.Sprintf("[%s]", prog.Stage())
			_, _ = io.WriteString(line, fmt.Sprintf(statusTitleTemplate+"%s %s", spin, title, progStr, auxInfo))
		}
	}

	go func() {
		defer wg.Done()

		formatFn(progress.Progress{})
		for p := range stream {
			formatFn(p)
		}

		spin := color.Green.Sprint(completedStatus)
		title = tileFormat.Sprint("Uploaded attestation")
		_, _ = io.WriteString(line, fmt.Sprintf(statusTitleTemplate, spin, title))
	}()
	return err
}

// ReadImageHandler periodically writes a the image read/parse/build-tree status in the form of a progress bar.
func ReadImageHandler(ctx context.Context, fr *frame.Frame, event partybus.Event, wg *sync.WaitGroup) error {
	_, prog, err := stereoEventParsers.ParseReadImage(event)
	if err != nil {
		return fmt.Errorf("bad %s event: %w", event.Type, err)
	}

	line, err := fr.Append()
	if err != nil {
		return err
	}

	wg.Add(1)

	formatter, spinner := startProcess()
	stream := progress.Stream(ctx, prog, interval)
	title := tileFormat.Sprint("Parsing image")

	formatFn := func(p progress.Progress) {
		progStr, err := formatter.Format(p)
		spin := color.Magenta.Sprint(spinner.Next())
		if err != nil {
			_, _ = io.WriteString(line, fmt.Sprintf("Error: %+v", err))
		} else {
			_, _ = io.WriteString(line, fmt.Sprintf(statusTitleTemplate+"%s", spin, title, progStr))
		}
	}

	go func() {
		defer wg.Done()

		formatFn(progress.Progress{})
		for p := range stream {
			formatFn(p)
		}

		spin := color.Green.Sprint(completedStatus)
		title = tileFormat.Sprint("Parsed image")
		_, _ = io.WriteString(line, fmt.Sprintf(statusTitleTemplate, spin, title))
	}()

	return nil
}

// PackageCatalogerStartedHandler periodically writes catalog statistics to a single line.
func PackageCatalogerStartedHandler(ctx context.Context, fr *frame.Frame, event partybus.Event, wg *sync.WaitGroup) error {
	monitor, err := syftEventParsers.ParsePackageCatalogerStarted(event)
	if err != nil {
		return fmt.Errorf("bad %s event: %w", event.Type, err)
	}

	line, err := fr.Append()
	if err != nil {
		return err
	}

	wg.Add(1)

	_, spinner := startProcess()
	stream := progress.StreamMonitors(ctx, []progress.Monitorable{monitor.FilesProcessed, monitor.PackagesDiscovered}, interval)
	title := tileFormat.Sprint("Cataloging packages")

	formatFn := func(p int64) {
		spin := color.Magenta.Sprint(spinner.Next())
		auxInfo := auxInfoFormat.Sprintf("[packages %d]", p)
		_, _ = io.WriteString(line, fmt.Sprintf(statusTitleTemplate+"%s", spin, title, auxInfo))
	}

	go func() {
		defer wg.Done()

		formatFn(0)
		for p := range stream {
			formatFn(p[1])
		}

		spin := color.Green.Sprint(completedStatus)
		title = tileFormat.Sprint("Cataloged packages")
		auxInfo := auxInfoFormat.Sprintf("[%d packages]", monitor.PackagesDiscovered.Current())
		_, _ = io.WriteString(line, fmt.Sprintf(statusTitleTemplate+"%s", spin, title, auxInfo))
	}()

	return nil
}

// SecretsCatalogerStartedHandler shows the intermittent secrets searching progress.
func SecretsCatalogerStartedHandler(ctx context.Context, fr *frame.Frame, event partybus.Event, wg *sync.WaitGroup) error {
	prog, err := syftEventParsers.ParseSecretsCatalogingStarted(event)
	if err != nil {
		return fmt.Errorf("bad %s event: %w", event.Type, err)
	}

	line, err := fr.Append()
	if err != nil {
		return err
	}
	wg.Add(1)

	formatter, spinner := startProcess()
	stream := progress.Stream(ctx, prog, interval)
	title := tileFormat.Sprint("Cataloging secrets")

	formatFn := func(p progress.Progress) {
		progStr, err := formatter.Format(p)
		spin := color.Magenta.Sprint(spinner.Next())
		if err != nil {
			_, _ = io.WriteString(line, fmt.Sprintf("Error: %+v", err))
		} else {
			auxInfo := auxInfoFormat.Sprintf("[%d secrets]", prog.SecretsDiscovered.Current())
			_, _ = io.WriteString(line, fmt.Sprintf(statusTitleTemplate+"%s %s", spin, title, progStr, auxInfo))
		}
	}

	go func() {
		defer wg.Done()

		formatFn(progress.Progress{})
		for p := range stream {
			formatFn(p)
		}

		spin := color.Green.Sprint(completedStatus)
		title = tileFormat.Sprint("Cataloged secrets")
		auxInfo := auxInfoFormat.Sprintf("[%d secrets]", prog.SecretsDiscovered.Current())
		_, _ = io.WriteString(line, fmt.Sprintf(statusTitleTemplate+"%s", spin, title, auxInfo))
	}()
	return err
}

//nolint:dupl
// FileMetadataCatalogerStartedHandler shows the intermittent secrets searching progress.
func FileMetadataCatalogerStartedHandler(ctx context.Context, fr *frame.Frame, event partybus.Event, wg *sync.WaitGroup) error {
	prog, err := syftEventParsers.ParseFileMetadataCatalogingStarted(event)
	if err != nil {
		return fmt.Errorf("bad %s event: %w", event.Type, err)
	}

	line, err := fr.Append()
	if err != nil {
		return err
	}
	wg.Add(1)

	formatter, spinner := startProcess()
	stream := progress.Stream(ctx, prog, interval)
	title := tileFormat.Sprint("Cataloging file metadata")

	formatFn := func(p progress.Progress) {
		progStr, err := formatter.Format(p)
		spin := color.Magenta.Sprint(spinner.Next())
		if err != nil {
			_, _ = io.WriteString(line, fmt.Sprintf("Error: %+v", err))
		} else {
			_, _ = io.WriteString(line, fmt.Sprintf(statusTitleTemplate+"%s", spin, title, progStr))
		}
	}

	go func() {
		defer wg.Done()

		formatFn(progress.Progress{})
		for p := range stream {
			formatFn(p)
		}

		spin := color.Green.Sprint(completedStatus)
		title = tileFormat.Sprint("Cataloged file metadata")
		_, _ = io.WriteString(line, fmt.Sprintf(statusTitleTemplate, spin, title))
	}()
	return err
}

// FileIndexingStartedHandler shows the intermittent indexing progress from a directory resolver.
func FileIndexingStartedHandler(ctx context.Context, fr *frame.Frame, event partybus.Event, wg *sync.WaitGroup) error {
	path, prog, err := syftEventParsers.ParseFileIndexingStarted(event)
	if err != nil {
		return fmt.Errorf("bad %s event: %w", event.Type, err)
	}

	line, err := fr.Append()
	if err != nil {
		return err
	}
	wg.Add(1)

	_, spinner := startProcess()
	stream := progress.Stream(ctx, prog, interval)
	title := tileFormat.Sprintf("Indexing %s", path)

	formatFn := func(_ progress.Progress) {
		spin := color.Magenta.Sprint(spinner.Next())
		if err != nil {
			_, _ = io.WriteString(line, fmt.Sprintf("Error: %+v", err))
		} else {
			auxInfo := auxInfoFormat.Sprintf("[file: %s]", internal.TruncateMiddleEllipsis(prog.Stage(), 100))
			_, _ = io.WriteString(line, fmt.Sprintf(statusTitleTemplate+"%s", spin, title, auxInfo))
		}
	}

	go func() {
		defer wg.Done()

		formatFn(progress.Progress{})
		for p := range stream {
			formatFn(p)
		}

		spin := color.Green.Sprint(completedStatus)
		title = tileFormat.Sprintf("Indexed %s", path)
		_, _ = io.WriteString(line, fmt.Sprintf(statusTitleTemplate, spin, title))
	}()
	return err
}

// FileMetadataCatalogerStartedHandler shows the intermittent secrets searching progress.
// nolint:dupl
func FileDigestsCatalogerStartedHandler(ctx context.Context, fr *frame.Frame, event partybus.Event, wg *sync.WaitGroup) error {
	prog, err := syftEventParsers.ParseFileDigestsCatalogingStarted(event)
	if err != nil {
		return fmt.Errorf("bad %s event: %w", event.Type, err)
	}

	line, err := fr.Append()
	if err != nil {
		return err
	}
	wg.Add(1)

	formatter, spinner := startProcess()
	stream := progress.Stream(ctx, prog, interval)
	title := tileFormat.Sprint("Cataloging file digests")

	formatFn := func(p progress.Progress) {
		progStr, err := formatter.Format(p)
		spin := color.Magenta.Sprint(spinner.Next())
		if err != nil {
			_, _ = io.WriteString(line, fmt.Sprintf("Error: %+v", err))
		} else {
			_, _ = io.WriteString(line, fmt.Sprintf(statusTitleTemplate+"%s", spin, title, progStr))
		}
	}

	go func() {
		defer wg.Done()

		formatFn(progress.Progress{})
		for p := range stream {
			formatFn(p)
		}

		spin := color.Green.Sprint(completedStatus)
		title = tileFormat.Sprint("Cataloged file digests")
		_, _ = io.WriteString(line, fmt.Sprintf(statusTitleTemplate, spin, title))
	}()
	return err
}

// ImportStartedHandler shows the intermittent upload progress to Anchore Enterprise.
func ImportStartedHandler(ctx context.Context, fr *frame.Frame, event partybus.Event, wg *sync.WaitGroup) error {
	host, prog, err := syftEventParsers.ParseImportStarted(event)
	if err != nil {
		return fmt.Errorf("bad %s event: %w", event.Type, err)
	}

	line, err := fr.Append()
	if err != nil {
		return err
	}
	wg.Add(1)

	formatter, spinner := startProcess()
	stream := progress.Stream(ctx, prog, interval)
	title := tileFormat.Sprint("Uploading image")

	formatFn := func(p progress.Progress) {
		progStr, err := formatter.Format(p)
		spin := color.Magenta.Sprint(spinner.Next())
		if err != nil {
			_, _ = io.WriteString(line, fmt.Sprintf("Error: %+v", err))
		} else {
			auxInfo := auxInfoFormat.Sprintf("[%s]", prog.Stage())
			_, _ = io.WriteString(line, fmt.Sprintf(statusTitleTemplate+"%s %s", spin, title, progStr, auxInfo))
		}
	}

	go func() {
		defer wg.Done()

		formatFn(progress.Progress{})
		for p := range stream {
			formatFn(p)
		}

		spin := color.Green.Sprint(completedStatus)
		title = tileFormat.Sprint("Uploaded image")
		auxInfo := auxInfoFormat.Sprintf("[%s]", host)
		_, _ = io.WriteString(line, fmt.Sprintf(statusTitleTemplate+"%s", spin, title, auxInfo))
	}()
	return err
}
