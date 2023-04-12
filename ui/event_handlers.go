package ui

import (
	"bufio"
	"container/list"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/dustin/go-humanize"
	"github.com/gookit/color"
	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/go-progress"
	"github.com/wagoodman/go-progress/format"
	"github.com/wagoodman/jotframe/pkg/frame"

	stereoEventParsers "github.com/anchore/stereoscope/pkg/event/parsers"
	"github.com/anchore/stereoscope/pkg/image/docker"
	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/ui/components"
	syftEventParsers "github.com/anchore/syft/syft/event/parsers"
)

const maxBarWidth = 50
const statusSet = components.SpinnerDotSet
const completedStatus = "✔"
const failedStatus = "✘"
const titleFormat = color.Bold
const subTitleFormat = color.Normal
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
	subStatusTitleTemplate   = fmt.Sprintf("   └── %%-%ds ", StatusTitleColumn-3)
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

// formatDockerImagePullStatus writes the docker image pull status summarized into a single line for the given state.
func formatDockerImagePullStatus(pullStatus *docker.PullStatus, spinner *components.Spinner, line *frame.Line) {
	var size, current uint64

	title := titleFormat.Sprint("Pulling image")

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
			title := titleFormat.Sprint("Pulled image")
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
	title := titleFormat.Sprint("Loading image")

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
		title = titleFormat.Sprint("Loaded image")
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
	title := titleFormat.Sprint("Parsing image")

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
		title = titleFormat.Sprint("Parsed image")
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
	title := titleFormat.Sprint("Cataloging packages")

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
		title = titleFormat.Sprint("Cataloged packages")
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
	title := titleFormat.Sprint("Cataloging secrets")

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
		title = titleFormat.Sprint("Cataloged secrets")
		auxInfo := auxInfoFormat.Sprintf("[%d secrets]", prog.SecretsDiscovered.Current())
		_, _ = io.WriteString(line, fmt.Sprintf(statusTitleTemplate+"%s", spin, title, auxInfo))
	}()
	return err
}

// FileMetadataCatalogerStartedHandler shows the intermittent secrets searching progress.
//
//nolint:dupl
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
	title := titleFormat.Sprint("Cataloging file metadata")

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
		title = titleFormat.Sprint("Cataloged file metadata")
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
	title := titleFormat.Sprintf("Indexing %s", path)

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
		title = titleFormat.Sprintf("Indexed %s", path)
		_, _ = io.WriteString(line, fmt.Sprintf(statusTitleTemplate, spin, title))
	}()
	return err
}

// FileMetadataCatalogerStartedHandler shows the intermittent secrets searching progress.
//
//nolint:dupl
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
	title := titleFormat.Sprint("Cataloging file digests")

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
		title = titleFormat.Sprint("Cataloged file digests")
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
	title := titleFormat.Sprint("Uploading image")

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
		title = titleFormat.Sprint("Uploaded image")
		auxInfo := auxInfoFormat.Sprintf("[%s]", host)
		_, _ = io.WriteString(line, fmt.Sprintf(statusTitleTemplate+"%s", spin, title, auxInfo))
	}()
	return err
}

// AttestationStartedHandler takes bytes from a event.ShellOutput and publishes them to the frame.
//
//nolint:funlen,gocognit
func AttestationStartedHandler(ctx context.Context, fr *frame.Frame, event partybus.Event, wg *sync.WaitGroup) error {
	reader, prog, taskInfo, err := syftEventParsers.ParseAttestationStartedEvent(event)
	if err != nil {
		return fmt.Errorf("bad %s event: %w", event.Type, err)
	}

	titleLine, err := fr.Append()
	if err != nil {
		return err
	}
	wg.Add(2)

	_, spinner := startProcess()

	title := titleFormat.Sprintf(taskInfo.Title.WhileRunning)

	s := bufio.NewScanner(reader)
	l := list.New()

	formatFn := func() {
		auxInfo := auxInfoFormat.Sprintf("[running %s]", taskInfo.Context)
		spin := color.Magenta.Sprint(spinner.Next())
		_, _ = io.WriteString(titleLine, fmt.Sprintf(statusTitleTemplate+"%s", spin, title, auxInfo))
	}

	formatFn()
	var failed bool
	formatComplete := func(aux string) {
		spin := color.Green.Sprint(completedStatus)
		if failed {
			spin = color.Red.Sprint(failedStatus)
			aux = prog.Error().Error()
		} else {
			title = titleFormat.Sprintf(taskInfo.Title.OnSuccess)
		}

		auxInfo := auxInfoFormat.Sprintf("[%s]", aux)

		_, _ = io.WriteString(titleLine, fmt.Sprintf(statusTitleTemplate+"%s", spin, title, auxInfo))
	}

	endWg := &sync.WaitGroup{}
	endWg.Add(1)

	go func() {
		defer wg.Done()
		defer endWg.Done()

		stream := progress.Stream(ctx, prog, interval)
		for range stream {
			formatFn()
		}
		err := prog.Error()
		if err != nil && !errors.Is(err, io.EOF) {
			failed = true
		}
	}()

	go func() {
		defer wg.Done()

		var tlogEntry string

		// only show the last 5 lines of the shell output
		for s.Scan() {
			line, _ := fr.Append()
			if l.Len() > 5 {
				elem := l.Front()
				line, ok := elem.Value.(*frame.Line)
				if !ok {
					continue
				}
				err = line.Remove()
				if err != nil {
					return
				}
				l.Remove(elem)
			}
			l.PushBack(line)
			text := s.Text()
			if strings.Contains(text, "tlog entry created with index") {
				tlogEntry = text
			} else {
				// no tlog entry create so user used personal PKI
				tlogEntry = "signed attestation using provided key"
			}
			_, err = line.Write([]byte(fmt.Sprintf("     %s %s", auxInfoFormat.Sprintf("░░"), text)))
			if err != nil {
				return
			}
		}

		endWg.Wait()

		if !failed {
			// roll up logs into completed status (only if successful)
			for e := l.Back(); e != nil; e = e.Prev() {
				line, ok := e.Value.(*frame.Line)
				if !ok {
					continue
				}
				err = line.Remove()
				if err != nil {
					return
				}
			}
		}

		formatComplete(tlogEntry)
	}()
	return nil
}

// GenericProgressStartedHandler shows the intermittent progress for generic messages
func GenericProgressStartedHandler(ctx context.Context, fr *frame.Frame, event partybus.Event, wg *sync.WaitGroup) error {
	prog, err := syftEventParsers.ParseGenericProgress(event)
	if err != nil {
		return fmt.Errorf("bad %s event: %w", event.Type, err)
	}

	line, err := fr.Append()
	if err != nil {
		return err
	}
	wg.Add(1)

	stream := progress.Stream(ctx, prog.GetMonitor(), interval)

	_, spinner := startProcess()

	formatLine := func(complete bool, auxInfo string) string {
		title := prog.Title
		if complete && prog.TitleOnCompletion != "" {
			title = prog.TitleOnCompletion
		}
		if prog.SubStatus {
			title = subTitleFormat.Sprintf("%s", title)
			if auxInfo == "" {
				return fmt.Sprintf(subStatusTitleTemplate, title)
			}
			return fmt.Sprintf(subStatusTitleTemplate+"%s", title, auxInfo)
		}

		spin := color.Magenta.Sprint(spinner.Next())
		if complete {
			spin = color.Green.Sprint(completedStatus)
		}
		title = titleFormat.Sprintf("%s", title)
		if auxInfo == "" {
			return fmt.Sprintf(statusTitleTemplate, spin, title)
		}
		return fmt.Sprintf(statusTitleTemplate+"%s", spin, title, auxInfo)
	}

	formatFn := func() {
		if err != nil {
			_, _ = io.WriteString(line, fmt.Sprintf("Error: %+v", err))
		} else {
			auxInfo := auxInfoFormat.Sprintf("[%s]", internal.TruncateMiddleEllipsis(prog.GetValue(), 100))
			_, _ = io.WriteString(line, formatLine(false, auxInfo))
		}
	}

	go func() {
		defer wg.Done()

		formatFn()
		for range stream {
			formatFn()
		}

		if prog.RemoveOnCompletion {
			_ = fr.Remove(line)
		} else {
			_, _ = io.WriteString(line, formatLine(true, ""))
		}
	}()
	return err
}
