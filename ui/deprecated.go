/*
Package ui provides all public UI elements intended to be repurposed in other applications. Specifically, a single
Handler object is provided to allow consuming applications (such as grype) to check if there are UI elements the handler
can respond to (given a specific event type) and handle the event in context of the given screen frame object.
*/
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

	stereoscopeEvent "github.com/anchore/stereoscope/pkg/event"
	stereoEventParsers "github.com/anchore/stereoscope/pkg/event/parsers"
	"github.com/anchore/stereoscope/pkg/image/docker"
	"github.com/anchore/syft/internal"
	syftEvent "github.com/anchore/syft/syft/event"
	syftEventParsers "github.com/anchore/syft/syft/event/parsers"
)

const maxBarWidth = 50
const statusSet = SpinnerDotSet
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

// Handler is an aggregated event handler for the set of supported events (PullDockerImage, ReadImage, FetchImage, PackageCatalogerStarted)
// Deprecated: use the bubbletea event handler in cmd/syft/ui/handler.go instead.
type Handler struct {
}

// NewHandler returns an empty Handler
// Deprecated: use the bubbletea event handler in cmd/syft/ui/handler.go instead.
func NewHandler() *Handler {
	return &Handler{}
}

// RespondsTo indicates if the handler is capable of handling the given event.
// Deprecated: use the bubbletea event handler in cmd/syft/ui/handler.go instead.
func (r *Handler) RespondsTo(event partybus.Event) bool {
	switch event.Type {
	case stereoscopeEvent.PullDockerImage,
		stereoscopeEvent.ReadImage,
		stereoscopeEvent.FetchImage,
		syftEvent.PackageCatalogerStarted,
		syftEvent.SecretsCatalogerStarted,
		syftEvent.FileDigestsCatalogerStarted,
		syftEvent.FileMetadataCatalogerStarted,
		syftEvent.FileIndexingStarted,
		syftEvent.AttestationStarted,
		syftEvent.CatalogerTaskStarted:
		return true
	default:
		return false
	}
}

// Handle calls the specific event handler for the given event within the context of the screen frame.
// Deprecated: use the bubbletea event handler in cmd/syft/ui/handler.go instead.
func (r *Handler) Handle(ctx context.Context, fr *frame.Frame, event partybus.Event, wg *sync.WaitGroup) error {
	switch event.Type {
	case stereoscopeEvent.PullDockerImage:
		return PullDockerImageHandler(ctx, fr, event, wg)

	case stereoscopeEvent.ReadImage:
		return ReadImageHandler(ctx, fr, event, wg)

	case stereoscopeEvent.FetchImage:
		return FetchImageHandler(ctx, fr, event, wg)

	case syftEvent.PackageCatalogerStarted:
		return PackageCatalogerStartedHandler(ctx, fr, event, wg)

	case syftEvent.SecretsCatalogerStarted:
		return SecretsCatalogerStartedHandler(ctx, fr, event, wg)

	case syftEvent.FileDigestsCatalogerStarted:
		return FileDigestsCatalogerStartedHandler(ctx, fr, event, wg)

	case syftEvent.FileMetadataCatalogerStarted:
		return FileMetadataCatalogerStartedHandler(ctx, fr, event, wg)

	case syftEvent.FileIndexingStarted:
		return FileIndexingStartedHandler(ctx, fr, event, wg)

	case syftEvent.AttestationStarted:
		return AttestationStartedHandler(ctx, fr, event, wg)

	case syftEvent.CatalogerTaskStarted:
		return CatalogerTaskStartedHandler(ctx, fr, event, wg)
	}
	return nil
}

const (
	SpinnerDotSet = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
)

type spinner struct {
	index   int
	charset []string
	lock    sync.Mutex
}

func newSpinner(charset string) spinner {
	return spinner{
		charset: strings.Split(charset, ""),
	}
}

func (s *spinner) Current() string {
	s.lock.Lock()
	defer s.lock.Unlock()

	return s.charset[s.index]
}

func (s *spinner) Next() string {
	s.lock.Lock()
	defer s.lock.Unlock()
	c := s.charset[s.index]
	s.index++
	if s.index >= len(s.charset) {
		s.index = 0
	}
	return c
}

// startProcess is a helper function for providing common elements for long-running UI elements (such as a
// progress bar formatter and status spinner)
func startProcess() (format.Simple, *spinner) {
	width, _ := frame.GetTerminalSize()
	barWidth := int(0.25 * float64(width))
	if barWidth > maxBarWidth {
		barWidth = maxBarWidth
	}
	formatter := format.NewSimpleWithTheme(barWidth, format.HeavyNoBarTheme, format.ColorCompleted, format.ColorTodo)
	spinner := newSpinner(statusSet)

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
func formatDockerImagePullStatus(pullStatus *docker.PullStatus, spinner *spinner, line *frame.Line) {
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

// CatalogerTaskStartedHandler shows the intermittent progress for a cataloger subprocess messages
func CatalogerTaskStartedHandler(ctx context.Context, fr *frame.Frame, event partybus.Event, wg *sync.WaitGroup) error {
	prog, err := syftEventParsers.ParseCatalogerTaskStarted(event)
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
