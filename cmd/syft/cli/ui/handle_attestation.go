package ui

import (
	"bufio"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/uuid"
	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/go-progress"
	"github.com/zyedidia/generic/queue"

	"github.com/anchore/bubbly/bubbles/taskprogress"
	"github.com/anchore/syft/internal/log"
	syftEventParsers "github.com/anchore/syft/syft/event/parsers"
)

var (
	_ tea.Model = (*attestLogFrame)(nil)
)

type attestLogFrame struct {
	reader     *backgroundLineReader
	prog       progress.Progressable
	lines      []string
	completed  bool
	failed     bool
	windowSize tea.WindowSizeMsg

	id       uint32
	sequence int

	updateDuration time.Duration
	borderStype    lipgloss.Style
}

// attestLogFrameTickMsg indicates that the timer has ticked and we should render a frame.
type attestLogFrameTickMsg struct {
	Time     time.Time
	Sequence int
	ID       uint32
}

type backgroundLineReader struct {
	limit int
	lines *queue.Queue[string]
	lock  *sync.RWMutex

	// This is added specifically for tests to assert when the background reader is done.
	// The main UI uses the global ui wait group from the handler to otherwise block
	// Shared concerns among multiple model made it difficult to test using the global wait group
	// so this is added to allow tests to assert when the background reader is done.
	running *sync.WaitGroup
}

func (m *Handler) handleAttestationStarted(e partybus.Event) []tea.Model {
	reader, prog, taskInfo, err := syftEventParsers.ParseAttestationStartedEvent(e)
	if err != nil {
		log.WithFields("error", err).Warn("unable to parse event")
		return nil
	}

	stage := progress.Stage{}

	tsk := m.newTaskProgress(
		taskprogress.Title{
			Default: taskInfo.Title.Default,
			Running: taskInfo.Title.WhileRunning,
			Success: taskInfo.Title.OnSuccess,
		},
		taskprogress.WithStagedProgressable(
			struct {
				progress.Progressable
				progress.Stager
			}{
				Progressable: prog,
				Stager:       &stage,
			},
		),
	)

	tsk.HideStageOnSuccess = false

	if taskInfo.Context != "" {
		tsk.Context = []string{taskInfo.Context}
	}

	borderStyle := tsk.HintStyle

	return []tea.Model{
		tsk,
		newLogFrame(newBackgroundLineReader(m.Running, reader, &stage), prog, borderStyle),
	}
}

func newLogFrame(reader *backgroundLineReader, prog progress.Progressable, borderStyle lipgloss.Style) attestLogFrame {
	return attestLogFrame{
		reader:         reader,
		prog:           prog,
		id:             uuid.Must(uuid.NewUUID()).ID(),
		updateDuration: 250 * time.Millisecond,
		borderStype:    borderStyle,
	}
}

func newBackgroundLineReader(wg *sync.WaitGroup, reader io.Reader, stage *progress.Stage) *backgroundLineReader {
	r := &backgroundLineReader{
		limit:   7,
		lock:    &sync.RWMutex{},
		lines:   queue.New[string](),
		running: &sync.WaitGroup{},
	}

	// tracks the background reader for the global handler wait group
	wg.Add(1)

	// tracks the background reader for the local wait group (used in tests to decouple from the global handler wait group)
	r.running.Add(1)

	go func() {
		r.read(reader, stage)
		wg.Done()
		r.running.Done()
	}()

	return r
}

func (l *backgroundLineReader) read(reader io.Reader, stage *progress.Stage) {
	s := bufio.NewScanner(reader)

	for s.Scan() {
		l.lock.Lock()

		text := s.Text()
		l.lines.Enqueue(text)

		if strings.Contains(text, "tlog entry created with index") {
			fields := strings.SplitN(text, ":", 2)
			present := text
			if len(fields) == 2 {
				present = fmt.Sprintf("transparency log index: %s", fields[1])
			}
			stage.Current = present
		} else if strings.Contains(text, "WARNING: skipping transparency log upload") {
			stage.Current = "transparency log upload skipped"
		}

		// only show the last X lines of the shell output
		for l.lines.Len() > l.limit {
			l.lines.Dequeue()
		}

		l.lock.Unlock()
	}
}

func (l backgroundLineReader) Lines() []string {
	l.lock.RLock()
	defer l.lock.RUnlock()

	var lines []string

	l.lines.Each(func(line string) {
		lines = append(lines, line)
	})

	return lines
}

func (l attestLogFrame) Init() tea.Cmd {
	// this is the periodic update of state information
	return func() tea.Msg {
		return attestLogFrameTickMsg{
			// The time at which the tick occurred.
			Time: time.Now(),

			// The ID of the log frame that this message belongs to. This can be
			// helpful when routing messages, however bear in mind that log frames
			// will ignore messages that don't contain ID by default.
			ID: l.id,

			Sequence: l.sequence,
		}
	}
}

func (l attestLogFrame) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		l.windowSize = msg
		return l, nil

	case attestLogFrameTickMsg:
		l.lines = l.reader.Lines()

		l.completed = progress.IsCompleted(l.prog)
		err := l.prog.Error()
		l.failed = err != nil && !progress.IsErrCompleted(err)

		tickCmd := l.handleTick(msg)

		return l, tickCmd
	}

	return l, nil
}

func (l attestLogFrame) View() string {
	if l.completed && !l.failed {
		return ""
	}

	sb := strings.Builder{}

	for _, line := range l.lines {
		sb.WriteString(fmt.Sprintf("     %s %s\n", l.borderStype.Render("░░"), line))
	}

	return sb.String()
}

func (l attestLogFrame) queueNextTick() tea.Cmd {
	return tea.Tick(l.updateDuration, func(t time.Time) tea.Msg {
		return attestLogFrameTickMsg{
			Time:     t,
			ID:       l.id,
			Sequence: l.sequence,
		}
	})
}

func (l *attestLogFrame) handleTick(msg attestLogFrameTickMsg) tea.Cmd {
	// If an ID is set, and the ID doesn't belong to this log frame, reject the message.
	if msg.ID > 0 && msg.ID != l.id {
		return nil
	}

	// If a sequence is set, and it's not the one we expect, reject the message.
	// This prevents the log frame from receiving too many messages and
	// thus updating too frequently.
	if msg.Sequence > 0 && msg.Sequence != l.sequence {
		return nil
	}

	l.sequence++

	// note: even if the log is completed we should still respond to stage changes and window size events
	return l.queueNextTick()
}
