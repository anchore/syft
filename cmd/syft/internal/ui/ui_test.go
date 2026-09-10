package ui

import (
	"io"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/stretchr/testify/require"

	"github.com/anchore/bubbly/bubbles/frame"
)

var _ tea.Model = (*staticModel)(nil)

type staticModel string

func (m staticModel) Init() tea.Cmd { return nil }

func (m staticModel) Update(tea.Msg) (tea.Model, tea.Cmd) { return m, nil }

func (m staticModel) View() string { return string(m) }

func Test_UI_viewEndsOnAnEmptyLine(t *testing.T) {
	// bubbletea erases the line the cursor rests on when the program stops, so a view whose last line
	// carries content loses that line as the run finishes. Until a log line happened to be in the
	// footer, that is what dropped the last row of the cataloging tree on any source that logs nothing.
	subject := New(io.Discard, false)
	subject.frame.(*frame.Frame).AppendModel(staticModel("first row\nlast row"))

	require.Equal(t, "first row\nlast row\n", subject.View())
}
