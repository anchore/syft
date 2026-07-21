package ui

import (
	"fmt"
	"os"

	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

var quitTextStyle = lipgloss.NewStyle().Margin(1, 0, 2, 4)

type item string

func (i item) Title() string       { return string(i) }
func (i item) Description() string { return "" }
func (i item) FilterValue() string { return string(i) }

type model struct {
	list     list.Model
	choice   string
	quitting bool
}

func PromptSelectBinary(binaryPaths []string) (string, error) {
	var items []list.Item
	for _, p := range binaryPaths {
		items = append(items, item(p))
	}

	d := list.NewDefaultDelegate()
	d.ShowDescription = false
	d.Styles.NormalTitle = d.Styles.NormalTitle.PaddingLeft(4)
	d.Styles.SelectedTitle = d.Styles.SelectedTitle.PaddingLeft(3)
	d.SetSpacing(0)

	l := list.New(items, d, 80, 80)
	l.Title = "Select a binary to capture a snippet from:"
	l.SetShowStatusBar(false)
	l.SetFilteringEnabled(true)
	l.Styles.Title = lipgloss.NewStyle().Bold(true).MarginLeft(1)
	l.Styles.PaginationStyle = list.DefaultStyles().PaginationStyle.PaddingLeft(4)
	l.Styles.HelpStyle = list.DefaultStyles().HelpStyle.PaddingLeft(4).PaddingBottom(1)

	m := model{list: l}

	p := tea.NewProgram(m, tea.WithAltScreen())

	fm, err := p.Run()
	if err != nil {
		fmt.Println("Error running program:", err)
		os.Exit(1)
	}

	m = fm.(model)

	if m.quitting {
		return "", fmt.Errorf("cancelled")
	}

	if m.choice == "" {
		return "", fmt.Errorf("no binary selected")
	}

	return m.choice, nil
}

func (m model) Init() tea.Cmd {
	return nil
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.list.SetWidth(msg.Width)
		m.list.SetHeight(msg.Height)
		return m, nil

	case tea.KeyMsg:
		switch keypress := msg.String(); keypress {
		case "ctrl+c":
			m.quitting = true
			return m, tea.Quit

		case "enter":
			i, ok := m.list.SelectedItem().(item)
			if ok {
				m.choice = string(i)
			}
			return m, tea.Quit
		}
	}

	var cmd tea.Cmd
	m.list, cmd = m.list.Update(msg)
	return m, cmd
}

func (m model) View() string {
	if m.choice != "" {
		return quitTextStyle.Render(fmt.Sprintf("Selected %q", m.choice))
	}
	if m.quitting {
		return quitTextStyle.Render("Cancelled")
	}
	return "\n" + m.list.View()
}
