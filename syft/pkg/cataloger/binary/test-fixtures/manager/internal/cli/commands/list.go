package commands

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/spf13/cobra"

	"github.com/anchore/syft/syft/pkg/cataloger/binary/test-fixtures/manager/internal"
	"github.com/anchore/syft/syft/pkg/cataloger/binary/test-fixtures/manager/internal/config"
)

func List(appConfig config.Application) *cobra.Command {
	var showPaths bool

	cmd := &cobra.Command{
		Use:   "list",
		Short: "list managed binaries and managed/unmanaged snippets",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return runList(appConfig, showPaths)
		},
	}

	cmd.Flags().BoolVarP(&showPaths, "show-paths", "p", false, "show paths to binaries and snippets")

	return cmd
}

func runList(appConfig config.Application, showPaths bool) error {
	material, err := internal.ListAllEntries(appConfig)
	if err != nil {
		return err
	}

	report := renderCatalogerListTable(material, showPaths)

	report += "\n Legend:\n"
	report += errorStyle.Render("   !!  indicates there is no binary or snippet for a configured entry") + "\n"
	report += warningStyle.Render("   !   indicates that the binary is managed but there is no snippet") + "\n"

	fmt.Println(report)

	return nil
}

const yes = "yes"

func renderCatalogerListTable(material map[internal.LogicalEntryKey]internal.EntryInfo, showPaths bool) string {
	t := table.NewWriter()
	t.SetStyle(table.StyleLight)
	t.AppendHeader(table.Row{"Group", "Version", "Platform", "Name", "Configured?", "Binary", "Snippet"})

	keys := internal.NewLogicalEntryKeys(material)

	for _, k := range keys {
		info := material[k]

		isConfigured := ""
		if info.IsConfigured {
			isConfigured = yes
		}

		bin := ""
		snippet := ""
		if showPaths {
			bin = info.BinaryPath
			snippet = info.SnippetPath
		} else {
			if info.BinaryPath != "" {
				bin = yes
			}

			if info.SnippetPath != "" {
				snippet = yes
			}
		}

		var state displayState
		if snippet == "" {
			if bin == "" {
				state = displayStateError
			} else {
				state = displayStateWarning
			}
		}

		t.AppendRow(table.Row{
			renderCell(k.OrgName, state, "!"),
			renderCell(k.Version, state),
			renderCell(displayPlatform(k.Platform), state),
			renderCell(k.Filename, state),
			renderCell(isConfigured, state),
			renderCell(bin, state),
			renderCell(snippet, state),
		})
	}

	return t.Render()
}

type displayState string

const (
	displayStateError   displayState = "error"
	displayStateWarning displayState = "warning"
)

var (
	errorStyle   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("9"))
	warningStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("11"))
	stdStyle     = lipgloss.NewStyle()
)

func renderCell(value string, state displayState, hints ...string) string {
	hint := strings.Join(hints, "")
	var prefix string
	switch state {
	case displayStateError:
		return errorStyle.Render(strings.Repeat(hint, 2) + value)
	case displayStateWarning:
		if hint != "" {
			prefix = " "
		}
		return warningStyle.Render(hint + prefix + value)
	}
	if hint != "" {
		prefix = "  "
	}
	return stdStyle.Render(prefix + value)
}

func displayPlatform(platform string) string {
	return strings.ReplaceAll(platform, "-", "/")
}
