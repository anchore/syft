package commands

import (
	"fmt"
	"strings"

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
		RunE: func(cmd *cobra.Command, args []string) error {
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

		t.AppendRow(table.Row{
			k.OrgName,
			k.Version,
			displayPlatform(k.Platform),
			k.Filename,
			isConfigured,
			bin,
			snippet,
		})
	}

	return t.Render()
}

func displayPlatform(platform string) string {
	return strings.ReplaceAll(platform, "-", "/")
}
