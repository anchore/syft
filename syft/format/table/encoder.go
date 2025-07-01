package table

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/olekukonko/tablewriter"
	"github.com/olekukonko/tablewriter/renderer"
	"github.com/olekukonko/tablewriter/tw"

	"github.com/anchore/syft/syft/sbom"
)

const ID sbom.FormatID = "syft-table"

type encoder struct {
}

func NewFormatEncoder() sbom.FormatEncoder {
	return encoder{}
}

func (e encoder) ID() sbom.FormatID {
	return ID
}

func (e encoder) Aliases() []string {
	return []string{
		"table",
	}
}

func (e encoder) Version() string {
	return sbom.AnyVersion
}

func (e encoder) Encode(writer io.Writer, s sbom.SBOM) error {
	var rows [][]string

	columns := []string{"Name", "Version", "Type"}
	for _, p := range s.Artifacts.Packages.Sorted() {
		row := []string{
			p.Name,
			p.Version,
			string(p.Type),
		}
		rows = append(rows, row)
	}

	if len(rows) == 0 {
		_, err := fmt.Fprintln(writer, "No packages discovered")
		return err
	}

	// sort by name, version, then type
	sort.SliceStable(rows, func(i, j int) bool {
		for col := 0; col < len(columns); col++ {
			if rows[i][col] != rows[j][col] {
				return rows[i][col] < rows[j][col]
			}
		}
		return false
	})

	columns = append(columns, "") // add a column for duplicate annotations
	rows = markDuplicateRows(rows)

	table := newTableWriter(writer, columns)

	if err := table.Bulk(rows); err != nil {
		return fmt.Errorf("failed to add table rows: %w", err)
	}

	return table.Render()
}

func newTableWriter(writer io.Writer, columns []string) *tablewriter.Table {
	// Here’s a simplified diagram of a table with a header, rows, and footer:
	//
	// [Borders.Top]
	// | Header1 | Header2 |  (Line below header: Lines.ShowTop)
	// [Separators.BetweenRows]
	// | Row1    | Row1    |
	// [Separators.BetweenRows]
	// | Row2    | Row2    |
	// [Lines.ShowBottom]
	// | Footer1 | Footer2 |
	// [Borders.Bottom]
	//
	// So for example:
	// ┌──────┬─────┐  <- Borders.Top
	// │ NAME │ AGE │
	// ├──────┼─────┤  <- Lines.ShowTop
	// │ Alice│ 25  │
	// ├──────┼─────┤  <- Separators.BetweenRows
	// │ Bob  │ 30  │
	// ├──────┼─────┤  <- Lines.ShowBottom
	// │ Total│ 2   │
	// └──────┴─────┘  <- Borders.Bottom

	return tablewriter.NewTable(writer,
		tablewriter.WithHeader(columns),
		tablewriter.WithHeaderAutoFormat(tw.On),
		tablewriter.WithHeaderAutoWrap(tw.WrapNone),
		tablewriter.WithHeaderAlignment(tw.AlignLeft),
		tablewriter.WithRowAutoFormat(tw.Off),
		tablewriter.WithRowAutoWrap(tw.WrapNone),
		tablewriter.WithRowAlignment(tw.AlignLeft),
		tablewriter.WithTrimSpace(tw.On),
		tablewriter.WithAutoHide(tw.On),
		tablewriter.WithRenderer(renderer.NewBlueprint()),
		tablewriter.WithBehavior(
			tw.Behavior{
				TrimSpace: tw.On,
				AutoHide:  tw.On,
			},
		),
		tablewriter.WithPadding(
			tw.Padding{
				Left:   "",
				Right:  "  ",
				Top:    "",
				Bottom: "",
			},
		),
		tablewriter.WithRendition(
			tw.Rendition{
				Symbols: tw.NewSymbols(tw.StyleNone),
				Borders: tw.Border{
					Left:   tw.Off,
					Top:    tw.Off,
					Right:  tw.Off,
					Bottom: tw.Off,
				},
				Settings: tw.Settings{
					Separators: tw.Separators{
						ShowHeader:     tw.Off,
						ShowFooter:     tw.Off,
						BetweenRows:    tw.Off,
						BetweenColumns: tw.Off,
					},
					Lines: tw.Lines{
						ShowTop:        tw.Off,
						ShowBottom:     tw.Off,
						ShowHeaderLine: tw.Off,
						ShowFooterLine: tw.Off,
					},
				},
			},
		),
	)
}

func markDuplicateRows(items [][]string) [][]string {
	seen := map[string]int{}
	var result [][]string

	for _, v := range items {
		key := strings.Join(v, "|")
		if _, ok := seen[key]; ok {
			// dup!
			seen[key]++
			continue
		}

		seen[key] = 1
		result = append(result, v)
	}

	style := lipgloss.NewStyle().Foreground(lipgloss.Color("#777777"))
	for i, v := range result {
		key := strings.Join(v, "|")
		// var name string
		var annotation string
		switch seen[key] {
		case 0, 1:
		case 2:
			annotation = "(+1 duplicate)"
		default:
			annotation = fmt.Sprintf("(+%d duplicates)", seen[key]-1)
		}

		annotation = style.Render(annotation)
		result[i] = append(v, annotation)
	}

	return result
}
