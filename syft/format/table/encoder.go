package table

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/olekukonko/tablewriter"

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

	table := tablewriter.NewWriter(writer)

	table.SetHeader(columns)
	table.SetHeaderLine(false)
	table.SetBorder(false)
	table.SetAutoWrapText(false)
	table.SetAutoFormatHeaders(true)
	table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetCenterSeparator("")
	table.SetColumnSeparator("")
	table.SetRowSeparator("")
	table.SetTablePadding("  ")
	table.SetNoWhiteSpace(true)

	table.AppendBulk(rows)
	table.Render()

	return nil
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
