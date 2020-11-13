package table

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/olekukonko/tablewriter"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

type Presenter struct {
	catalog *pkg.Catalog
	source  source.Source
}

func NewPresenter(catalog *pkg.Catalog, s source.Source) *Presenter {
	return &Presenter{
		catalog: catalog,
		source:  s,
	}
}

func (pres *Presenter) Present(output io.Writer) error {
	rows := make([][]string, 0)

	columns := []string{"Name", "Version", "Type"}
	for p := range pres.catalog.Enumerate() {
		row := []string{
			p.Name,
			p.Version,
			string(p.Type),
		}
		rows = append(rows, row)
	}

	if len(rows) == 0 {
		fmt.Fprintln(output, "No packages discovered")
		return nil
	}

	// sort by name, version, then type
	sort.SliceStable(rows, func(i, j int) bool {
		for col := 0; col < len(columns); col++ {
			if rows[i][0] != rows[j][0] {
				return rows[i][col] < rows[j][col]
			}
		}
		return false
	})
	rows = removeDuplicateRows(rows)

	table := tablewriter.NewWriter(output)

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

func removeDuplicateRows(items [][]string) [][]string {
	seen := map[string][]string{}
	// nolint:prealloc
	var result [][]string

	for _, v := range items {
		key := strings.Join(v, "|")
		if seen[key] != nil {
			// dup!
			continue
		}

		seen[key] = v
		result = append(result, v)
	}
	return result
}
