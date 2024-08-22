package helpers

import (
	"strings"

	"github.com/anchore/syft/syft/pkg"
)

const (
	noAssertion     = "NOASSERTION"
	copyrightPrefix = "Copyright"
)

func GetCopyrights(copyrights pkg.CopyrightsSet) string {
	result := noAssertion

	for _, c := range copyrights.ToSlice() {
		var sb strings.Builder

		sb.WriteString(copyrightPrefix)

		// Start Year
		if c.StartYear != "" {
			sb.WriteString(" ")
			sb.WriteString(c.StartYear)
		}

		// End Year
		if c.EndYear != "" {
			sb.WriteString("-")
			sb.WriteString(c.EndYear)
		}

		// Author
		if c.Author != "" {
			sb.WriteString(" ")
			sb.WriteString(c.Author)
		}

		// Assign the formatted string to result
		result = sb.String()
	}

	return result
}
