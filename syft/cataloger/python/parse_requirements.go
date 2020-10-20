package python

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"github.com/anchore/syft/syft/cataloger/common"
	"github.com/anchore/syft/syft/pkg"
)

// integrity check
var _ common.ParserFn = parseRequirementsTxt

// parseRequirementsTxt takes a Python requirements.txt file, returning all Python packages that are locked to a
// specific version.
func parseRequirementsTxt(_ string, reader io.Reader) ([]pkg.Package, error) {
	packages := make([]pkg.Package, 0)

	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := scanner.Text()

		line = strings.TrimRight(line, "\n")

		switch {
		case strings.HasPrefix(line, "#"):
			// commented out line, skip
			continue
		case strings.HasPrefix(line, "-e"):
			// editable packages aren't parsed (yet)
			continue
		case len(strings.Split(line, "==")) < 2:
			// a package without a version, or a range (unpinned) which
			// does not tell us exactly what will be installed
			// XXX only needed if we want to log this, otherwise the next case catches it
			continue
		case len(strings.Split(line, "==")) == 2:
			// remove comments if present
			uncommented := removeTrailingComment(line)
			// parse a new requirement
			parts := strings.Split(uncommented, "==")
			name := strings.TrimSpace(parts[0])
			version := strings.TrimSpace(parts[1])
			packages = append(packages, pkg.Package{
				Name:     name,
				Version:  version,
				Language: pkg.Python,
				Type:     pkg.PythonPkg,
			})
		default:
			continue
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to parse python requirements file: %w", err)
	}

	return packages, nil
}

// removeTrailingComment takes a requirements.txt line and strips off comment strings.
func removeTrailingComment(line string) string {
	parts := strings.Split(line, "#")
	switch len(parts) {
	case 1:
		// there aren't any comments
		return line
	default:
		// any number of "#" means we only want the first part, assuming this
		// isn't prefixed with "#" (up to the caller)
		return parts[0]
	}
}
