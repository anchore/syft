package python

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/common"
)

// integrity check
var _ common.ParserFn = parseRequirementsTxt

// parseRequirementsTxt takes a Python requirements.txt file, returning all Python packages that are locked to a
// specific version.
func parseRequirementsTxt(_ string, reader io.Reader) ([]*pkg.Package, []artifact.Relationship, error) {
	packages := make([]*pkg.Package, 0)

	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := scanner.Text()
		line = trimRequirementsTxtLine(line)

		switch {
		case len(line) == 0:
			// nothing to parse on this line
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
			packages = append(packages, &pkg.Package{
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
		return nil, nil, fmt.Errorf("failed to parse python requirements file: %w", err)
	}

	return packages, nil, nil
}

// trimRequirementsTxtLine removes content from the given requirements.txt line
// that should not be considered for parsing.
func trimRequirementsTxtLine(line string) string {
	line = strings.TrimSpace(line)
	line = removeTrailingComment(line)
	line = removeEnvironmentMarkers(line)

	return line
}

// removeTrailingComment takes a requirements.txt line and strips off comment strings.
func removeTrailingComment(line string) string {
	parts := strings.SplitN(line, "#", 2)
	if len(parts) < 2 {
		// there aren't any comments
	}

	return parts[0]
}

// removeEnvironmentMarkers removes any instances of environment markers (delimited by ';') from the line.
// For more information, see https://www.python.org/dev/peps/pep-0508/#environment-markers.
func removeEnvironmentMarkers(line string) string {
	parts := strings.SplitN(line, ";", 2)
	if len(parts) < 2 {
		// there aren't any comments
	}

	return parts[0]
}
