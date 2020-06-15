package bundler

import (
	"bufio"
	"io"
	"strings"

	"github.com/anchore/imgbom/imgbom/pkg"
	"github.com/anchore/imgbom/internal"
)

var sectionsOfInterest = internal.NewStringSetFromSlice([]string{"GEM"})

func parseGemfileLockEntries(reader io.Reader) ([]pkg.Package, error) {
	pkgs := make([]pkg.Package, 0)
	scanner := bufio.NewScanner(reader)

	var currentSection string

	for scanner.Scan() {
		line := scanner.Text()
		sanitizedLine := strings.TrimSpace(line)

		if len(line) > 1 && line[0] != ' ' {
			// start of section
			currentSection = sanitizedLine
			continue
		} else if !sectionsOfInterest.Contains(currentSection) {
			// skip this line, we're in the wrong section
			continue
		}

		if isDependencyLine(line) {
			candidate := strings.Fields(sanitizedLine)
			if len(candidate) != 2 {
				continue
			}
			pkgs = append(pkgs, pkg.Package{
				Name:     candidate[0],
				Version:  strings.Trim(candidate[1], "()"),
				Language: pkg.Ruby,
				Type:     pkg.BundlerPkg,
			})
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return pkgs, nil
}

func isDependencyLine(line string) bool {
	if len(line) < 5 {
		return false
	}
	return strings.Count(line[:5], " ") == 4
}
