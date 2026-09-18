package ruby

import (
	"bufio"
	"context"
	"strings"

	"github.com/scylladb/go-set/strset"

	"github.com/anchore/syft/internal/unknown"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

var _ generic.Parser = parseGemFileLockEntries

var sectionsOfInterest = strset.New("GEM", "GIT", "PATH", "PLUGIN SOURCE")

// parseGemFileLockEntries is a parser function for Gemfile.lock contents, returning all Gems discovered.
//
// Each gem's dependency list (the indented lines beneath its spec) is recorded
// on the package metadata; the dependency.Processor wired into the cataloger
// turns those into dependency-of relationships once all packages are known.
func parseGemFileLockEntries(_ context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	scanner := bufio.NewScanner(reader)

	var currentSection string
	var entries []pkg.RubyGemfileLockEntry
	current := -1 // index into entries of the gem whose dependency lines we're reading

	for scanner.Scan() {
		line := scanner.Text()
		sanitizedLine := strings.TrimSpace(line)

		if len(line) > 1 && line[0] != ' ' {
			// start of section
			currentSection = sanitizedLine
			current = -1
			continue
		} else if !sectionsOfInterest.Has(currentSection) {
			// skip this line, we're in the wrong section
			continue
		}

		switch {
		case isGemSpecLine(line):
			fields := strings.Fields(sanitizedLine)
			if len(fields) != 2 {
				current = -1
				continue
			}
			entries = append(entries, pkg.RubyGemfileLockEntry{
				Name:    fields[0],
				Version: strings.Trim(fields[1], "()"),
			})
			current = len(entries) - 1
		case current >= 0 && isGemDependencyLine(line):
			fields := strings.Fields(sanitizedLine)
			if len(fields) == 0 {
				continue
			}
			entries[current].Dependencies = append(entries[current].Dependencies, fields[0])
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, err
	}

	pkgs := make([]pkg.Package, 0, len(entries))
	for _, entry := range entries {
		pkgs = append(pkgs,
			newGemfileLockPackage(entry, reader.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation)),
		)
	}

	return pkgs, nil, unknown.IfEmptyf(pkgs, "unable to determine packages")
}

// isGemSpecLine reports whether a line is a gem spec entry (4-space indent),
// e.g. "    rake (13.0.6)".
func isGemSpecLine(line string) bool {
	if len(line) < 5 {
		return false
	}
	return strings.Count(line[:5], " ") == 4
}

// isGemDependencyLine reports whether a line is a dependency of the current
// gem spec (6-space indent), e.g. "      actionpack (= 6.1.4)".
func isGemDependencyLine(line string) bool {
	if len(line) < 7 {
		return false
	}
	return strings.Count(line[:7], " ") == 6
}
