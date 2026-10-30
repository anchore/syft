package ruby

import (
	"context"
	"strings"

	"github.com/scylladb/go-set/strset"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/unknown"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/dependency"
)

var _ generic.Parser = parseGemFileLockEntries

var sectionsOfInterest = strset.New("GEM", "GIT", "PATH", "PLUGIN SOURCE")

// parseGemFileLockEntries is a parser function for Gemfile.lock contents, returning all Gems discovered.
//
// Each gem's dependency list (the indented lines beneath its spec) is recorded
// on the package metadata and resolved into dependency-of relationships between
// the gems of this lockfile only, so separate projects in one scan stay apart.
// Gems listed in the DEPENDENCIES section, the ones the Gemfile declares, are
// marked Direct.
func parseGemFileLockEntries(_ context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	scanner := internal.NewLineScanner(reader)

	var currentSection string
	var entries []pkg.RubyGemfileLockEntry
	direct := strset.New()
	current := -1 // index into entries of the gem whose dependency lines we're reading

	for scanner.Scan() {
		line := scanner.Text()
		sanitizedLine := strings.TrimSpace(line)

		switch {
		case len(line) > 1 && line[0] != ' ':
			// start of section
			currentSection = sanitizedLine
			current = -1
			continue
		case currentSection == "DEPENDENCIES":
			if fields := strings.Fields(sanitizedLine); isDirectDependencyLine(line) && len(fields) > 0 {
				direct.Add(strings.TrimSuffix(fields[0], "!"))
			}
			continue
		case !sectionsOfInterest.Has(currentSection):
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
		entry.Direct = direct.Has(entry.Name)
		pkgs = append(pkgs,
			newGemfileLockPackage(entry, reader.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation)),
		)
	}

	return pkgs, dependency.Resolve(gemfileLockDependencySpecifier, pkgs), unknown.IfEmptyf(pkgs, "unable to determine packages")
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

// isDirectDependencyLine reports whether a line names a gem in the DEPENDENCIES
// section (2-space indent), e.g. "  rails (= 4.1.1)" or "  turbolinks!".
func isDirectDependencyLine(line string) bool {
	if len(line) < 3 {
		return false
	}
	return strings.Count(line[:3], " ") == 2
}
