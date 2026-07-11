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
func parseGemFileLockEntries(_ context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	var pkgs []pkg.Package
	scanner := bufio.NewScanner(reader)

	var currentSection string

	for scanner.Scan() {
		line := scanner.Text()
		sanitizedLine := strings.TrimSpace(line)

		if len(line) > 1 && line[0] != ' ' {
			// start of section
			currentSection = sanitizedLine
			continue
		} else if !sectionsOfInterest.Has(currentSection) {
			// skip this line, we're in the wrong section
			continue
		}

		if isDependencyLine(line) {
			candidate := strings.Fields(sanitizedLine)
			if len(candidate) != 2 {
				continue
			}
			pkgs = append(pkgs,
				newGemfileLockPackage(
					candidate[0],
					gemfileLockVersion(candidate[1]),
					reader.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
				),
			)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, err
	}
	return pkgs, nil, unknown.IfEmptyf(pkgs, "unable to determine packages")
}

func isDependencyLine(line string) bool {
	if len(line) < 5 {
		return false
	}
	return strings.Count(line[:5], " ") == 4
}

// gemfileLockVersion extracts the gem version from a Gemfile.lock spec token such
// as "(1.13.0)" or, for a platform-specific gem, "(1.13.0-x86_64-linux)". Bundler
// appends the platform to the version with a "-", and a RubyGems version never
// contains a "-" (pre-release segments use "."), so the platform suffix can be
// split off cleanly. Without this the platform leaks into the version, corrupting
// the PURL and producing a separate entry per platform for the same gem.
func gemfileLockVersion(token string) string {
	version := strings.Trim(token, "()")
	if idx := strings.Index(version, "-"); idx >= 0 {
		version = version[:idx]
	}
	return version
}
