package java

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

var (
	gradleConsistentVersionsLockfileHeader = map[string]struct{}{
		"# Run ./gradlew --write-locks to regenerate this file":                                                    {},
		"# Run ./gradlew writeVersionsLock to regenerate this file":                                                {},
		"# Run ./gradlew writeVersionsLocks to regenerate this file":                                               {},
		"# Run ./gradlew writeVersionsLocks to regenerate this file. Blank lines are to minimize merge conflicts.": {},
	}
	gradleConsistentVersionsLockfileEntry = regexp.MustCompile(`^([^:\s]+):([^:\s]+):([^:\s(]+)\s+\(\d+ constraints: \w+\)$`)
)

// parseGradleConsistentVersionsLockfile parses Palantir gradle-consistent-versions lockfiles (versions.lock),
// see https://github.com/palantir/gradle-consistent-versions. Production dependencies are listed first, followed by
// an optional "[Test dependencies]" section, each resolved dependency on its own line as:
//
//	<group>:<artifact>:<version> (<N> constraints: <hash>)
//
// The constraint/hash suffix is ignored; only group:artifact:version is needed. Test dependencies are reported
// with a "test" scope, matching how pom.xml test dependencies are reported.
func parseGradleConsistentVersionsLockfile(_ context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	var pkgs []pkg.Package

	scanner := internal.NewLineScanner(reader)

	identified := false
	inTestSection := false
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			if _, ok := gradleConsistentVersionsLockfileHeader[line]; ok {
				identified = true
			}
			continue
		}
		if !identified {
			continue
		}

		if line == "[Test dependencies]" {
			inTestSection = true
			continue
		}
		if strings.HasPrefix(line, "[") {
			continue
		}

		parts := gradleConsistentVersionsLockfileEntry.FindStringSubmatch(line)
		if len(parts) != 4 {
			continue
		}

		group, name, version := parts[1], parts[2], parts[3]

		pkgs = append(pkgs, newGradleConsistentVersionsPackage(reader, group, name, version, inTestSection))
	}

	if err := scanner.Err(); err != nil {
		return pkgs, nil, fmt.Errorf("unable to read gradle-consistent-versions lockfile: %w", err)
	}
	return pkgs, nil, nil
}

func newGradleConsistentVersionsPackage(reader file.LocationReadCloser, group, name, version string, test bool) pkg.Package {
	archive := pkg.JavaArchive{
		PomProject: &pkg.JavaPomProject{
			GroupID:    group,
			ArtifactID: name,
			Version:    version,
			Name:       name,
		},
	}
	if test {
		archive.PomProperties = &pkg.JavaPomProperties{
			GroupID:    group,
			ArtifactID: name,
			Version:    version,
			Scope:      "test",
		}
	}

	p := pkg.Package{
		Name:    name,
		Version: version,
		Locations: file.NewLocationSet(
			reader.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
		),
		Language: pkg.Java,
		Type:     pkg.JavaPkg,
		PURL:     packageURL(name, version, archive),
		Metadata: archive,
	}
	p.SetID()
	return p
}
