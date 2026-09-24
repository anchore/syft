package java

import (
	"bufio"
	"context"
	"strings"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

// parseGradleConsistentVersionsLockfile parses Palantir gradle-consistent-versions
// lockfiles (versions.lock). Each resolved dependency is listed on its own line as:
//
//	<group>:<artifact>:<version> (<N> constraints: <hash>)
//
// The constraint/hash suffix is ignored; only group:artifact:version is needed.
func parseGradleConsistentVersionsLockfile(_ context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	var pkgs []pkg.Package

	scanner := bufio.NewScanner(reader)

	for scanner.Scan() {
		line := scanner.Text()

		// trim leading and trailing whitespace from the line
		line = strings.TrimSpace(line)

		// skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// drop the constraint summary suffix, e.g. " (1 constraints: 38053b3b)"
		if idx := strings.Index(line, "("); idx >= 0 {
			line = line[:idx]
		}
		line = strings.TrimSpace(line)

		parts := strings.Split(line, ":")
		if len(parts) != 3 {
			continue
		}

		group, name, version := parts[0], parts[1], parts[2]
		if group == "" || name == "" || version == "" {
			continue
		}

		archive := pkg.JavaArchive{
			PomProject: &pkg.JavaPomProject{
				GroupID:    group,
				ArtifactID: name,
				Version:    version,
				Name:       name,
			},
		}

		mappedPkg := pkg.Package{
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
		mappedPkg.SetID()
		pkgs = append(pkgs, mappedPkg)
	}

	return pkgs, nil, nil
}
