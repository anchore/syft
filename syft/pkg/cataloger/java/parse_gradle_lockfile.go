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

const gradleLockfileGlob = "**/gradle.lockfile*"

// lockfileDependency represents a single dependency in the gradle.lockfile file
type lockfileDependency struct {
	Group   string
	Name    string
	Version string
}

func parseGradleLockfile(_ context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	var pkgs []pkg.Package

	// create a new scanner to read the file
	scanner := bufio.NewScanner(reader)

	// create slices to hold the dependencies and plugins
	dependencies := []lockfileDependency{}

	// loop over all lines in the file
	for scanner.Scan() {
		line := scanner.Text()

		// trim leading and trailing whitespace from the line
		line = strings.TrimSpace(line)

		groupNameVersion := line
		groupNameVersion = strings.Split(groupNameVersion, "=")[0]
		parts := strings.Split(groupNameVersion, ":")

		// we have a version directly specified
		if len(parts) == 3 {
			// create a new Dependency struct and add it to the dependencies slice
			dep := lockfileDependency{Group: parts[0], Name: parts[1], Version: parts[2]}
			dependencies = append(dependencies, dep)
		}
	}

	// map the dependencies
	for _, dep := range dependencies {
		archive := pkg.JavaArchive{
			PomProject: &pkg.JavaPomProject{
				GroupID:    dep.Group,
				ArtifactID: dep.Name,
				Version:    dep.Version,
				Name:       dep.Name,
			},
		}

		mappedPkg := pkg.Package{
			Name:    dep.Name,
			Version: dep.Version,
			Locations: file.NewLocationSet(
				reader.Location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
			),
			Language: pkg.Java,
			Type:     pkg.JavaPkg,
			PURL:     packageURL(dep.Name, dep.Version, archive),
			// though we do have dependencies listed, we do not have them related to one another, thus we must answer incomplete
			Dependencies: pkg.IncompleteDependencies,
			Metadata:     archive,
		}
		mappedPkg.SetID()
		pkgs = append(pkgs, mappedPkg)
	}

	return pkgs, nil, nil
}
