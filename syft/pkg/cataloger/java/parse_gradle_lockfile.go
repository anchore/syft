package java

import (
	"bufio"
	"strings"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
	"github.com/anchore/syft/syft/source"
)

const gradleLockfileGlob = "**/gradle.lockfile*"

// Dependency represents a single dependency in the gradle.lockfile file
type LockfileDependency struct {
	Group   string
	Name    string
	Version string
}

func parserGradleLockfile(_ source.FileResolver, _ *generic.Environment, reader source.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	var pkgs []pkg.Package

	// Create a new scanner to read the file
	scanner := bufio.NewScanner(reader)

	// Create slices to hold the dependencies and plugins
	dependencies := []LockfileDependency{}

	// Loop over all lines in the file
	for scanner.Scan() {
		line := scanner.Text()

		// Trim leading and trailing whitespace from the line
		line = strings.TrimSpace(line)

		groupNameVersion := line
		groupNameVersion = strings.Trim(groupNameVersion, "\"")
		parts := strings.Split(groupNameVersion, ":")

		// we have a version directly specified
		if len(parts) == 3 {
			version := strings.Split(parts[2], "=")
			// Create a new Dependency struct and add it to the dependencies slice
			dep := LockfileDependency{Group: parts[0], Name: parts[1], Version: version[0]}
			dependencies = append(dependencies, dep)
		}
	}
	// map the dependencies
	for _, dep := range dependencies {
		mappedPkg := pkg.Package{
			Name:         dep.Name,
			Version:      dep.Version,
			Locations:    source.NewLocationSet(reader.Location),
			Language:     pkg.Java,
			Type:         pkg.JavaPkg,
			MetadataType: pkg.JavaMetadataType,
		}
		pkgs = append(pkgs, mappedPkg)
	}

	return pkgs, nil, nil
}
