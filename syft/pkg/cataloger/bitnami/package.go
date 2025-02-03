package bitnami

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	version "github.com/bitnami/go-version/pkg/version"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

func parseBitnamiPURL(p string) (*pkg.BitnamiEntry, error) {
	purl, err := packageurl.FromString(p)
	if err != nil {
		return nil, err
	}

	v, err := version.Parse(purl.Version)
	if err != nil {
		return nil, err
	}

	entry := pkg.BitnamiEntry{
		Name:     purl.Name,
		Version:  strings.TrimSuffix(v.String(), fmt.Sprintf("-%s", v.Revision().String())),
		Revision: v.Revision().String(),
	}

	for _, q := range purl.Qualifiers {
		switch q.Key {
		case "arch":
			entry.Architecture = q.Value
		case "distro":
			entry.Distro = q.Value
		}
	}

	return &entry, nil
}

// packageFiles goes through the list of relationships and finds the files that
// are owned by the given package
func packageFiles(relationships []artifact.Relationship, p pkg.Package, baseDirectory string) []string {
	var result []string
	for _, r := range relationships {
		if r.Type != artifact.ContainsRelationship {
			continue
		}

		if from, ok := r.From.(pkg.Package); ok {
			if from.PURL == p.PURL {
				if to, ok := r.To.(pkg.Package); ok {
					result = append(result, packageFiles(relationships, to, baseDirectory)...)
				}
				if value, ok := r.To.(file.Location); ok {
					result = append(result, filepath.Join(baseDirectory, value.RealPath))
				}
			}
		}
	}

	return result
}

// mainPkgFiles returns the files owned by the main package in the SPDX file.
func mainPkgFiles(resolver file.Resolver, spdxFilePath string, secondaryPkgsFiles []string) ([]string, error) {
	ownedPathGlob := fmt.Sprintf("%s/**", filepath.Dir(spdxFilePath))
	ownedLocations, err := resolver.FilesByGlob(ownedPathGlob)
	if err != nil {
		return nil, err
	}

	ownedLocationSet := file.NewLocationSet(ownedLocations...)
	ownedFiles := ownedLocationSet.CoordinateSet().Paths()

	// Remove the SPDX file and the files already assigned to other packages
	// from the list of owned files
	files := slices.DeleteFunc(ownedFiles, func(f string) bool {
		return f == spdxFilePath || slices.Contains(secondaryPkgsFiles, f)
	})

	return files, nil
}
