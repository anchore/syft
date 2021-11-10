/*
Package pkg provides the data structures for a package, a package catalog, package types, and domain-specific metadata.
*/
package pkg

import (
	"fmt"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/source"
)

// Package represents an application or library that has been bundled into a distributable format.
// TODO: if we ignore FoundBy for ID generation should we merge the field to show it was found in two places?
type Package struct {
	Name         string            // the package name
	Version      string            // the version of the package
	FoundBy      string            // the specific cataloger that discovered this package
	Locations    []source.Location // the locations that lead to the discovery of this package (note: this is not necessarily the locations that make up this package)
	Licenses     []string          // licenses discovered with the package metadata
	Language     Language          // the language ecosystem this package belongs to (e.g. JavaScript, Python, etc)
	Type         Type              // the package type (e.g. Npm, Yarn, Python, Rpm, Deb, etc)
	CPEs         []CPE             // all possible Common Platform Enumerators
	PURL         string            // the Package URL (see https://github.com/package-url/purl-spec)
	MetadataType MetadataType      // the shape of the additional data in the "metadata" field
	Metadata     interface{}       // additional data found while parsing the package source
}

func (p Package) ID() artifact.ID {
	f, err := artifact.IDFromHash(p)
	if err != nil {
		// TODO: what to do in this case?
		log.Warnf("unable to get fingerprint of package=%s@%s: %+v", p.Name, p.Version, err)
		return ""
	}

	return f
}

// Stringer to represent a package.
func (p Package) String() string {
	return fmt.Sprintf("Pkg(type=%s, name=%s, version=%s)", p.Type, p.Name, p.Version)
}
