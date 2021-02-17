/*
Package pkg provides the data structures for a package, a package catalog, package types, and domain-specific metadata.
*/
package pkg

import (
	"fmt"

	"github.com/anchore/syft/syft/source"
)

// Package represents an application or library that has been bundled into a distributable format.
type Package struct {
	ID        ID                // uniquely identifies a package, set by the cataloger
	Name      string            // the package name
	Version   string            // the version of the package
	FoundBy   string            // the specific cataloger that discovered this package
	Locations []source.Location // the locations that lead to the discovery of this package (note: this is not necessarily the locations that make up this package)
	// TODO: should we move licenses into metadata?
	Licenses     []string     // licenses discovered with the package metadata
	Language     Language     // the language ecosystem this package belongs to (e.g. JavaScript, Python, etc)
	Type         Type         // the package type (e.g. Npm, Yarn, Python, Rpm, Deb, etc)
	CPEs         []CPE        // all possible Common Platform Enumerators
	PURL         string       // the Package URL (see https://github.com/package-url/purl-spec)
	Relations    Relations    // describes any relationship of this package to other packages (referenced by ID)
	MetadataType MetadataType // the shape of the additional data in the "metadata" field
	Metadata     interface{}  // additional data found while parsing the package source
}

// Stringer to represent a package.
func (p Package) String() string {
	return fmt.Sprintf("Pkg(type=%s, name=%s, version=%s)", p.Type, p.Name, p.Version)
}
