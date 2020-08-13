/*
Package pkg provides the data structures for a package, a package catalog, package types, and domain-specific metadata.
*/
package pkg

import (
	"fmt"

	"github.com/anchore/stereoscope/pkg/file"
)

type ID int64

// Package represents an application or library that has been bundled into a distributable format.
type Package struct {
	id      ID               // uniquely identifies a package, set by the cataloger
	Name    string           `json:"manifest"` // the package name
	Version string           `json:"version"`  // the version of the package
	FoundBy string           `json:"found-by"` // the specific cataloger that discovered this package
	Source  []file.Reference `json:"sources"`  // the locations that lead to the discovery of this package (note: this is not necessarily the locations that make up this package)
	// TODO: should we move licenses into metadata?
	Licenses []string    `json:"licenses"`           // licenses discovered with the package metadata
	Language Language    `json:"language"`           // the language ecosystem this package belongs to (e.g. JavaScript, Python, etc)
	Type     Type        `json:"type"`               // the package type (e.g. Npm, Yarn, Egg, Wheel, Rpm, Deb, etc)
	Metadata interface{} `json:"metadata,omitempty"` // additional data found while parsing the package source
}

// ID returns the package ID, which is unique relative to a package catalog.
func (p Package) ID() ID {
	return p.id
}

// Stringer to represent a package.
func (p Package) String() string {
	return fmt.Sprintf("Pkg(type=%s, name=%s, version=%s)", p.Type, p.Name, p.Version)
}
