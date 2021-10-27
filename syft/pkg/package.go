/*
Package pkg provides the data structures for a package, a package catalog, package types, and domain-specific metadata.
*/
package pkg

import (
	"fmt"
	"strings"

	"github.com/anchore/syft/syft/source"
	"github.com/google/uuid"
	"github.com/mitchellh/hashstructure"
)

// Package represents an application or library that has been bundled into a distributable format.
// TODO: if we ignore FoundBy for ID generation should we merge the field to show it was found in two places?
type Package struct {
	ID        ID                `hash:"ignore"` // uniquely identifies a package, set by the cataloger
	Name      string            // the package name
	Version   string            // the version of the package
	FoundBy   string            `hash:"ignore"` // the specific cataloger that discovered this package
	Locations []source.Location `hash:"ignore"` // the locations that lead to the discovery of this package (note: this is not necessarily the locations that make up this package)
	// TODO: should we move licenses into metadata?
	Licenses     []string     // licenses discovered with the package metadata
	Language     Language     // the language ecosystem this package belongs to (e.g. JavaScript, Python, etc)
	Type         Type         // the package type (e.g. Npm, Yarn, Python, Rpm, Deb, etc)
	CPEs         []CPE        // all possible Common Platform Enumerators
	PURL         string       // the Package URL (see https://github.com/package-url/purl-spec)
	MetadataType MetadataType // the shape of the additional data in the "metadata" field
	Metadata     interface{}  // additional data found while parsing the package source
}

// Stringer to represent a package.
func (p Package) String() string {
	return fmt.Sprintf("Pkg(type=%s, name=%s, version=%s)", p.Type, p.Name, p.Version)
}

func (p Package) Fingerprint() string {
	f, err := hashstructure.Hash(p, &hashstructure.HashOptions{
		ZeroNil:      true,
		SlicesAsSets: true,
	})
	if err != nil {
		// if there is an error generating the hash
		// we still want a unique identifier
		// TODO: track packages that don't get hashed for report?
		backup := uuid.Must(uuid.NewRandom()).String()

		return strings.ReplaceAll(backup, "-", "")
	}

	return fmt.Sprint(f)
}

func (p *Package) Merge(other Package) {
	// we need to merge all fields which are ignored during fingerprinting.
	// Locations should be merged and sorted to show the different
	// layers where a package might have been found
	locations := source.NewLocationSet(p.Locations...)
	for _, l := range other.Locations {
		locations.Add(l)
	}

	p.Locations = locations.ToSlice()
}
