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
	id           artifact.ID        `hash:"ignore"`
	Name         string             // the package name
	Version      string             // the version of the package
	FoundBy      string             `cyclonedx:"foundBy"` // the specific cataloger that discovered this package
	Locations    source.LocationSet // the locations that lead to the discovery of this package (note: this is not necessarily the locations that make up this package)
	Licenses     []string           // licenses discovered with the package metadata
	Language     Language           `cyclonedx:"language"`     // the language ecosystem this package belongs to (e.g. JavaScript, Python, etc)
	Type         Type               `cyclonedx:"type"`         // the package type (e.g. Npm, Yarn, Python, Rpm, Deb, etc)
	CPEs         []CPE              `hash:"ignore"`            // all possible Common Platform Enumerators (note: this is NOT included in the definition of the ID since all fields on a CPE are derived from other fields)
	PURL         string             `hash:"ignore"`            // the Package URL (see https://github.com/package-url/purl-spec)
	MetadataType MetadataType       `cyclonedx:"metadataType"` // the shape of the additional data in the "metadata" field
	Metadata     interface{}        // additional data found while parsing the package source
}

func (p *Package) OverrideID(id artifact.ID) {
	p.id = id
}

func (p *Package) SetID() {
	id, err := artifact.IDByHash(p)
	if err != nil {
		// TODO: what to do in this case?
		log.Warnf("unable to get fingerprint of package=%s@%s: %+v", p.Name, p.Version, err)
		return
	}
	p.id = id
}

func (p Package) ID() artifact.ID {
	return p.id
}

// Stringer to represent a package.
func (p Package) String() string {
	return fmt.Sprintf("Pkg(name=%q version=%q type=%q id=%q)", p.Name, p.Version, p.Type, p.id)
}

func (p *Package) merge(other Package) error {
	if p.id != other.id {
		return fmt.Errorf("cannot merge packages with different IDs: %q vs %q", p.id, other.id)
	}
	if p.PURL != other.PURL {
		log.Warnf("merging packages have with different pURLs: %q=%q vs %q=%q", p.id, p.PURL, other.id, other.PURL)
	}

	p.Locations.Add(other.Locations.ToSlice()...)

	p.CPEs = mergeCPEs(p.CPEs, other.CPEs)

	if p.PURL == "" {
		p.PURL = other.PURL
	}
	return nil
}
