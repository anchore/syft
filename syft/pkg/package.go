/*
Package pkg provides the data structures for a package, a package catalog, package types, and domain-specific metadata.
*/
package pkg

import (
	"fmt"
	"sort"

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
	FoundBy      string             `hash:"ignore" cyclonedx:"foundBy"` // the specific cataloger that discovered this package
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

// IsValid checks whether a package has the minimum necessary info
// which is a non-empty name.
// The nil-check was added as a helper as often, in this code base, packages
// move between callers as pointers.
// CycloneDX and SPDX define Name as the minimum required info for a valid package:
// * https://spdx.github.io/spdx-spec/package-information/#73-package-version-field
// * https://cyclonedx.org/docs/1.4/json/#components_items_name
func IsValid(p *Package) bool {
	return p != nil && p.Name != ""
}

func Sort(pkgs []Package) {
	sort.SliceStable(pkgs, func(i, j int) bool {
		if pkgs[i].Name == pkgs[j].Name {
			if pkgs[i].Version == pkgs[j].Version {
				iLocations := pkgs[i].Locations.ToSlice()
				jLocations := pkgs[j].Locations.ToSlice()
				if pkgs[i].Type == pkgs[j].Type && len(iLocations) > 0 && len(jLocations) > 0 {
					if iLocations[0].String() == jLocations[0].String() {
						// compare IDs as a final fallback
						return pkgs[i].ID() < pkgs[j].ID()
					}
					return iLocations[0].String() < jLocations[0].String()
				}
				return pkgs[i].Type < pkgs[j].Type
			}
			return pkgs[i].Version < pkgs[j].Version
		}
		return pkgs[i].Name < pkgs[j].Name
	})
}
