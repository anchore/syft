/*
Package pkg provides the data structures for a package, a package catalog, package types, and domain-specific metadata.
*/
package pkg

import (
	"fmt"
	"sort"
	"strings"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/source"
)

// Package represents an application or library that has been bundled into a distributable format.
// TODO: if we ignore FoundBy for ID generation should we merge the field to show it was found in two places?
type Package struct {
	id           artifact.ID             `hash:"ignore"`
	Name         string                  // the package name
	Version      string                  // the version of the package
	FoundBy      string                  `hash:"ignore" cyclonedx:"foundBy"` // the specific cataloger that discovered this package
	Locations    source.LocationSet      // the locations that lead to the discovery of this package (note: this is not necessarily the locations that make up this package)
	Licenses     internal.LogicalStrings // licenses discovered with the package metadata
	Language     Language                `hash:"ignore" cyclonedx:"language"` // the language ecosystem this package belongs to (e.g. JavaScript, Python, etc)
	Type         Type                    `cyclonedx:"type"`                   // the package type (e.g. Npm, Yarn, Python, Rpm, Deb, etc)
	CPEs         []cpe.CPE               `hash:"ignore"`                      // all possible Common Platform Enumerators (note: this is NOT included in the definition of the ID since all fields on a CPE are derived from other fields)
	PURL         string                  `hash:"ignore"`                      // the Package URL (see https://github.com/package-url/purl-spec)
	MetadataType MetadataType            `cyclonedx:"metadataType"`           // the shape of the additional data in the "metadata" field
	Metadata     interface{}             // additional data found while parsing the package source
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

	p.CPEs = cpe.Merge(p.CPEs, other.CPEs)

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

//nolint:gocognit
func Less(i, j Package) bool {
	if i.Name == j.Name {
		if i.Version == j.Version {
			iLocations := i.Locations.ToSlice()
			jLocations := j.Locations.ToSlice()
			if i.Type == j.Type {
				maxLen := len(iLocations)
				if len(jLocations) > maxLen {
					maxLen = len(jLocations)
				}
				for l := 0; l < maxLen; l++ {
					if len(iLocations) < l+1 || len(jLocations) < l+1 {
						if len(iLocations) == len(jLocations) {
							break
						}
						return len(iLocations) < len(jLocations)
					}
					if iLocations[l].RealPath == jLocations[l].RealPath {
						continue
					}
					return iLocations[l].RealPath < jLocations[l].RealPath
				}
				// compare remaining metadata as a final fallback
				// note: we cannot guarantee that IDs (which digests the metadata) are stable enough to sort on
				// when there are potentially missing elements there is too much reduction in the dimensions to
				// lean on ID comparison. The best fallback is to look at the string representation of the metadata.
				return strings.Compare(fmt.Sprintf("%#v", i.Metadata), fmt.Sprintf("%#v", j.Metadata)) < 0
			}
			return i.Type < j.Type
		}
		return i.Version < j.Version
	}
	return i.Name < j.Name
}
func Sort(pkgs []Package) {
	sort.SliceStable(pkgs, func(i, j int) bool {
		return Less(pkgs[i], pkgs[j])
	})
}
