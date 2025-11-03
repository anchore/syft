/*
Package pkg provides the data structures for a package, a package catalog, package types, and domain-specific metadata.
*/
package pkg

import (
	"fmt"
	"sort"
	"strings"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/file"
)

// Package represents an application or library that has been bundled into a distributable format.
// TODO: if we ignore FoundBy for ID generation should we merge the field to show it was found in two places?
type Package struct {
	// id is a content-addressable identifier for this package, computed from most attribute values (applied recursively)
	id artifact.ID `hash:"ignore"`

	// Name is the package name
	Name string

	// Version is the package version
	Version string

	// FoundBy is the specific cataloger that discovered this package
	FoundBy string `hash:"ignore" cyclonedx:"foundBy"`

	// Locations are the locations that lead to the discovery of this package (note: not necessarily the locations that make up the package)
	Locations file.LocationSet

	// Licenses are the licenses discovered from the package metadata
	Licenses LicenseSet

	// Language is the language this package was written in (e.g. JavaScript, Python, etc)
	Language Language `hash:"ignore" cyclonedx:"language"`

	// Type is the ecosystem the package belongs to (e.g. Npm, Yarn, Python, Rpm, Deb, etc)
	Type Type `cyclonedx:"type"`

	// CPEs are all possible Common Platform Enumerators (note: NOT included in ID since derived from other fields)
	CPEs []cpe.CPE `hash:"ignore"`

	// PURL is the Package URL (see https://github.com/package-url/purl-spec)
	PURL string `hash:"ignore"`

	// Metadata is additional data found while parsing the package source
	Metadata any
}

func (p *Package) OverrideID(id artifact.ID) {
	p.id = id
}

func (p *Package) SetID() {
	id, err := artifact.IDByHash(p)
	if err != nil {
		// TODO: what to do in this case?
		log.Debugf("unable to get fingerprint of package=%s@%s: %+v", p.Name, p.Version, err)
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
		log.Debugf("merging packages have with different pURLs: %q=%q vs %q=%q", p.id, p.PURL, other.id, other.PURL)
	}

	p.Locations.Add(other.Locations.ToSlice()...)
	p.Licenses.Add(other.Licenses.ToSlice()...)

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
