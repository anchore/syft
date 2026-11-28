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

func Less(i, j Package) bool {
	if sameNameVersionType(&i, &j) {
		var ki, kj sortKey
		return lessTied(&i, &j, &ki, &kj)
	}
	return lessByNameVersionType(&i, &j)
}

func sameNameVersionType(i, j *Package) bool {
	return i.Name == j.Name && i.Version == j.Version && i.Type == j.Type
}

func lessByNameVersionType(i, j *Package) bool {
	if i.Name != j.Name {
		return i.Name < j.Name
	}
	if i.Version != j.Version {
		return i.Version < j.Version
	}
	return i.Type < j.Type
}

// lessTied orders same name/version/type pkgs by locations, metadata
func lessTied(i, j *Package, ki, kj *sortKey) bool {
	iLocations, jLocations := ki.locationsOf(i), kj.locationsOf(j)
	for l := range min(len(iLocations), len(jLocations)) {
		iPath, jPath := iLocations[l].FullNestedPath(), jLocations[l].FullNestedPath()
		if iPath != jPath {
			return iPath < jPath
		}
	}
	if len(iLocations) != len(jLocations) {
		return len(iLocations) < len(jLocations)
	}
	// metadata string fallback; IDs not stable enough
	return strings.Compare(ki.metadataOf(i), kj.metadataOf(j)) < 0
}

// sortKey caches costly-to-compare pkg fields
type sortKey struct {
	locations    []file.Location
	metadata     string
	hasLocations bool
	hasMetadata  bool
}

func (k *sortKey) locationsOf(p *Package) []file.Location {
	if !k.hasLocations {
		k.locations = p.Locations.ToSlice()
		k.hasLocations = true
	}
	return k.locations
}

func (k *sortKey) metadataOf(p *Package) string {
	if !k.hasMetadata {
		k.metadata = fmt.Sprintf("%#v", p.Metadata)
		k.hasMetadata = true
	}
	return k.metadata
}

// Sort is stable Less; keys computed once, lazily
func Sort(pkgs []Package) {
	if len(pkgs) < 2 {
		return
	}
	s := packageSorter{pkgs: pkgs, order: make([]int, len(pkgs))}
	for i := range pkgs {
		s.order[i] = i
	}
	sort.Stable(&s)
	permute(pkgs, s.order)
}

// permute applies order to pkgs in place, consumes order
func permute(pkgs []Package, order []int) {
	for start := range order {
		if order[start] == start {
			continue
		}
		first := pkgs[start]
		dst := start
		for {
			src := order[dst]
			order[dst] = dst
			if src == start {
				pkgs[dst] = first
				break
			}
			pkgs[dst] = pkgs[src]
			dst = src
		}
	}
}

type packageSorter struct {
	pkgs  []Package
	keys  []sortKey
	order []int
}

func (s *packageSorter) Len() int { return len(s.order) }

func (s *packageSorter) Swap(i, j int) { s.order[i], s.order[j] = s.order[j], s.order[i] }

func (s *packageSorter) Less(i, j int) bool {
	a, b := s.order[i], s.order[j]
	pa, pb := &s.pkgs[a], &s.pkgs[b]
	if !sameNameVersionType(pa, pb) {
		return lessByNameVersionType(pa, pb)
	}
	if s.keys == nil {
		s.keys = make([]sortKey, len(s.pkgs))
	}
	return lessTied(pa, pb, &s.keys[a], &s.keys[b])
}
