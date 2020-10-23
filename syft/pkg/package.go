/*
Package pkg provides the data structures for a package, a package catalog, package types, and domain-specific metadata.
*/
package pkg

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/syft/syft/distro"
	"github.com/package-url/packageurl-go"
)

type ID int64

// Package represents an application or library that has been bundled into a distributable format.
type Package struct {
	id      ID               // uniquely identifies a package, set by the cataloger
	Name    string           `json:"manifest"` // the package name
	Version string           `json:"version"`  // the version of the package
	FoundBy string           `json:"foundBy"`  // the specific cataloger that discovered this package
	Source  []file.Reference `json:"sources"`  // the locations that lead to the discovery of this package (note: this is not necessarily the locations that make up this package)
	// TODO: should we move licenses into metadata?
	Licenses     []string     `json:"licenses"`           // licenses discovered with the package metadata
	Language     Language     `json:"language"`           // the language ecosystem this package belongs to (e.g. JavaScript, Python, etc)
	Type         Type         `json:"type"`               // the package type (e.g. Npm, Yarn, Python, Rpm, Deb, etc)
	MetadataType MetadataType `json:"metadataType"`       // the shape of the additional data in the "metadata" field
	Metadata     interface{}  `json:"metadata,omitempty"` // additional data found while parsing the package source
}

// ID returns the package ID, which is unique relative to a package catalog.
func (p Package) ID() ID {
	return p.id
}

// Stringer to represent a package.
func (p Package) String() string {
	return fmt.Sprintf("Pkg(type=%s, name=%s, version=%s)", p.Type, p.Name, p.Version)
}

// PackageURL returns a package-URL representation of the given package (see https://github.com/package-url/purl-spec)
func (p Package) PackageURL(d distro.Distro) string {
	// default to pURLs on the metadata
	if p.Metadata != nil {
		if i, ok := p.Metadata.(interface{ PackageURL() string }); ok {
			return i.PackageURL()
		} else if i, ok := p.Metadata.(interface{ PackageURL(distro.Distro) string }); ok {
			return i.PackageURL(d)
		}
	}

	var purlType = p.Type.PackageURLType()
	var name = p.Name
	var namespace = ""

	switch {
	case purlType == "":
		// there is no purl type, don't attempt to craft a purl
		// TODO: should this be a "generic" purl type instead?
		return ""
	case p.Type == GoModulePkg:
		re := regexp.MustCompile(`(\/)[^\/]*$`)
		fields := re.Split(p.Name, -1)
		namespace = fields[0]
		name = strings.TrimPrefix(p.Name, namespace+"/")
	}

	// generate a purl from the package data
	pURL := packageurl.NewPackageURL(
		purlType,
		namespace,
		name,
		p.Version,
		nil,
		"")

	return pURL.ToString()
}
