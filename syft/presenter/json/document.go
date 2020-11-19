package json

import (
	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/version"
	"github.com/anchore/syft/syft/distro"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

// Document represents the syft cataloging findings as a JSON document
type Document struct {
	Artifacts  []Package    `json:"artifacts"`  // Artifacts is the list of packages discovered and placed into the catalog
	Source     Source       `json:"source"`     // Source represents the original object that was cataloged
	Distro     Distribution `json:"distro"`     // Distro represents the Linux distribution that was detected from the source
	Descriptor Descriptor   `json:"descriptor"` // Descriptor is a block containing self-describing information about syft
}

// NewDocument creates and populates a new JSON document struct from the given cataloging results.
func NewDocument(catalog *pkg.Catalog, srcMetadata source.Metadata, d *distro.Distro) (Document, error) {
	src, err := NewSource(srcMetadata)
	if err != nil {
		return Document{}, nil
	}

	doc := Document{
		Artifacts: make([]Package, 0),
		Source:    src,
		Distro:    NewDistribution(d),
		Descriptor: Descriptor{
			Name:    internal.ApplicationName,
			Version: version.FromBuild().Version,
		},
	}

	for _, p := range catalog.Sorted() {
		art, err := NewPackage(p)
		if err != nil {
			return Document{}, err
		}
		doc.Artifacts = append(doc.Artifacts, art)
	}

	return doc, nil
}
