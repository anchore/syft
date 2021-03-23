package packages

import (
	"fmt"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/version"
	"github.com/anchore/syft/syft/distro"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

// JSONDocument represents the syft cataloging findings as a JSON document
type JSONDocument struct {
	Artifacts             []JSONPackage      `json:"artifacts"` // Artifacts is the list of packages discovered and placed into the catalog
	ArtifactRelationships []JSONRelationship `json:"artifactRelationships"`
	Source                JSONSource         `json:"source"`     // Source represents the original object that was cataloged
	Distro                JSONDistribution   `json:"distro"`     // Distro represents the Linux distribution that was detected from the source
	Descriptor            JSONDescriptor     `json:"descriptor"` // Descriptor is a block containing self-describing information about syft
	Schema                JSONSchema         `json:"schema"`     // Schema is a block reserved for defining the version for the shape of this JSON document and where to find the schema document to validate the shape
}

// NewJSONDocument creates and populates a new JSON document struct from the given cataloging results.
func NewJSONDocument(catalog *pkg.Catalog, srcMetadata source.Metadata, d *distro.Distro, scope source.Scope, configuration interface{}) (JSONDocument, error) {
	src, err := NewJSONSource(srcMetadata, scope)
	if err != nil {
		return JSONDocument{}, err
	}

	artifacts, err := NewJSONPackages(catalog)
	if err != nil {
		return JSONDocument{}, err
	}

	return JSONDocument{
		Artifacts:             artifacts,
		ArtifactRelationships: newJSONRelationships(pkg.NewRelationships(catalog)),
		Source:                src,
		Distro:                NewJSONDistribution(d),
		Descriptor: JSONDescriptor{
			Name:          internal.ApplicationName,
			Version:       version.FromBuild().Version,
			Configuration: configuration,
		},
		Schema: JSONSchema{
			Version: internal.JSONSchemaVersion,
			URL:     fmt.Sprintf("https://raw.githubusercontent.com/anchore/syft/main/schema/json/schema-%s.json", internal.JSONSchemaVersion),
		},
	}, nil
}

// JSONDescriptor describes what created the document as well as surrounding metadata
type JSONDescriptor struct {
	Name          string      `json:"name"`
	Version       string      `json:"version"`
	Configuration interface{} `json:"configuration,omitempty"`
}

type JSONSchema struct {
	Version string `json:"version"`
	URL     string `json:"url"`
}
