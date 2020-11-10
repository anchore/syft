package json

import (
	"github.com/anchore/syft/syft/distro"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/scope"
)

type Document struct {
	Artifacts []Artifact   `json:"artifacts"`
	Source    Source       `json:"source"`
	Distro    Distribution `json:"distro"`
}

// Distritbution provides information about a detected Linux Distribution
type Distribution struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	IDLike  string `json:"idLike"`
}

func NewDocument(catalog *pkg.Catalog, s scope.Scope, d distro.Distro) (Document, error) {
	doc := Document{
		Artifacts: make([]Artifact, 0),
	}

	src, err := NewSource(s)
	if err != nil {
		return Document{}, nil
	}
	doc.Source = src
	distroName := d.Name()
	if distroName == "UnknownDistroType" {
		distroName = ""
	}
	doc.Distro = Distribution{
		Name:    distroName,
		Version: d.FullVersion(),
		IDLike:  d.IDLike,
	}

	for _, p := range catalog.Sorted() {
		art, err := NewArtifact(p, s)
		if err != nil {
			return Document{}, err
		}
		doc.Artifacts = append(doc.Artifacts, art)
	}

	return doc, nil
}
