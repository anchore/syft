package json

import (
	"time"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/version"
	"github.com/anchore/syft/syft/distro"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/scope"
)

type Document struct {
	Artifacts  []Artifact   `json:"artifacts"`
	Source     Source       `json:"source"`
	Distro     Distribution `json:"distro"`
	Descriptor Descriptor   `json:"descriptor"`
}

// Descriptor describes what created the document as well as surrounding metadata
type Descriptor struct {
	Name            string `json:"name"`
	Version         string `json:"version"`
	ReportTimestamp string `json:"reportTimestamp"`
	// TODO: we should include scope option here as well (or in source)
}

// Distribution provides information about a detected Linux Distribution
type Distribution struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	IDLike  string `json:"idLike"`
}

func NewDocument(catalog *pkg.Catalog, s scope.Scope, d distro.Distro) (Document, error) {
	src, err := NewSource(s)
	if err != nil {
		return Document{}, nil
	}

	distroName := d.Name()
	if distroName == "UnknownDistroType" {
		distroName = ""
	}

	doc := Document{
		Artifacts: make([]Artifact, 0),
		Source:    src,
		Distro: Distribution{
			Name:    distroName,
			Version: d.FullVersion(),
			IDLike:  d.IDLike,
		},
		Descriptor: Descriptor{
			Name:            internal.ApplicationName,
			Version:         version.FromBuild().Version,
			ReportTimestamp: time.Now().Format(time.RFC3339),
		},
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
