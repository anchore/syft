package json

import (
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/scope"
)

type Document struct {
	Artifacts []Artifact `json:"artifacts"`
	Source    Source     `json:"source"`
}

func NewDocument(catalog *pkg.Catalog, s scope.Scope) (Document, error) {
	doc := Document{
		Artifacts: make([]Artifact, 0),
	}

	src, err := NewSource(s)
	if err != nil {
		return Document{}, nil
	}
	doc.Source = src

	for _, p := range catalog.Sorted() {
		art, err := NewArtifact(p, s)
		if err != nil {
			return Document{}, err
		}
		doc.Artifacts = append(doc.Artifacts, art)
	}

	return doc, nil
}
