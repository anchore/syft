package json

import (
	"fmt"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/scope"
)

type Document struct {
	Artifacts []Artifact `json:"artifacts"`
	Image     *Image     `json:"image,omitempty"`
	Directory *string    `json:"directory,omitempty"`
}

func NewDocument(catalog *pkg.Catalog, s scope.Scope) (Document, error) {
	doc := Document{
		Artifacts: make([]Artifact, 0),
	}

	srcObj := s.Source()
	switch src := srcObj.(type) {
	case scope.ImageSource:
		doc.Image = NewImage(src)
	case scope.DirSource:
		doc.Directory = &s.DirSrc.Path
	default:
		return Document{}, fmt.Errorf("unsupported source: %T", src)
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
