package json

import (
	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/version"
	"github.com/anchore/syft/syft/distro"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

type Document struct {
	Artifacts  []Artifact   `json:"artifacts"`
	Source     Source       `json:"source"`
	Distro     Distribution `json:"distro"`
	Descriptor Descriptor   `json:"descriptor"`
}

func NewDocument(catalog *pkg.Catalog, srcMetadata source.Metadata, d distro.Distro) (Document, error) {
	src, err := NewSource(srcMetadata)
	if err != nil {
		return Document{}, nil
	}

	doc := Document{
		Artifacts: make([]Artifact, 0),
		Source:    src,
		Distro:    NewDistribution(d),
		Descriptor: Descriptor{
			Name:    internal.ApplicationName,
			Version: version.FromBuild().Version,
		},
	}

	for _, p := range catalog.Sorted() {
		art, err := NewArtifact(p)
		if err != nil {
			return Document{}, err
		}
		doc.Artifacts = append(doc.Artifacts, art)
	}

	return doc, nil
}
