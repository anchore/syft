package source

import (
	"github.com/anchore/syft/syft/artifact"
)

// Metadata represents any static source data that helps describe "what" was cataloged.
type Metadata struct {
	Scheme        Scheme        // the source data scheme type (directory or image)
	ImageMetadata ImageMetadata // all image info (image only)
	Path          string        // the root path to be cataloged (directory only)
}

func (m *Metadata) ID() artifact.ID {
	id, _ := artifact.IDByHash(m)
	return id
}

var _ artifact.Identifiable = (*Metadata)(nil)
