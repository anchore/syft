package source

import (
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft/file"
)

// Metadata represents any static source data that helps describe "what" was cataloged.
type Metadata struct {
	ID            string        `hash:"ignore"` // the id generated from the parent source struct
	Scheme        Scheme        // the source data scheme type (directory or image)
	ImageMetadata ImageMetadata // all image info (image only)
	Path          string        // the root path to be cataloged (directory only)
	Base          string        // the base path to be cataloged (directory only)
	Name          string
}

func fileMetadataByLocation(img *image.Image, location Location) (file.Metadata, error) {
	entry, err := img.FileCatalog.Get(location.Reference())
	if err != nil {
		return file.Metadata{}, err
	}

	return entry.Metadata, nil
}
