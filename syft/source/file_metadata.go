package source

import (
	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/image"
)

type FileMetadata = file.Metadata

func fileMetadataByLocation(img *image.Image, location Location) (file.Metadata, error) {
	entry, err := img.FileCatalog.Get(location.ref)
	if err != nil {
		return FileMetadata{}, err
	}

	return entry.Metadata, nil
}
