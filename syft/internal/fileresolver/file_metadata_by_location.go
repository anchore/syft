package fileresolver

import (
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft/file"
)

func fileMetadataByLocation(img *image.Image, location file.Location) (file.Metadata, error) {
	entry, err := img.FileCatalog.Get(location.Reference())
	if err != nil {
		return file.Metadata{}, err
	}

	return entry.Metadata, nil
}
