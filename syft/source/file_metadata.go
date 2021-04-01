package source

import (
	"os"

	"github.com/anchore/stereoscope/pkg/image"
)

type FileMetadata struct {
	Mode            os.FileMode
	Type            FileType
	UserID          int
	GroupID         int
	LinkDestination string
	Size            int64
}

func fileMetadataByLocation(img *image.Image, location Location) (FileMetadata, error) {
	entry, err := img.FileCatalog.Get(location.ref)
	if err != nil {
		return FileMetadata{}, err
	}

	return FileMetadata{
		Mode:            entry.Metadata.Mode,
		Type:            newFileTypeFromTarHeaderTypeFlag(entry.Metadata.TypeFlag),
		UserID:          entry.Metadata.UserID,
		GroupID:         entry.Metadata.GroupID,
		LinkDestination: entry.Metadata.Linkname,
		Size:            entry.Metadata.Size,
	}, nil
}
