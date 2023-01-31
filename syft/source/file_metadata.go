package source

import (
	"os"

	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/internal/log"
)

type FileMetadata = file.Metadata

func fileMetadataByLocation(img *image.Image, location Location) (file.Metadata, error) {
	entry, err := img.FileCatalog.Get(location.ref)
	if err != nil {
		return FileMetadata{}, err
	}

	return entry.Metadata, nil
}

func fileMetadataFromPath(path string, info os.FileInfo, withMIMEType bool) file.Metadata {
	var mimeType string
	uid, gid := GetXid(info)

	if withMIMEType {
		f, err := os.Open(path)
		if err != nil {
			// TODO: it may be that the file is inaccessible, however, this is not an error or a warning. In the future we need to track these as known-unknowns
			f = nil
		} else {
			defer func() {
				if err := f.Close(); err != nil {
					log.Warnf("unable to close file while obtaining metadata: %s", path)
				}
			}()
		}

		mimeType = file.MIMEType(f)
	}

	return FileMetadata{
		Mode: info.Mode(),
		Type: file.TypeFromMode(info.Mode()),
		// unsupported across platforms
		UserID:   uid,
		GroupID:  gid,
		Size:     info.Size(),
		MIMEType: mimeType,
	}
}
