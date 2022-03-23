package source

import (
	"os"

	stereoscopeFile "github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/file"
)

func fileMetadataByImageLocation(img *image.Image, location file.Location) (file.Metadata, error) {
	entry, err := img.FileCatalog.Get(location.Ref())
	if err != nil {
		return file.Metadata{}, err
	}

	return file.Metadata{
		Mode:            entry.Metadata.Mode,
		Type:            file.NewFileTypeFromTarHeaderTypeFlag(entry.Metadata.TypeFlag),
		UserID:          entry.Metadata.UserID,
		GroupID:         entry.Metadata.GroupID,
		LinkDestination: entry.Metadata.Linkname,
		Size:            entry.Metadata.Size,
		MIMEType:        entry.Metadata.MIMEType,
	}, nil
}

func fileMetadataFromPath(path string, info os.FileInfo, withMIMEType bool) file.Metadata {
	var mimeType string
	uid, gid := getFileXid(info)

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

		mimeType = stereoscopeFile.MIMEType(f)
	}

	return file.Metadata{
		Mode: info.Mode(),
		Type: file.NewFileTypeFromMode(info.Mode()),
		// unsupported across platforms
		UserID:   uid,
		GroupID:  gid,
		Size:     info.Size(),
		MIMEType: mimeType,
	}
}
