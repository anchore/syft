package source

import (
	"os"
	"syscall"

	"github.com/anchore/syft/internal/log"

	"github.com/anchore/stereoscope/pkg/file"

	"github.com/anchore/stereoscope/pkg/image"
)

type FileMetadata struct {
	Mode            os.FileMode
	Type            FileType
	UserID          int
	GroupID         int
	LinkDestination string
	Size            int64
	MIMEType        string
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
		MIMEType:        entry.Metadata.MIMEType,
	}, nil
}

func fileMetadataFromPath(path string, info os.FileInfo) (FileMetadata, error) {
	uid := -1
	gid := -1
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		uid = int(stat.Uid)
		gid = int(stat.Gid)
	}

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

	return FileMetadata{
		Mode: info.Mode(),
		Type: newFileTypeFromMode(info.Mode()),
		// unsupported across platforms
		UserID:   uid,
		GroupID:  gid,
		MIMEType: file.MIMEType(f),
	}, nil
}
