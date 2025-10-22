package fileresolver

import (
	"os"

	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/syft/internal/windows"
)

func NewMetadataFromPath(path string, info os.FileInfo) file.Metadata {
	var mimeType string
	uid, gid := getXid(info)

	ty := file.TypeFromMode(info.Mode())

	if ty == file.TypeRegular {
		usablePath := path
		// denormalize the path back to windows so we can open the file
		if windows.HostRunningOnWindows() {
			usablePath = windows.FromPosix(usablePath)
		}

		f, err := os.Open(usablePath)
		if err != nil {
			// TODO: it may be that the file is inaccessible, however, this is not an error or a warning. In the future we need to track these as known-unknowns
			f = nil
		} else {
			defer internal.CloseAndLogError(f, usablePath)
		}

		mimeType = file.MIMEType(f)
	}

	return file.Metadata{
		FileInfo: info,
		Path:     path,
		Type:     ty,
		// unsupported across platforms
		UserID:   uid,
		GroupID:  gid,
		MIMEType: mimeType,
	}
}
