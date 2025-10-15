package fileresolver

import (
	"os"
	"syscall"

	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/syft/internal/log"
)

func NewMetadataFromPath(path string, info os.FileInfo) file.Metadata {
	var mimeType string
	uid, gid := getXid(info)

	ty := file.TypeFromMode(info.Mode())

	if ty == file.TypeRegular {
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

// getXid is the UID GID system info for unix
func getXid(info os.FileInfo) (uid, gid int) {
	uid = -1
	gid = -1
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		uid = int(stat.Uid)
		gid = int(stat.Gid)
	}

	return uid, gid
}
