package directorysource

import (
	"os"
	"strings"

	"github.com/anchore/syft/internal/cache"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/internal/fileresolver"
)

// we do not want to cache things and then subsequently scan them, if, for example a user runs `syft /` twice
func excludeCachePathVisitors() []fileresolver.PathIndexVisitor {
	var out []fileresolver.PathIndexVisitor
	for _, dir := range cache.GetManager().RootDirs() {
		out = append(out, excludeCacheDirPathVisitor{
			dir: dir,
		}.excludeCacheDir)
	}
	return out
}

type excludeCacheDirPathVisitor struct {
	dir string
}

func (d excludeCacheDirPathVisitor) excludeCacheDir(_, path string, _ os.FileInfo, _ error) error {
	if strings.HasPrefix(path, d.dir) {
		log.Tracef("skipping cache path: %s", path)
		return fileresolver.ErrSkipPath
	}
	return nil
}
