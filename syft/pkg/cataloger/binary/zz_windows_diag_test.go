package binary

import (
	"context"
	"io"
	"testing"

	"github.com/anchore/syft/syft/source"
	"github.com/anchore/syft/syft/source/directorysource"
)

// temporary diagnostic, to be removed
func TestZZWindowsDiag(t *testing.T) {
	for _, dir := range []string{
		"testdata/classifiers/snippets/python-duplicates/3.8.16/linux-amd64",
		"testdata/classifiers/bin/ruby-shared-libs/2.6.10/linux-amd64",
	} {
		src, err := directorysource.NewFromPath(dir)
		if err != nil {
			t.Logf("DIAG %s: %v", dir, err)
			continue
		}
		r, _ := src.FileResolver(source.SquashedScope)
		for l := range r.AllLocations(context.Background()) {
			m, _ := r.FileMetadataByLocation(l)
			t.Logf("DIAG %s: all real=%q access=%q type=%v size=%d", dir, l.RealPath, l.AccessPath, m.Type, m.Size())
			if rc, err := r.FileContentsByLocation(l); err != nil {
				t.Logf("DIAG   contents err: %v", err)
			} else {
				b, _ := io.ReadAll(rc)
				_ = rc.Close()
				t.Logf("DIAG   contents %d bytes: %q", len(b), b)
			}
		}
		for _, g := range []string{"**/python*", "**/libpython*.so*", "**/lib*", "**/ruby"} {
			locs, err := r.FilesByGlob(g)
			for _, l := range locs {
				t.Logf("DIAG %s: glob %s -> %q (err=%v)", dir, g, l.RealPath, err)
			}
		}
	}
}
