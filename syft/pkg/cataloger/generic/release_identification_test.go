package generic

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

// releaseLookupCountingResolver records how many times the cataloger asks for /etc/os-release,
// the first file linux.IdentifyRelease looks up.
type releaseLookupCountingResolver struct {
	file.Resolver
	osReleaseLookups int
}

func (r *releaseLookupCountingResolver) FilesByPath(paths ...string) ([]file.Location, error) {
	for _, p := range paths {
		if p == "/etc/os-release" {
			r.osReleaseLookups++
		}
	}
	return r.Resolver.FilesByPath(paths...)
}

func Test_Cataloger_SkipsOSReleaseWhenNoFilesMatch(t *testing.T) {
	tests := []struct {
		name              string
		files             []string // what the resolver holds; the cataloger globs for **/a-path.txt
		wantReadOSRelease bool
	}{
		{
			name:              "no files",
			files:             nil,
			wantReadOSRelease: false,
		},
		{
			name:              "files, but none match the glob",
			files:             []string{"testdata/another-path.txt"},
			wantReadOSRelease: false,
		},
		{
			name:              "a file matches the glob",
			files:             []string{"testdata/a-path.txt"},
			wantReadOSRelease: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := func(_ context.Context, _ file.Resolver, _ *Environment, _ file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
				return nil, nil, nil
			}
			resolver := &releaseLookupCountingResolver{Resolver: file.NewMockResolverForPaths(tt.files...)}

			_, _, err := NewCataloger("test-cataloger").WithParserByGlobs(parser, "**/a-path.txt").Catalog(context.Background(), resolver)
			require.NoError(t, err)

			assert.Equal(t, tt.wantReadOSRelease, resolver.osReleaseLookups > 0, "os-release lookups: %d", resolver.osReleaseLookups)
		})
	}
}
