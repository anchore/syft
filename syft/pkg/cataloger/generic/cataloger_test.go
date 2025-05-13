package generic

import (
	"context"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/internal/unknown"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

func Test_Cataloger(t *testing.T) {
	allParsedPaths := make(map[string]bool)
	parser := func(_ context.Context, resolver file.Resolver, env *Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
		allParsedPaths[reader.Path()] = true
		contents, err := io.ReadAll(reader)
		require.NoError(t, err)

		if len(contents) == 0 {
			return nil, nil, nil
		}

		p := pkg.Package{
			Name:      string(contents),
			Locations: file.NewLocationSet(reader.Location),
		}
		r := artifact.Relationship{
			From: p,
			To:   p,
			Type: artifact.ContainsRelationship,
		}

		return []pkg.Package{p}, []artifact.Relationship{r}, nil
	}

	upstream := "some-other-cataloger"

	expectedSelection := []string{"test-fixtures/last/path.txt", "test-fixtures/another-path.txt", "test-fixtures/a-path.txt", "test-fixtures/empty.txt"}
	resolver := file.NewMockResolverForPaths(expectedSelection...)
	cataloger := NewCataloger(upstream).
		WithParserByPath(parser, "test-fixtures/another-path.txt", "test-fixtures/last/path.txt").
		WithParserByGlobs(parser, "**/a-path.txt", "**/empty.txt")

	actualPkgs, relationships, err := cataloger.Catalog(context.Background(), resolver)
	assert.NoError(t, err)

	expectedPkgs := make(map[string]pkg.Package)
	for _, path := range expectedSelection {
		require.True(t, allParsedPaths[path])
		if path == "test-fixtures/empty.txt" {
			continue // note: empty.txt won't become a package
		}
		expectedPkgs[path] = pkg.Package{
			FoundBy: upstream,
			Name:    fmt.Sprintf("%s file contents!", path),
		}
	}

	assert.Len(t, allParsedPaths, len(expectedSelection))
	assert.Len(t, actualPkgs, len(expectedPkgs))
	assert.Len(t, relationships, len(actualPkgs))

	for _, p := range actualPkgs {
		ls := p.Locations.ToSlice()
		require.NotEmpty(t, ls)
		ref := ls[0]
		exP, ok := expectedPkgs[ref.RealPath]
		if !ok {
			t.Errorf("missing expected pkg: ref=%+v", ref)
			continue
		}

		// assigned by the generic cataloger
		if p.FoundBy != exP.FoundBy {
			t.Errorf("bad upstream: %s", p.FoundBy)
		}

		// assigned by the parser
		if exP.Name != p.Name {
			t.Errorf("bad contents mapping: %+v", p.Locations)
		}
	}
}

type spyReturningFileResolver struct {
	m *file.MockResolver
	s *spyingIoReadCloser
}

type spyingIoReadCloser struct {
	rc     io.ReadCloser
	closed bool
}

func newSpyReturningFileResolver(s *spyingIoReadCloser, paths ...string) file.Resolver {
	m := file.NewMockResolverForPaths(paths...)
	return spyReturningFileResolver{
		m: m,
		s: s,
	}
}

func (s *spyingIoReadCloser) Read(p []byte) (n int, err error) {
	return s.rc.Read(p)
}

func (s *spyingIoReadCloser) Close() error {
	s.closed = true
	return s.rc.Close()
}

var _ io.ReadCloser = (*spyingIoReadCloser)(nil)

func (m spyReturningFileResolver) FileContentsByLocation(location file.Location) (io.ReadCloser, error) {
	return m.s, nil
}

func (m spyReturningFileResolver) HasPath(path string) bool {
	return m.m.HasPath(path)
}

func (m spyReturningFileResolver) FilesByPath(paths ...string) ([]file.Location, error) {
	return m.m.FilesByPath(paths...)
}

func (m spyReturningFileResolver) FilesByGlob(patterns ...string) ([]file.Location, error) {
	return m.m.FilesByGlob(patterns...)
}

func (m spyReturningFileResolver) FilesByMIMEType(types ...string) ([]file.Location, error) {
	return m.m.FilesByMIMEType(types...)
}

func (m spyReturningFileResolver) RelativeFileByPath(f file.Location, path string) *file.Location {
	return m.m.RelativeFileByPath(f, path)
}

func (m spyReturningFileResolver) AllLocations(ctx context.Context) <-chan file.Location {
	return m.m.AllLocations(ctx)
}

func (m spyReturningFileResolver) FileMetadataByLocation(location file.Location) (file.Metadata, error) {
	return m.m.FileMetadataByLocation(location)
}

var _ file.Resolver = (*spyReturningFileResolver)(nil)

func TestClosesFileOnParserPanic(t *testing.T) {
	rc := io.NopCloser(strings.NewReader("some string"))
	spy := spyingIoReadCloser{
		rc: rc,
	}
	resolver := newSpyReturningFileResolver(&spy, "test-fixtures/another-path.txt")
	ctx := context.TODO()

	processors := []requester{
		func(resolver file.Resolver, env Environment) []request {
			return []request{
				{
					Location: file.Location{
						LocationData: file.LocationData{
							Coordinates: file.Coordinates{},
							AccessPath:  "/some/access/path",
						},
					},
					Parser: func(context.Context, file.Resolver, *Environment, file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
						panic("panic!")
					},
				},
			}
		},
	}

	c := Cataloger{
		requesters:        processors,
		upstreamCataloger: "unit-test-cataloger",
	}

	assert.PanicsWithValue(t, "panic!", func() {
		_, _, _ = c.Catalog(ctx, resolver)
	})
	require.True(t, spy.closed)
}

func Test_genericCatalogerReturnsErrors(t *testing.T) {
	genericErrorReturning := NewCataloger("error returning").WithParserByGlobs(func(ctx context.Context, resolver file.Resolver, environment *Environment, locationReader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
		return []pkg.Package{
			{
				Name: "some-package-" + locationReader.Path(),
			},
		}, nil, unknown.Newf(locationReader, "unable to read")
	}, "**/*")

	m := file.NewMockResolverForPaths(
		"test-fixtures/a-path.txt",
		"test-fixtures/empty.txt",
	)

	got, _, errs := genericErrorReturning.Catalog(context.TODO(), m)

	// require packages and errors
	require.NotEmpty(t, got)

	unknowns, others := unknown.ExtractCoordinateErrors(errs)
	require.NotEmpty(t, unknowns)
	require.Empty(t, others)
}
