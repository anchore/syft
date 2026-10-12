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

	expectedSelection := []string{"testdata/last/path.txt", "testdata/another-path.txt", "testdata/a-path.txt", "testdata/empty.txt"}
	resolver := file.NewMockResolverForPaths(expectedSelection...)
	cataloger := NewCataloger(upstream).
		WithParserByPath(parser, "testdata/another-path.txt", "testdata/last/path.txt").
		WithParserByGlobs(parser, "**/a-path.txt", "**/empty.txt")

	actualPkgs, relationships, err := cataloger.Catalog(context.Background(), resolver)
	assert.NoError(t, err)

	expectedPkgs := make(map[string]pkg.Package)
	for _, path := range expectedSelection {
		require.True(t, allParsedPaths[path])
		if path == "testdata/empty.txt" {
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

func (m spyReturningFileResolver) FilesByMediaType(types ...string) ([]file.Location, error) {
	return m.m.FilesByMediaType(types...)
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
	resolver := newSpyReturningFileResolver(&spy, "testdata/another-path.txt")
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

	_, _, err := c.Catalog(ctx, resolver)
	require.Error(t, err)
	var coordErr *unknown.CoordinateError
	require.ErrorAs(t, err, &coordErr)
	assert.ErrorContains(t, err, "recovered from panic while parsing file: panic!")
	require.True(t, spy.closed)
}

func TestParserPanicBecomesUnknown(t *testing.T) {
	tests := []struct {
		name    string
		doPanic func()
		wantErr string
	}{
		{
			name:    "string panic",
			doPanic: func() { panic("boom") },
			wantErr: "boom",
		},
		{
			name: "runtime panic",
			doPanic: func() {
				var m map[string]int
				m["x"] = 1
			},
			wantErr: "assignment to entry in nil map",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := func(_ context.Context, _ file.Resolver, _ *Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
				if reader.Path() == "testdata/another-path.txt" {
					tt.doPanic()
				}
				return []pkg.Package{{Name: "good", Locations: file.NewLocationSet(reader.Location)}}, nil, nil
			}

			resolver := file.NewMockResolverForPaths("testdata/a-path.txt", "testdata/another-path.txt")
			c := NewCataloger("unit-test-cataloger").
				WithParserByPath(parser, "testdata/a-path.txt", "testdata/another-path.txt")

			pkgs, _, err := c.Catalog(context.Background(), resolver)

			require.Len(t, pkgs, 1)
			assert.Equal(t, "good", pkgs[0].Name)

			unknowns, remaining := unknown.ExtractCoordinateErrors(err)
			require.NoError(t, remaining)
			require.Len(t, unknowns, 1)
			assert.Equal(t, "testdata/another-path.txt", unknowns[0].Coordinates.RealPath)
			assert.ErrorContains(t, unknowns[0].Reason, tt.wantErr)
		})
	}
}

func TestProcessorPanicKeepsResults(t *testing.T) {
	parser := func(_ context.Context, _ file.Resolver, _ *Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
		return []pkg.Package{{Name: "good", Locations: file.NewLocationSet(reader.Location)}}, nil, nil
	}

	rename := func(pkgs []pkg.Package, rels []artifact.Relationship, err error) ([]pkg.Package, []artifact.Relationship, error) {
		for i := range pkgs {
			pkgs[i].Name = "processed"
		}
		return pkgs, rels, err
	}

	tests := []struct {
		name      string
		cataloger *Cataloger
		want      string
	}{
		{
			name: "processor",
			cataloger: NewCataloger("unit-test-cataloger").
				WithParserByPath(parser, "testdata/a-path.txt").
				WithProcessors(func([]pkg.Package, []artifact.Relationship, error) ([]pkg.Package, []artifact.Relationship, error) {
					panic("boom")
				}),
			want: "good",
		},
		{
			// output from earlier processors survives a later processor panicking
			name: "chained processors",
			cataloger: NewCataloger("unit-test-cataloger").
				WithParserByPath(parser, "testdata/a-path.txt").
				WithProcessors(rename, func([]pkg.Package, []artifact.Relationship, error) ([]pkg.Package, []artifact.Relationship, error) {
					panic("boom")
				}),
			want: "processed",
		},
		{
			name: "resolving processor",
			cataloger: NewCataloger("unit-test-cataloger").
				WithParserByPath(parser, "testdata/a-path.txt").
				WithResolvingProcessors(func(context.Context, file.Resolver, []pkg.Package, []artifact.Relationship, error) ([]pkg.Package, []artifact.Relationship, error) {
					var m map[string]int
					m["x"] = 1
					return nil, nil, nil
				}),
			want: "good",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolver := file.NewMockResolverForPaths("testdata/a-path.txt")

			pkgs, _, err := tt.cataloger.Catalog(context.Background(), resolver)

			require.NoError(t, err)
			require.Len(t, pkgs, 1)
			assert.Equal(t, tt.want, pkgs[0].Name)
		})
	}
}

func Test_CatalogerWithParserByMediaType(t *testing.T) {
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

		return []pkg.Package{p}, nil, nil
	}

	upstream := "media-type-cataloger"

	// Create locations with test fixtures that exist on disk
	loc1 := file.NewLocation("testdata/a-path.txt")
	loc2 := file.NewLocation("testdata/another-path.txt")

	// Create a mock resolver that maps media types to locations
	resolver := file.NewMockResolverForMediaTypes(map[string][]file.Location{
		"application/vnd.test.model": {loc1, loc2},
	})

	cataloger := NewCataloger(upstream).
		WithParserByMediaType(parser, "application/vnd.test.model")

	actualPkgs, _, err := cataloger.Catalog(context.Background(), resolver)
	assert.NoError(t, err)

	// Verify both files were parsed
	assert.True(t, allParsedPaths["testdata/a-path.txt"], "expected a-path.txt to be parsed")
	assert.True(t, allParsedPaths["testdata/another-path.txt"], "expected another-path.txt to be parsed")

	// Verify packages were created
	assert.Len(t, actualPkgs, 2)

	// Verify FoundBy is set correctly
	for _, p := range actualPkgs {
		assert.Equal(t, upstream, p.FoundBy)
	}
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
		"testdata/a-path.txt",
		"testdata/empty.txt",
	)

	got, _, errs := genericErrorReturning.Catalog(context.TODO(), m)

	// require packages and errors
	require.NotEmpty(t, got)

	unknowns, others := unknown.ExtractCoordinateErrors(errs)
	require.NotEmpty(t, unknowns)
	require.Empty(t, others)
}
