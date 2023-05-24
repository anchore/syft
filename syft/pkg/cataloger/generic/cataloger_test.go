package generic

import (
	"fmt"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

func Test_Cataloger(t *testing.T) {
	allParsedPaths := make(map[string]bool)
	parser := func(resolver file.Resolver, env *Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
		allParsedPaths[reader.AccessPath()] = true
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

	actualPkgs, relationships, err := cataloger.Catalog(resolver)
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
