package common

import (
	"fmt"
	"io"
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

func parser(_ string, reader io.Reader) ([]*pkg.Package, []artifact.Relationship, error) {
	contents, err := ioutil.ReadAll(reader)
	if err != nil {
		panic(err)
	}
	return []*pkg.Package{
		{
			Name: string(contents),
		},
	}, nil, nil
}

func TestGenericCataloger(t *testing.T) {

	globParsers := map[string]ParserFn{
		"**/a-path.txt": parser,
	}
	pathParsers := map[string]ParserFn{
		"test-fixtures/another-path.txt": parser,
		"test-fixtures/last/path.txt":    parser,
	}
	upstream := "some-other-cataloger"

	expectedSelection := []string{"test-fixtures/last/path.txt", "test-fixtures/another-path.txt", "test-fixtures/a-path.txt"}
	resolver := source.NewMockResolverForPaths(expectedSelection...)
	cataloger := NewGenericCataloger(pathParsers, globParsers, upstream)

	expectedPkgs := make(map[string]pkg.Package)
	for _, path := range expectedSelection {
		expectedPkgs[path] = pkg.Package{
			FoundBy: upstream,
			Name:    fmt.Sprintf("%s file contents!", path),
		}
	}

	actualPkgs, _, err := cataloger.Catalog(resolver)
	assert.NoError(t, err)
	assert.Len(t, actualPkgs, len(expectedPkgs))

	for _, p := range actualPkgs {
		ref := p.Locations.ToSlice()[0]
		exP, ok := expectedPkgs[ref.RealPath]
		if !ok {
			t.Errorf("missing expected pkg: ref=%+v", ref)
			continue
		}

		if p.FoundBy != exP.FoundBy {
			t.Errorf("bad upstream: %s", p.FoundBy)
		}

		if exP.Name != p.Name {
			t.Errorf("bad contents mapping: %+v", p.Locations)
		}
	}
}
