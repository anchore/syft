package common

import (
	"fmt"
	"io"
	"io/ioutil"
	"testing"

	"github.com/anchore/syft/syft/source"

	"github.com/anchore/syft/syft/pkg"
)

type testResolverMock struct {
	contents map[source.Location]string
}

func newTestResolver() *testResolverMock {
	return &testResolverMock{
		contents: make(map[source.Location]string),
	}
}

func (r *testResolverMock) FileContentsByLocation(_ source.Location) (string, error) {
	return "", fmt.Errorf("not implemented")
}

func (r *testResolverMock) MultipleFileContentsByLocation([]source.Location) (map[source.Location]string, error) {
	return r.contents, nil
}

func (r *testResolverMock) FilesByPath(paths ...string) ([]source.Location, error) {
	results := make([]source.Location, len(paths))

	for idx, p := range paths {
		results[idx] = source.NewLocation(p)
		r.contents[results[idx]] = fmt.Sprintf("%s file contents!", p)
	}

	return results, nil
}

func (r *testResolverMock) FilesByGlob(_ ...string) ([]source.Location, error) {
	path := "/a-path.txt"
	location := source.NewLocation(path)
	r.contents[location] = fmt.Sprintf("%s file contents!", path)
	return []source.Location{location}, nil
}

func (r *testResolverMock) RelativeFileByPath(_ source.Location, _ string) *source.Location {
	panic(fmt.Errorf("not implemented"))
	return nil
}

func parser(_ string, reader io.Reader) ([]pkg.Package, error) {
	contents, err := ioutil.ReadAll(reader)
	if err != nil {
		panic(err)
	}
	return []pkg.Package{
		{
			Name: string(contents),
		},
	}, nil
}

func TestGenericCataloger(t *testing.T) {

	globParsers := map[string]ParserFn{
		"**a-path.txt": parser,
	}
	pathParsers := map[string]ParserFn{
		"/another-path.txt": parser,
		"/last/path.txt":    parser,
	}
	upstream := "some-other-cataloger"
	resolver := newTestResolver()
	cataloger := NewGenericCataloger(pathParsers, globParsers, upstream)

	expectedSelection := []string{"/last/path.txt", "/another-path.txt", "/a-path.txt"}
	expectedPkgs := make(map[string]pkg.Package)
	for _, path := range expectedSelection {
		expectedPkgs[path] = pkg.Package{
			FoundBy: upstream,
			Name:    fmt.Sprintf("%s file contents!", path),
		}
	}

	actualPkgs, err := cataloger.Catalog(resolver)
	if err != nil {
		t.Fatalf("cataloger catalog action failed: %+v", err)
	}

	if len(actualPkgs) != len(expectedPkgs) {
		t.Fatalf("unexpected packages len: %d", len(actualPkgs))
	}

	for _, p := range actualPkgs {
		ref := p.Locations[0]
		exP, ok := expectedPkgs[ref.Path]
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
