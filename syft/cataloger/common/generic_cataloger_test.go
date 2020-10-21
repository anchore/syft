package common

import (
	"fmt"
	"io"
	"io/ioutil"
	"testing"

	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/syft/syft/pkg"
)

type testResolver struct {
	contents map[file.Reference]string
}

func newTestResolver() *testResolver {
	return &testResolver{
		contents: make(map[file.Reference]string),
	}
}

func (r *testResolver) FileContentsByRef(_ file.Reference) (string, error) {
	return "", fmt.Errorf("not implemented")
}

func (r *testResolver) MultipleFileContentsByRef(_ ...file.Reference) (map[file.Reference]string, error) {
	return r.contents, nil
}

func (r *testResolver) FilesByPath(paths ...file.Path) ([]file.Reference, error) {
	results := make([]file.Reference, len(paths))

	for idx, p := range paths {
		results[idx] = file.NewFileReference(p)
		r.contents[results[idx]] = fmt.Sprintf("%s file contents!", p)
	}

	return results, nil
}

func (r *testResolver) FilesByGlob(_ ...string) ([]file.Reference, error) {
	path := "/a-path.txt"
	ref := file.NewFileReference(file.Path(path))
	r.contents[ref] = fmt.Sprintf("%s file contents!", path)
	return []file.Reference{ref}, nil
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
		ref := p.Source[0]
		exP, ok := expectedPkgs[string(ref.Path)]
		if !ok {
			t.Errorf("missing expected pkg: ref=%+v", ref)
			continue
		}

		if p.FoundBy != exP.FoundBy {
			t.Errorf("bad upstream: %s", p.FoundBy)
		}

		if exP.Name != p.Name {
			t.Errorf("bad contents mapping: %+v", p.Source)
		}
	}
}
