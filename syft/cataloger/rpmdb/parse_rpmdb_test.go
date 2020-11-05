package rpmdb

import (
	"fmt"
	"os"
	"testing"

	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/go-test/deep"
)

type rpmdbTestFileResolverMock struct {
	ignorePaths bool
}

func newTestFileResolver(ignorePaths bool) *rpmdbTestFileResolverMock {
	return &rpmdbTestFileResolverMock{
		ignorePaths: ignorePaths,
	}
}

func (r *rpmdbTestFileResolverMock) FilesByPath(paths ...file.Path) ([]file.Reference, error) {
	if r.ignorePaths {
		// act as if no paths exist
		return nil, nil
	}
	// act as if all files exist
	var refs = make([]file.Reference, len(paths))
	for i, p := range paths {
		refs[i] = file.NewFileReference(p)
	}
	return refs, nil
}

func (r *rpmdbTestFileResolverMock) FilesByGlob(_ ...string) ([]file.Reference, error) {
	return nil, fmt.Errorf("not implemented")
}
func (r *rpmdbTestFileResolverMock) RelativeFileByPath(_ file.Reference, path string) (*file.Reference, error) {
	return nil, fmt.Errorf("not implemented")
}

func TestParseRpmDB(t *testing.T) {
	tests := []struct {
		fixture     string
		expected    map[string]pkg.Package
		ignorePaths bool
	}{
		{
			fixture: "test-fixtures/Packages",
			// we only surface package paths for files that exist (here we DO NOT expect a path)
			ignorePaths: true,
			expected: map[string]pkg.Package{
				"dive": {
					Name:         "dive",
					Version:      "0.9.2-1",
					Type:         pkg.RpmPkg,
					MetadataType: pkg.RpmdbMetadataType,
					Metadata: pkg.RpmdbMetadata{
						Name:      "dive",
						Epoch:     0,
						Arch:      "x86_64",
						Release:   "1",
						Version:   "0.9.2",
						SourceRpm: "dive-0.9.2-1.src.rpm",
						Size:      12406784,
						License:   "MIT",
						Vendor:    "",
						Files:     []pkg.RpmdbFileRecord{},
					},
				},
			},
		},
		{
			fixture: "test-fixtures/Packages",
			// we only surface package paths for files that exist (here we expect a path)
			ignorePaths: false,
			expected: map[string]pkg.Package{
				"dive": {
					Name:         "dive",
					Version:      "0.9.2-1",
					Type:         pkg.RpmPkg,
					MetadataType: pkg.RpmdbMetadataType,
					Metadata: pkg.RpmdbMetadata{
						Name:      "dive",
						Epoch:     0,
						Arch:      "x86_64",
						Release:   "1",
						Version:   "0.9.2",
						SourceRpm: "dive-0.9.2-1.src.rpm",
						Size:      12406784,
						License:   "MIT",
						Vendor:    "",
						Files: []pkg.RpmdbFileRecord{
							{
								Path:   "/usr/local/bin/dive",
								Mode:   33261,
								Size:   12406784,
								SHA256: "81d29f327ba23096b3c52ff6fe1c425641e618bc87b5c05ee377edc650afaa55",
							},
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.fixture, func(t *testing.T) {
			fixture, err := os.Open(test.fixture)
			if err != nil {
				t.Fatalf("failed to open fixture: %+v", err)
			}

			fileResolver := newTestFileResolver(test.ignorePaths)

			actual, err := parseRpmDB(fileResolver, fixture)
			if err != nil {
				t.Fatalf("failed to parse rpmdb: %+v", err)
			}

			if len(actual) != len(test.expected) {
				for _, a := range actual {
					t.Log("   ", a)
				}
				t.Fatalf("unexpected package count: %d!=%d", len(actual), len(test.expected))
			}

			for _, a := range actual {
				e := test.expected[a.Name]
				diffs := deep.Equal(a, e)
				if len(diffs) > 0 {
					for _, d := range diffs {
						t.Errorf("diff: %+v", d)
					}
				}
			}
		})
	}

}
