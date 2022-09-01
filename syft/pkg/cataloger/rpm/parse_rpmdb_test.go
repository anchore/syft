package rpm

import (
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/file"

	"github.com/anchore/syft/syft/source"

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

func (r rpmdbTestFileResolverMock) HasPath(path string) bool {
	return !r.ignorePaths
}

func (r *rpmdbTestFileResolverMock) FilesByPath(paths ...string) ([]source.Location, error) {
	if r.ignorePaths {
		// act as if no paths exist
		return nil, nil
	}
	// act as if all files exist
	var locations = make([]source.Location, len(paths))
	for i, p := range paths {
		locations[i] = source.NewLocation(p)
	}
	return locations, nil
}

func (r *rpmdbTestFileResolverMock) FilesByGlob(...string) ([]source.Location, error) {
	return nil, fmt.Errorf("not implemented")
}

func (r *rpmdbTestFileResolverMock) RelativeFileByPath(source.Location, string) *source.Location {
	panic(fmt.Errorf("not implemented"))
	return nil
}

func (r *rpmdbTestFileResolverMock) FilesByMIMEType(...string) ([]source.Location, error) {
	return nil, fmt.Errorf("not implemented")
}

func TestParseRpmDB(t *testing.T) {
	dbLocation := source.NewLocation("test-path")

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
					Locations:    source.NewLocationSet(dbLocation),
					FoundBy:      dbCatalogerName,
					Type:         pkg.RpmPkg,
					MetadataType: pkg.RpmdbMetadataType,
					Licenses:     []string{"MIT"},
					Metadata: pkg.RpmdbMetadata{
						Name:      "dive",
						Epoch:     nil,
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
					Locations:    source.NewLocationSet(dbLocation),
					FoundBy:      dbCatalogerName,
					Type:         pkg.RpmPkg,
					MetadataType: pkg.RpmdbMetadataType,
					Licenses:     []string{"MIT"},
					Metadata: pkg.RpmdbMetadata{
						Name:      "dive",
						Epoch:     nil,
						Arch:      "x86_64",
						Release:   "1",
						Version:   "0.9.2",
						SourceRpm: "dive-0.9.2-1.src.rpm",
						Size:      12406784,
						License:   "MIT",
						Vendor:    "",
						Files: []pkg.RpmdbFileRecord{
							{
								Path: "/usr/local/bin/dive",
								Mode: 33261,
								Size: 12406784,
								Digest: file.Digest{
									Algorithm: "sha256",
									Value:     "81d29f327ba23096b3c52ff6fe1c425641e618bc87b5c05ee377edc650afaa55",
								},
								// note: there is no username, groupname, or flags for this RPM
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

			actual, err := parseRpmDB(fileResolver, dbLocation, fixture)
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

func TestToElVersion(t *testing.T) {
	tests := []struct {
		name     string
		entry    pkg.RpmdbMetadata
		expected string
	}{
		{
			name: "no epoch",
			entry: pkg.RpmdbMetadata{
				Version: "1.2.3-4",
				Release: "el7",
				Arch:    "x86-64",
			},
			expected: "1.2.3-4-el7",
		},
		{
			name: "with 0 epoch",
			entry: pkg.RpmdbMetadata{
				Version: "1.2.3-4",
				Release: "el7",
				Arch:    "x86-64",
				Epoch:   intRef(0),
			},
			expected: "0:1.2.3-4-el7",
		},
		{
			name: "with non-zero epoch",
			entry: pkg.RpmdbMetadata{
				Version: "1.2.3-4",
				Release: "el7",
				Arch:    "x86-64",
				Epoch:   intRef(12),
			},
			expected: "12:1.2.3-4-el7",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, toELVersion(test.entry))
		})
	}
}

func intRef(i int) *int {
	return &i
}
