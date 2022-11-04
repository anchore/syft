package rpm

import (
	"fmt"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
	"github.com/anchore/syft/syft/source"
)

var _ source.FileResolver = (*rpmdbTestFileResolverMock)(nil)

type rpmdbTestFileResolverMock struct {
	ignorePaths bool
}

func (r rpmdbTestFileResolverMock) FileContentsByLocation(location source.Location) (io.ReadCloser, error) {
	//TODO implement me
	panic("implement me")
}

func (r rpmdbTestFileResolverMock) AllLocations() <-chan source.Location {
	//TODO implement me
	panic("implement me")
}

func (r rpmdbTestFileResolverMock) FileMetadataByLocation(location source.Location) (source.FileMetadata, error) {
	//TODO implement me
	panic("implement me")
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
	tests := []struct {
		fixture     string
		expected    []pkg.Package
		ignorePaths bool
	}{
		{
			fixture: "test-fixtures/Packages",
			// we only surface package paths for files that exist (here we DO NOT expect a path)
			ignorePaths: true,
			expected: []pkg.Package{
				{
					Name:         "dive",
					Version:      "0.9.2-1",
					PURL:         "pkg:rpm/dive@0.9.2-1?arch=x86_64&upstream=dive-0.9.2-1.src.rpm",
					Locations:    source.NewLocationSet(source.NewLocation("test-fixtures/Packages")),
					Type:         pkg.RpmPkg,
					MetadataType: pkg.RpmMetadataType,
					Licenses:     []string{"MIT"},
					Metadata: pkg.RpmMetadata{
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
			expected: []pkg.Package{
				{
					Name:         "dive",
					Version:      "0.9.2-1",
					PURL:         "pkg:rpm/dive@0.9.2-1?arch=x86_64&upstream=dive-0.9.2-1.src.rpm",
					Locations:    source.NewLocationSet(source.NewLocation("test-fixtures/Packages")),
					Type:         pkg.RpmPkg,
					MetadataType: pkg.RpmMetadataType,
					Licenses:     []string{"MIT"},
					Metadata: pkg.RpmMetadata{
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
			pkgtest.NewCatalogTester().
				WithResolver(newTestFileResolver(test.ignorePaths)).
				FromFile(t, test.fixture).
				Expects(test.expected, nil).
				TestParser(t, parseRpmDB)
		})
	}

}

func TestToElVersion(t *testing.T) {
	tests := []struct {
		name     string
		entry    pkg.RpmMetadata
		expected string
	}{
		{
			name: "no epoch",
			entry: pkg.RpmMetadata{
				Version: "1.2.3-4",
				Release: "el7",
				Arch:    "x86-64",
			},
			expected: "1.2.3-4-el7",
		},
		{
			name: "with 0 epoch",
			entry: pkg.RpmMetadata{
				Version: "1.2.3-4",
				Release: "el7",
				Arch:    "x86-64",
				Epoch:   intRef(0),
			},
			expected: "0:1.2.3-4-el7",
		},
		{
			name: "with non-zero epoch",
			entry: pkg.RpmMetadata{
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
