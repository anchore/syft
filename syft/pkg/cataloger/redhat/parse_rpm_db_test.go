package redhat

import (
	"context"
	"fmt"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

var _ file.Resolver = (*rpmdbTestFileResolverMock)(nil)

type rpmdbTestFileResolverMock struct {
	ignorePaths bool
}

func (r rpmdbTestFileResolverMock) FilesByExtension(extensions ...string) ([]file.Location, error) {
	panic("not implemented")
}

func (r rpmdbTestFileResolverMock) FilesByBasename(filenames ...string) ([]file.Location, error) {
	panic("not implemented")
}

func (r rpmdbTestFileResolverMock) FilesByBasenameGlob(globs ...string) ([]file.Location, error) {
	panic("not implemented")
}

func (r rpmdbTestFileResolverMock) FileContentsByLocation(location file.Location) (io.ReadCloser, error) {
	panic("not implemented")
}

func (r rpmdbTestFileResolverMock) AllLocations(_ context.Context) <-chan file.Location {
	panic("not implemented")
}

func (r rpmdbTestFileResolverMock) FileMetadataByLocation(location file.Location) (file.Metadata, error) {
	panic("not implemented")
}

func newTestFileResolver(ignorePaths bool) *rpmdbTestFileResolverMock {
	return &rpmdbTestFileResolverMock{
		ignorePaths: ignorePaths,
	}
}

func (r rpmdbTestFileResolverMock) HasPath(path string) bool {
	return !r.ignorePaths
}

func (r *rpmdbTestFileResolverMock) FilesByPath(paths ...string) ([]file.Location, error) {
	if r.ignorePaths {
		// act as if no paths exist
		return nil, nil
	}
	// act as if all files exist
	var locations = make([]file.Location, len(paths))
	for i, p := range paths {
		locations[i] = file.NewLocation(p)
	}
	return locations, nil
}

func (r *rpmdbTestFileResolverMock) FilesByGlob(...string) ([]file.Location, error) {
	return nil, fmt.Errorf("not implemented")
}

func (r *rpmdbTestFileResolverMock) RelativeFileByPath(file.Location, string) *file.Location {
	panic(fmt.Errorf("not implemented"))
	return nil
}

func (r *rpmdbTestFileResolverMock) FilesByMIMEType(...string) ([]file.Location, error) {
	return nil, fmt.Errorf("not implemented")
}

func TestParseRpmDB(t *testing.T) {
	packagesLocation := file.NewLocation("test-fixtures/Packages")
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
					Name:      "dive",
					Version:   "0.9.2-1",
					PURL:      "pkg:rpm/dive@0.9.2-1?arch=x86_64&upstream=dive-0.9.2-1.src.rpm",
					Locations: file.NewLocationSet(file.NewLocation("test-fixtures/Packages")),
					Type:      pkg.RpmPkg,
					Licenses: pkg.NewLicenseSet(
						pkg.NewLicenseFromLocations("MIT", packagesLocation),
					),
					Metadata: pkg.RpmDBEntry{
						Name:            "dive",
						Epoch:           nil,
						Arch:            "x86_64",
						Release:         "1",
						Version:         "0.9.2",
						SourceRpm:       "dive-0.9.2-1.src.rpm",
						Size:            12406784,
						Vendor:          "",
						ModularityLabel: strRef(""),
						Provides:        []string{"dive"},
						Files:           []pkg.RpmFileRecord{},
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
					Name:      "dive",
					Version:   "0.9.2-1",
					PURL:      "pkg:rpm/dive@0.9.2-1?arch=x86_64&upstream=dive-0.9.2-1.src.rpm",
					Locations: file.NewLocationSet(packagesLocation),
					Type:      pkg.RpmPkg,
					Licenses: pkg.NewLicenseSet(
						pkg.NewLicenseFromLocations("MIT", packagesLocation),
					),
					Metadata: pkg.RpmDBEntry{
						Name:            "dive",
						Epoch:           nil,
						Arch:            "x86_64",
						Release:         "1",
						Version:         "0.9.2",
						SourceRpm:       "dive-0.9.2-1.src.rpm",
						Size:            12406784,
						Vendor:          "",
						ModularityLabel: strRef(""),
						Provides:        []string{"dive"},
						Files: []pkg.RpmFileRecord{
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
		entry    pkg.RpmDBEntry
		expected string
	}{
		{
			name: "no epoch",
			entry: pkg.RpmDBEntry{
				Version: "1.2.3-4",
				Release: "el7",
				Arch:    "x86-64",
			},
			expected: "1.2.3-4-el7",
		},
		{
			name: "with 0 epoch",
			entry: pkg.RpmDBEntry{
				Version: "1.2.3-4",
				Release: "el7",
				Arch:    "x86-64",
				Epoch:   intRef(0),
			},
			expected: "0:1.2.3-4-el7",
		},
		{
			name: "with non-zero epoch",
			entry: pkg.RpmDBEntry{
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
			assert.Equal(t, test.expected, toELVersion(test.entry.Epoch, test.entry.Version, test.entry.Release))
		})
	}
}

func Test_corruptRpmDbEntry(t *testing.T) {
	pkgtest.NewCatalogTester().
		FromFile(t, "test-fixtures/glob-paths/usr/lib/sysimage/rpm/Packages.db").
		WithError().
		TestParser(t, parseRpmDB)
}

func intRef(i int) *int {
	return &i
}

func strRef(s string) *string {
	return &s
}
