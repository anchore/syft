package golang

import (
	"testing"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
	"github.com/anchore/syft/syft/source"
)

func TestParseGoMod(t *testing.T) {
	tests := []struct {
		fixture  string
		expected []pkg.Package
	}{
		{
			fixture: "test-fixtures/one-package",
			expected: []pkg.Package{
				{
					Name:      "github.com/bmatcuk/doublestar",
					Version:   "v1.3.1",
					PURL:      "pkg:golang/github.com/bmatcuk/doublestar@v1.3.1",
					Locations: source.NewLocationSet(source.NewLocation("test-fixtures/one-package")),
					Language:  pkg.Go,
					Type:      pkg.GoModulePkg,
				},
			},
		},
		{

			fixture: "test-fixtures/many-packages",
			expected: []pkg.Package{
				{
					Name:      "github.com/anchore/go-testutils",
					Version:   "v0.0.0-20200624184116-66aa578126db",
					PURL:      "pkg:golang/github.com/anchore/go-testutils@v0.0.0-20200624184116-66aa578126db",
					Locations: source.NewLocationSet(source.NewLocation("test-fixtures/many-packages")),
					Language:  pkg.Go,
					Type:      pkg.GoModulePkg,
				},
				{
					Name:      "github.com/anchore/go-version",
					Version:   "v1.2.2-0.20200701162849-18adb9c92b9b",
					PURL:      "pkg:golang/github.com/anchore/go-version@v1.2.2-0.20200701162849-18adb9c92b9b",
					Locations: source.NewLocationSet(source.NewLocation("test-fixtures/many-packages")),
					Language:  pkg.Go,
					Type:      pkg.GoModulePkg,
				},
				{
					Name:      "github.com/anchore/stereoscope",
					Version:   "v0.0.0-20200706164556-7cf39d7f4639",
					PURL:      "pkg:golang/github.com/anchore/stereoscope@v0.0.0-20200706164556-7cf39d7f4639",
					Locations: source.NewLocationSet(source.NewLocation("test-fixtures/many-packages")),
					Language:  pkg.Go,
					Type:      pkg.GoModulePkg,
				},
				{
					Name:      "github.com/bmatcuk/doublestar",
					Version:   "v8.8.8",
					PURL:      "pkg:golang/github.com/bmatcuk/doublestar@v8.8.8",
					Locations: source.NewLocationSet(source.NewLocation("test-fixtures/many-packages")),
					Language:  pkg.Go,
					Type:      pkg.GoModulePkg,
				},
				{
					Name:      "github.com/go-test/deep",
					Version:   "v1.0.6",
					PURL:      "pkg:golang/github.com/go-test/deep@v1.0.6",
					Locations: source.NewLocationSet(source.NewLocation("test-fixtures/many-packages")),
					Language:  pkg.Go,
					Type:      pkg.GoModulePkg,
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.fixture, func(t *testing.T) {
			pkgtest.NewCatalogTester().
				FromFile(t, test.fixture).
				Expects(test.expected, nil).
				TestParser(t, parseGoModFile)
		})
	}
}
