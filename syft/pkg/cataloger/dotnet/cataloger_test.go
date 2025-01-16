package dotnet

import (
	"github.com/anchore/syft/syft/file"
	"testing"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func TestCataloger_Globs(t *testing.T) {
	tests := []struct {
		name      string
		fixture   string
		cataloger pkg.Cataloger
		expected  []string
	}{
		{
			name:      "obtain deps.json files",
			fixture:   "test-fixtures/glob-paths",
			cataloger: NewDotnetDepsCataloger(),
			expected: []string{
				"src/something.deps.json",
			},
		},
		{
			name:      "obtain portable executable files",
			fixture:   "test-fixtures/glob-paths",
			cataloger: NewDotnetPortableExecutableCataloger(),
			expected: []string{
				"src/something.dll",
				"src/something.exe",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pkgtest.NewCatalogTester().
				FromDirectory(t, test.fixture).
				ExpectsResolverContentQueries(test.expected).
				TestCataloger(t, test.cataloger)
		})
	}
}

func Test_ELF_Package_Cataloger(t *testing.T) {

	cases := []struct {
		name     string
		fixture  string
		expected []pkg.Package
	}{
		{
			name:    "go case",
			fixture: "image-net8-app",
			expected: []pkg.Package{
				{
					Name:    "Humanizer (net6.0)",
					Version: "2.14.1.48190",
					Locations: file.NewLocationSet(
						file.NewVirtualLocation("/app/lib.dll", "/app/lib.dll"),
					),
					Licenses: pkg.NewLicenseSet(
						pkg.License{Value: "MIT", SPDXExpression: "MIT", Type: "declared"},
					),

					Type:     pkg.DotnetPkg,
					Metadata: pkg.DotnetPortableExecutableEntry{},
				},
				{
					Name:    "Humanizer (net6.0)",
					Version: "2.14.1.48190",
					Locations: file.NewLocationSet(
						file.NewVirtualLocation("/app/lib.dll", "/app/lib.dll"),
					),
					Licenses: pkg.NewLicenseSet(
						pkg.License{Value: "MIT", SPDXExpression: "MIT", Type: "declared"},
					),

					Type:     pkg.DotnetPkg,
					Metadata: pkg.DotnetPortableExecutableEntry{},
				},
				{
					Name:    "Humanizer (netstandard2.0)",
					Version: "2.14.1.48190",
					Locations: file.NewLocationSet(
						file.NewVirtualLocation("/app/lib.dll", "/app/lib.dll"),
					),
					Licenses: pkg.NewLicenseSet(
						pkg.License{Value: "MIT", SPDXExpression: "MIT", Type: "declared"},
					),

					Type:     pkg.DotnetPkg,
					Metadata: pkg.DotnetPortableExecutableEntry{},
				},
				{
					Name:    "Json.NET .NET 6.0",
					Version: "13.0.3.27908",
					Locations: file.NewLocationSet(
						file.NewVirtualLocation("/app/lib.dll", "/app/lib.dll"),
					),
					Licenses: pkg.NewLicenseSet(
						pkg.License{Value: "MIT", SPDXExpression: "MIT", Type: "declared"},
					),

					Type:     pkg.DotnetPkg,
					Metadata: pkg.DotnetPortableExecutableEntry{},
				},
				{
					Name:    "dotnetapp",
					Version: "1.0.0.0",
					Locations: file.NewLocationSet(
						file.NewVirtualLocation("/app/lib.dll", "/app/lib.dll"),
					),
					Licenses: pkg.NewLicenseSet(
						pkg.License{Value: "MIT", SPDXExpression: "MIT", Type: "declared"},
					),

					Type:     pkg.DotnetPkg,
					Metadata: pkg.DotnetPortableExecutableEntry{},
				},
			},
		},
	}

	for _, v := range cases {
		t.Run(v.name, func(t *testing.T) {
			//for i := range v.expected {
			//	p := &v.expected[i]
			//	p.SetID()
			//}
			pkgtest.NewCatalogTester().
				WithImageResolver(t, v.fixture).
				IgnoreLocationLayer(). // this fixture can be rebuilt, thus the layer ID will change
				Expects(v.expected, nil).
				TestCataloger(t, NewDotnetPortableExecutableCataloger())
		})
	}

}
