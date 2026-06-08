package binary

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func Test_PEPackageCataloger(t *testing.T) {
	cases := []struct {
		name     string
		fixture  string
		expected []pkg.Package
		wantErr  require.ErrorAssertionFunc
	}{
		{
			name:    "non-.NET package",
			fixture: "image-jruby",
			expected: []pkg.Package{
				{
					Name:    "JRuby",
					Version: "9.3.15.0",
					Type:    pkg.BinaryPkg,
					Locations: file.NewLocationSet(
						file.NewLocation("/jruby_windows_9_3_15_0.exe"),
					),
					FoundBy: "pe-binary-package-cataloger",
					Metadata: pkg.PEBinary{
						VersionResources: pkg.KeyValues{
							{Key: "CompanyName", Value: "JRuby Dev Team"},
							{Key: "FileDescription", Value: "JRuby"},
							{Key: "FileVersion", Value: "9.3.15.0"},
							{Key: "InternalName", Value: "jruby"},
							{Key: "LegalCopyright", Value: "JRuby Dev Team"},
							{Key: "OriginalFilename", Value: "jruby_windows-x32_9_3_15_0.exe"},
							{Key: "ProductName", Value: "JRuby"},
							{Key: "ProductVersion", Value: "9.3.15.0"},
						},
					},
				},
			},
		},
		{
			name:     "ignore .NET packages",
			fixture:  "image-dotnet-app",
			expected: nil, // expect nothing!
		},
	}

	for _, v := range cases {
		t.Run(v.name, func(t *testing.T) {
			pkgtest.NewCatalogTester().
				WithImageResolver(t, v.fixture).
				IgnoreLocationLayer(). // this fixture can be rebuilt, thus the layer ID will change
				Expects(v.expected, nil).
				TestCataloger(t, NewPEPackageCataloger())
		})
	}

}

func Test_PEPackageCataloger_Globs(t *testing.T) {
	tests := []struct {
		name     string
		fixture  string
		expected []string
	}{
		{
			name:    "obtain PE binary files (dll, exe, bpl)",
			fixture: "testdata/glob-paths",
			expected: []string{
				"src/library.dll",
				"src/program.exe",
				"src/archive.bpl",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pkgtest.NewCatalogTester().
				FromDirectory(t, test.fixture).
				ExpectsResolverContentQueries(test.expected).
				TestCataloger(t, NewPEPackageCataloger())
		})
	}
}
