package licenses

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/internal/licenses"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/internal/fileresolver"
	"github.com/anchore/syft/syft/pkg"
)

// scanner is used by all tests
var scanner = getScanner()

func Test_FindRelativeLicenses(t *testing.T) {
	resolver := fileresolver.NewFromUnindexedDirectory("testdata")
	sourceTxtResolved, err := resolver.FilesByPath("source.txt")
	require.NoError(t, err)

	sourceTxt := file.NewLocationSet(sourceTxtResolved[0].WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation))

	tests := []struct {
		name     string
		resolver file.Resolver
		p        pkg.Package
		expected pkg.LicenseSet
	}{
		{
			name:     "existing license",
			resolver: resolver,
			p: pkg.Package{
				Locations: sourceTxt,
				Licenses:  pkg.NewLicenseSet(pkg.NewLicense("GPL-2.0")),
			},
			expected: pkg.NewLicenseSet(pkg.NewLicense("GPL-2.0")),
		},
		{
			name:     "no licenses",
			resolver: fileresolver.Empty{},
			p: pkg.Package{
				Locations: sourceTxt,
			},
			expected: pkg.NewLicenseSet(),
		},
		{
			name:     "found relative license",
			resolver: resolver,
			p: pkg.Package{
				Locations: sourceTxt,
			},
			expected: pkg.NewLicenseSet(pkg.NewLicense("MIT")),
		},
	}

	ctx := context.TODO()
	ctx = licenses.SetContextLicenseScanner(ctx, scanner)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := RelativeToPackage(ctx, tt.resolver, tt.p)
			require.Equal(t, licenseNames(tt.expected.ToSlice()), licenseNames(got.Licenses.ToSlice()))
		})
	}
}

func Test_Finders(t *testing.T) {
	resolver := fileresolver.NewFromUnindexedDirectory("testdata")

	// prepare context with license scanner
	ctx := context.TODO()
	ctx = licenses.SetContextLicenseScanner(ctx, scanner)

	// resolve known files
	licenseLocs, err := resolver.FilesByPath("LICENSE")
	require.NoError(t, err)
	require.NotEmpty(t, licenseLocs)
	licenseLoc := licenseLocs[0]

	sourceLocs, err := resolver.FilesByPath("source.txt")
	require.NoError(t, err)
	require.NotEmpty(t, sourceLocs)
	sourceLoc := sourceLocs[0]

	tests := []struct {
		name     string
		finder   func(t *testing.T) []pkg.License
		expected []string
	}{
		{
			name: "FindAtLocations finds LICENSE content",
			finder: func(t *testing.T) []pkg.License {
				return FindAtLocations(ctx, resolver, licenseLoc)
			},
			expected: []string{"MIT"},
		},
		{
			name: "FindAtLocations with empty resolver returns none",
			finder: func(t *testing.T) []pkg.License {
				return FindAtLocations(ctx, fileresolver.Empty{}, licenseLoc)
			},
		},
		{
			name: "FindAtPaths finds LICENSE by path",
			finder: func(t *testing.T) []pkg.License {
				return FindAtPaths(ctx, resolver, "LICENSE")
			},
			expected: []string{"MIT"},
		},
		{
			name: "FindInDirs finds LICENSE in directory",
			finder: func(t *testing.T) []pkg.License {
				return FindInDirs(ctx, resolver, ".")
			},
			expected: []string{"MIT"},
		},
		{
			name: "FindRelativeToLocations finds LICENSE relative to source.txt",
			finder: func(t *testing.T) []pkg.License {
				return FindRelativeToLocations(ctx, resolver, sourceLoc)
			},
			expected: []string{"MIT"},
		},
		{
			name: "FindByGlob finds LICENSE with glob",
			finder: func(t *testing.T) []pkg.License {
				return FindByGlob(ctx, resolver, "*")
			},
			expected: []string{"MIT"},
		},
		{
			name: "FindByGlob finds LICENSE with recursive glob",
			finder: func(t *testing.T) []pkg.License {
				return FindByGlob(ctx, resolver, "**/*")
			},
			expected: []string{"MIT"},
		},
		{
			name: "NewFromValues with locations returns license values",
			finder: func(t *testing.T) []pkg.License {
				return NewFromValues(ctx, []file.Location{licenseLoc}, "MIT")
			},
			expected: []string{"MIT"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.finder(t)
			require.Equal(t, tt.expected, licenseNames(got))
		})
	}
}

func licenseNames(slice []pkg.License) []string {
	var out []string
	for _, l := range slice {
		out = append(out, l.SPDXExpression)
	}
	return out
}

func getScanner() licenses.Scanner {
	s, err := licenses.NewDefaultScanner()
	if err != nil {
		panic(err)
	}
	return s
}
