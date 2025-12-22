package integration

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

func TestPackageDeduplication(t *testing.T) {
	// this test verifies that package deduplication works correctly across layers.
	// The test fixture installs/upgrades packages in multiple stages, creating
	// duplicate RPM DB entries across layers. Without deduplication, we'd see ~600 packages.
	//
	// Note: we index by package name (not name-version) to be resilient to Rocky Linux
	// repo updates. Location counts are summed across all versions of each package.
	tests := []struct {
		scope         source.Scope
		packageCount  int
		instanceCount map[string]int // how many distinct package instances (by name)
		locationCount map[string]int // total locations across ALL versions of each package
	}{
		{
			scope:        source.AllLayersScope,
			packageCount: 176, // without deduplication this would be ~600
			instanceCount: map[string]int{
				"basesystem":   1,
				"wget":         1,
				"curl-minimal": 2, // base + upgraded (2 different versions)
				"vsftpd":       1,
				"httpd":        1,
			},
			locationCount: map[string]int{
				"basesystem":   5, // in all layers
				"curl-minimal": 5, // total across both versions (2 + 3)
				"wget":         4, // wget + all above layers
				"vsftpd":       2, // vsftpd + all above layers
				"httpd":        1, // last layer
			},
		},
		{
			scope:        source.SquashedScope,
			packageCount: 170,
			instanceCount: map[string]int{
				"basesystem":   1,
				"wget":         1,
				"curl-minimal": 1, // deduped to latest
				"vsftpd":       1,
				"httpd":        1,
			},
			locationCount: map[string]int{
				"basesystem":   1,
				"curl-minimal": 1,
				"wget":         1,
				"vsftpd":       1,
				"httpd":        1,
			},
		},
	}

	for _, tt := range tests {
		t.Run(string(tt.scope), func(t *testing.T) {
			sbom, _ := catalogFixtureImage(t, "image-vertical-package-dups", tt.scope)

			// verify binary packages have names
			for _, p := range sbom.Artifacts.Packages.Sorted() {
				if p.Type == pkg.BinaryPkg {
					assert.NotEmpty(t, p.Name)
				}
			}

			// verify exact package count
			assert.Equal(t, tt.packageCount, sbom.Artifacts.Packages.PackageCount())

			// verify instance count by package name
			for name, expectedCount := range tt.instanceCount {
				pkgs := sbom.Artifacts.Packages.PackagesByName(name)
				assert.Len(t, pkgs, expectedCount, "unexpected instance count for %s", name)
			}

			// verify total location count across all versions of each package
			for name, expectedLocCount := range tt.locationCount {
				pkgs := sbom.Artifacts.Packages.PackagesByName(name)
				totalLocations := 0
				for _, p := range pkgs {
					totalLocations += len(p.Locations.ToSlice())
				}
				assert.Equal(t, expectedLocCount, totalLocations, "unexpected total location count for %s", name)
			}
		})
	}
}
