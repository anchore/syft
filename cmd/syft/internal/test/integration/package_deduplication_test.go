package integration

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

func TestPackageDeduplication(t *testing.T) {
	tests := []struct {
		scope         source.Scope
		packageCount  int
		instanceCount map[string]int
		locationCount map[string]int
	}{
		{
			scope:        source.AllLayersScope,
			packageCount: 178, // without deduplication this would be ~600
			instanceCount: map[string]int{
				"basesystem":   1,
				"wget":         1,
				"curl-minimal": 2, // upgraded in the image
				"vsftpd":       1,
				"httpd":        1, // rpm, - we exclude binary
			},
			locationCount: map[string]int{
				"basesystem-11-13.el9":               5, // in all layers
				"curl-minimal-7.76.1-26.el9_3.2.0.1": 2, // base + wget layer
				"curl-minimal-7.76.1-29.el9_4.1":     3, // curl upgrade layer + all above layers
				"wget-1.21.1-8.el9_4":                4, // wget + all above layers
				"vsftpd-3.0.5-5.el9":                 2, // vsftpd + all above layers
				"httpd-2.4.57-11.el9_4.1":            1, // last layer
			},
		},
		{
			scope:        source.SquashedScope,
			packageCount: 172,
			instanceCount: map[string]int{
				"basesystem":   1,
				"wget":         1,
				"curl-minimal": 1, // upgraded, but the most recent
				"vsftpd":       1,
				"httpd":        1, // rpm, binary is now excluded by overlap
			},
			locationCount: map[string]int{
				"basesystem-11-13.el9":           1,
				"curl-minimal-7.76.1-29.el9_4.1": 1, // upgrade
				"wget-1.21.1-8.el9_4":            1,
				"vsftpd-3.0.5-5.el9":             1,
				"httpd-2.4.57-11.el9_4.1":        1,
			},
		},
	}

	for _, tt := range tests {
		t.Run(string(tt.scope), func(t *testing.T) {
			sbom, _ := catalogFixtureImage(t, "image-vertical-package-dups", tt.scope)
			for _, p := range sbom.Artifacts.Packages.Sorted() {
				if p.Type == pkg.BinaryPkg {
					assert.NotEmpty(t, p.Name)
				}
			}

			assert.Equal(t, tt.packageCount, sbom.Artifacts.Packages.PackageCount())
			for name, expectedInstanceCount := range tt.instanceCount {
				pkgs := sbom.Artifacts.Packages.PackagesByName(name)

				// with multiple packages with the same name, something is wrong (or this is the wrong fixture)
				if assert.Len(t, pkgs, expectedInstanceCount, "unexpected package count for %s", name) {
					for _, p := range pkgs {
						nameVersion := fmt.Sprintf("%s-%s", name, p.Version)
						expectedLocationCount, ok := tt.locationCount[nameVersion]
						if !ok {
							t.Errorf("missing name-version: %s", nameVersion)
							continue
						}

						// we should see merged locations (assumption, there was 1 location for each package)
						assert.Len(t, p.Locations.ToSlice(), expectedLocationCount, "unexpected location count for %s", nameVersion)

						// all paths should match
						assert.Len(t, p.Locations.CoordinateSet().Paths(), 1, "unexpected location count for %s", nameVersion)
					}
				}
			}

		})
	}
}
