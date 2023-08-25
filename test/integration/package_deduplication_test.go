//go:build !arm64

package integration

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
			packageCount: 172, // without deduplication this would be 618
			instanceCount: map[string]int{
				"basesystem": 1,
				"wget":       1,
				"curl":       2, // upgraded in the image
				"vsftpd":     1,
				"httpd":      1, // rpm, - we exclude binary
			},
			locationCount: map[string]int{
				"basesystem-10.0-7.el7.centos": 4,
				"curl-7.29.0-59.el7":           1, // from base image
				"curl-7.29.0-59.el7_9.1":       3, // upgrade
				"wget-1.14-18.el7_6.1":         3,
				"vsftpd-3.0.2-29.el7_9":        2,
				"httpd-2.4.6-97.el7.centos.5":  1,
				// "httpd-2.4.6":                  1, // binary
			},
		},
		{
			scope:        source.SquashedScope,
			packageCount: 170,
			instanceCount: map[string]int{
				"basesystem": 1,
				"wget":       1,
				"curl":       1, // upgraded, but the most recent
				"vsftpd":     1,
				"httpd":      1, // rpm, binary is now excluded by overlap
			},
			locationCount: map[string]int{
				"basesystem-10.0-7.el7.centos": 1,
				"curl-7.29.0-59.el7_9.1":       1, // upgrade
				"wget-1.14-18.el7_6.1":         1,
				"vsftpd-3.0.2-29.el7_9":        1,
				"httpd-2.4.6-97.el7.centos.5":  1,
				// "httpd-2.4.6":                  1, // binary (excluded)
			},
		},
	}

	for _, tt := range tests {
		t.Run(string(tt.scope), func(t *testing.T) {
			sbom, _ := catalogFixtureImage(t, "image-vertical-package-dups", tt.scope, nil)
			for _, p := range sbom.Artifacts.Packages.Sorted() {
				if p.Type == pkg.BinaryPkg {
					assert.NotEmpty(t, p.Name)
				}
			}

			assert.Equal(t, tt.packageCount, sbom.Artifacts.Packages.PackageCount())
			for name, expectedInstanceCount := range tt.instanceCount {
				pkgs := sbom.Artifacts.Packages.PackagesByName(name)

				// with multiple packages with the same name, something is wrong (or this is the wrong fixture)
				require.Len(t, pkgs, expectedInstanceCount)

				for _, p := range pkgs {
					nameVersion := fmt.Sprintf("%s-%s", name, p.Version)
					expectedLocationCount, ok := tt.locationCount[nameVersion]
					if !ok {
						t.Fatalf("missing name-version: %s", nameVersion)
					}

					// we should see merged locations (assumption, there was 1 location for each package)
					assert.Len(t, p.Locations.ToSlice(), expectedLocationCount)

					// all paths should match
					assert.Len(t, p.Locations.CoordinateSet().Paths(), 1)
				}
			}

		})
	}
}
