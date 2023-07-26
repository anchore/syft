package spdxjson

import (
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/pkg"
)

func TestSPDXJSONDecoder(t *testing.T) {
	tests := []struct {
		path          string
		fail          bool
		packages      []string
		relationships []string
	}{
		{
			path:          "alpine-3.10.syft.spdx.json",
			packages:      []string{"busybox", "libssl1.1", "ssl_client"},
			relationships: []string{"busybox", "busybox", "libssl1.1", "libssl1.1"},
		},
		{
			path:          "alpine-3.10.vendor.spdx.json",
			packages:      []string{"alpine", "busybox", "ssl_client"},
			relationships: []string{},
		},
		{
			path: "example7-bin.spdx.json",
		},
		{
			path: "example7-go-module.spdx.json",
		},
		{
			path: "example7-golang.spdx.json",
		},
		{
			path: "example7-third-party-modules.spdx.json",
		},
		{
			path: "bad/example7-bin.spdx.json",
			fail: true,
		},
		{
			path: "bad/example7-go-module.spdx.json",
			fail: true,
		},
		{
			path: "bad/example7-golang.spdx.json",
			fail: true,
		},
		{
			path: "bad/example7-third-party-modules.spdx.json",
			fail: true,
		},
	}

	for _, test := range tests {
		t.Run(test.path, func(t *testing.T) {
			f, err := os.Open("test-fixtures/spdx/" + test.path)
			require.NoError(t, err)

			sbom, err := decoder(f)

			if test.fail {
				require.Error(t, err)
				return
			} else {
				require.NoError(t, err)
			}

			if test.packages != nil {
				assert.Equal(t, sbom.Artifacts.Packages.PackageCount(), len(test.packages))

			packages:
				for _, pkgName := range test.packages {
					for _, p := range sbom.Artifacts.Packages.Sorted() {
						if p.Name == pkgName {
							continue packages
						}
					}
					assert.NoError(t, fmt.Errorf("Unable to find package: %s", pkgName))
				}
			}

			if test.relationships != nil {
				assert.Len(t, sbom.Relationships, len(test.relationships))

			relationships:
				for _, pkgName := range test.relationships {
					for _, rel := range sbom.Relationships {
						p, ok := rel.From.(pkg.Package)
						if ok && p.Name == pkgName {
							continue relationships
						}
					}
					assert.NoError(t, fmt.Errorf("Unable to find relationship: %s", pkgName))
				}
			}
		})
	}
}
