package spdxjson

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
)

func TestDecoder_Decode(t *testing.T) {
	tests := []struct {
		name          string
		fail          bool
		id            sbom.FormatID
		version       string
		packages      []string
		relationships []string
	}{
		{
			name:          "alpine-3.10.syft.spdx.json",
			id:            ID,
			version:       "2.2",
			packages:      []string{"busybox", "libssl1.1", "ssl_client"},
			relationships: []string{"busybox", "busybox", "libssl1.1", "libssl1.1"},
		},
		{
			name:          "alpine-3.10.vendor.spdx.json",
			id:            ID,
			version:       "2.2",
			packages:      []string{"alpine", "busybox", "ssl_client"},
			relationships: []string{},
		},
		{
			name:    "example7-bin.spdx.json",
			id:      ID,
			version: "2.2",
		},
		{
			name:    "example7-go-module.spdx.json",
			id:      ID,
			version: "2.2",
		},
		{
			name:    "example7-golang.spdx.json",
			id:      ID,
			version: "2.2",
		},
		{
			name:    "example7-third-party-modules.spdx.json",
			id:      ID,
			version: "2.2",
		},
		{
			name:    "bad/example7-bin.spdx.json",
			id:      ID,
			version: "2.2",
			fail:    true,
		},
		{
			name:    "bad/example7-go-module.spdx.json",
			id:      ID,
			version: "2.2",
			fail:    true,
		},
		{
			name:    "bad/example7-golang.spdx.json",
			id:      ID,
			version: "2.2",
			fail:    true,
		},
		{
			name:    "bad/example7-third-party-modules.spdx.json",
			id:      ID,
			version: "2.2",
			fail:    true,
		},
		{
			name: "bad/bad-sbom",
			fail: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reader, err := os.Open(filepath.Join("test-fixtures", "spdx", test.name))
			require.NoError(t, err)

			dec := NewFormatDecoder()

			formatID, formatVersion := dec.Identify(reader)
			if test.fail {
				assert.Equal(t, test.id, formatID)
				assert.Equal(t, test.version, formatVersion)

				_, decodeID, decodeVersion, err := dec.Decode(reader)
				require.Error(t, err)
				assert.Equal(t, test.id, decodeID)
				assert.Equal(t, test.version, decodeVersion)

				return
			}
			assert.Equal(t, test.id, formatID)
			assert.Equal(t, test.version, formatVersion)

			s, decodeID, decodeVersion, err := dec.Decode(reader)

			require.NoError(t, err)
			assert.Equal(t, test.id, decodeID)
			assert.Equal(t, test.version, decodeVersion)

			if test.packages != nil {
				assert.Equal(t, s.Artifacts.Packages.PackageCount(), len(test.packages))

			packages:
				for _, pkgName := range test.packages {
					for _, p := range s.Artifacts.Packages.Sorted() {
						if p.Name == pkgName {
							continue packages
						}
					}
					assert.NoError(t, fmt.Errorf("Unable to find package: %s", pkgName))
				}
			}

			if test.relationships != nil {
				assert.Len(t, s.Relationships, len(test.relationships))

			relationships:
				for _, pkgName := range test.relationships {
					for _, rel := range s.Relationships {
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

func TestDecoder_Identify(t *testing.T) {
	type testCase struct {
		name    string
		file    string
		id      sbom.FormatID
		version string
	}

	var cases []testCase

	for _, version := range SupportedVersions() {
		cases = append(cases, testCase{
			name:    fmt.Sprintf("v%s schema", version),
			file:    fmt.Sprintf("test-fixtures/identify/%s.json", version),
			id:      ID,
			version: version,
		})
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			reader, err := os.Open(test.file)
			require.NoError(t, err)

			dec := NewFormatDecoder()

			formatID, formatVersion := dec.Identify(reader)
			assert.Equal(t, test.id, formatID)
			assert.Equal(t, test.version, formatVersion)
		})
	}
}
