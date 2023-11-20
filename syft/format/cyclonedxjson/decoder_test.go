package cyclonedxjson

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/sbom"
)

func TestDecoder_Decode(t *testing.T) {
	tests := []struct {
		name     string
		file     string
		err      bool
		distro   string
		packages []string
	}{
		{
			name:     "dir-scan",
			file:     "snapshot/TestCycloneDxDirectoryEncoder.golden",
			distro:   "debian:1.2.3",
			packages: []string{"package-1:1.0.1", "package-2:2.0.1"},
		},
		{
			name:     "image-scan",
			file:     "snapshot/TestCycloneDxImageEncoder.golden",
			distro:   "debian:1.2.3",
			packages: []string{"package-1:1.0.1", "package-2:2.0.1"},
		},
		{
			name: "not-an-sbom",
			file: "bad-sbom",
			err:  true,
		},
	}
	for _, test := range tests {
		t.Run(test.file, func(t *testing.T) {
			reader, err := os.Open(filepath.Join("test-fixtures", test.file))
			require.NoError(t, err)

			dec := NewFormatDecoder()

			formatID, formatVersion := dec.Identify(reader)
			if test.err {
				assert.Equal(t, sbom.FormatID(""), formatID)
				assert.Equal(t, "", formatVersion)

				_, decodeID, decodeVersion, err := dec.Decode(reader)
				require.Error(t, err)
				assert.Equal(t, sbom.FormatID(""), decodeID)
				assert.Equal(t, "", decodeVersion)

				return
			}
			assert.Equal(t, ID, formatID)
			assert.NotEmpty(t, formatVersion)

			bom, decodeID, decodeVersion, err := dec.Decode(reader)
			require.NotNil(t, bom)
			require.NoError(t, err)

			assert.Equal(t, ID, decodeID)
			assert.Equal(t, formatVersion, decodeVersion)

			split := strings.SplitN(test.distro, ":", 2)
			distroName := split[0]
			distroVersion := split[1]
			assert.Equal(t, bom.Artifacts.LinuxDistribution.ID, distroName)
			assert.Equal(t, bom.Artifacts.LinuxDistribution.Version, distroVersion)

			var pkgs []string
			for p := range bom.Artifacts.Packages.Enumerate() {
				pkgs = append(pkgs, fmt.Sprintf("%s:%s", p.Name, p.Version))
			}

			assert.ElementsMatch(t, test.packages, pkgs)
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

	cases = append(cases, []testCase{
		{
			name:    "no-schema-1.4",
			file:    "test-fixtures/identify/micronaut-1.4.json",
			id:      ID,
			version: "1.4",
		},
		{
			name:    "no-schema-1.5",
			file:    "test-fixtures/identify/micronaut-1.5.json",
			id:      ID,
			version: "1.5",
		},
	}...)

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
