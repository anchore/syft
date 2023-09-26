package cyclonedxjson

import (
	"fmt"
	"github.com/anchore/syft/syft/sbom"
	"github.com/stretchr/testify/require"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_decoder(t *testing.T) {
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
			contents, err := io.ReadAll(reader)
			require.NoError(t, err)

			dec := NewFormatDecoder()

			formatID, formatVersion := dec.Identify(contents)
			if test.err {
				assert.Equal(t, sbom.FormatID(""), formatID)
				assert.Equal(t, "", formatVersion)

				_, decodeID, decodeVersion, err := dec.Decode(contents)
				require.Error(t, err)
				assert.Equal(t, sbom.FormatID(""), decodeID)
				assert.Equal(t, "", decodeVersion)

				return
			}
			assert.Equal(t, ID, formatID)
			assert.NotEmpty(t, formatVersion)

			bom, decodeID, decodeVersion, err := dec.Decode(contents)
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
