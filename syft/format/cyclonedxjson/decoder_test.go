package cyclonedxjson

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/format/internal/testutil"
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
			reader, err := os.Open(filepath.Join("testdata", test.file))
			require.NoError(t, err)
			reset := func() { _, err = reader.Seek(0, io.SeekStart); require.NoError(t, err) }

			dec := NewFormatDecoder()

			formatID, formatVersion := dec.Identify(reader)
			if test.err {
				assert.Equal(t, sbom.FormatID(""), formatID)
				assert.Equal(t, "", formatVersion)

				reset()
				_, decodeID, decodeVersion, err := dec.Decode(reader)
				require.Error(t, err)
				assert.Equal(t, sbom.FormatID(""), decodeID)
				assert.Equal(t, "", decodeVersion)

				return
			}
			assert.Equal(t, ID, formatID)
			assert.NotEmpty(t, formatVersion)

			reset()
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

// the source name and version (as set by --source-name and --source-version) are only expressed as the
// CycloneDX metadata.component name and version, so they must survive an encode-decode round trip.
// see https://github.com/anchore/grype/issues/2418
func TestDecoder_SourceNameAndVersionRoundTrip(t *testing.T) {
	subject := testutil.DirectoryInput(t, t.TempDir())
	subject.Source.Name = "my-app"
	subject.Source.Version = "0.1.0"

	for _, enc := range defaultFormatEncoders() {
		t.Run(enc.Version(), func(t *testing.T) {
			var buf bytes.Buffer
			require.NoError(t, enc.Encode(&buf, subject))

			s, _, _, err := NewFormatDecoder().Decode(bytes.NewReader(buf.Bytes()))
			require.NoError(t, err)
			require.NotNil(t, s)

			assert.Equal(t, subject.Source.Name, s.Source.Name)
			assert.Equal(t, subject.Source.Version, s.Source.Version)
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
			file:    fmt.Sprintf("testdata/identify/%s.json", version),
			id:      ID,
			version: version,
		})
	}

	cases = append(cases, []testCase{
		{
			name:    "no-schema-1.4",
			file:    "testdata/identify/micronaut-1.4.json",
			id:      ID,
			version: "1.4",
		},
		{
			name:    "no-schema-1.5",
			file:    "testdata/identify/micronaut-1.5.json",
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
