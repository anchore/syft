package cyclonedxjson

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
)

func TestDecoder_Decode(t *testing.T) {
	tests := []struct {
		name     string
		file     string
		err      bool
		distro   string
		packages []string
		// locations are the location paths expected for a package, by package name
		locations map[string][]string
	}{
		{
			name:     "dir-scan",
			file:     "snapshot/TestCycloneDxDirectoryEncoder.golden",
			distro:   "debian:1.2.3",
			packages: []string{"package-1:1.0.1", "package-2:2.0.1"},
			locations: map[string][]string{
				"package-1": {"/some/path/pkg1"},
				"package-2": {"/some/path/pkg1"},
			},
		},
		{
			name:     "image-scan",
			file:     "snapshot/TestCycloneDxImageEncoder.golden",
			distro:   "debian:1.2.3",
			packages: []string{"package-1:1.0.1", "package-2:2.0.1"},
			locations: map[string][]string{
				"package-1": {"/somefile-1.txt"},
				"package-2": {"/somefile-2.txt"},
			},
		},
		{
			// an unmodified document from cdxgen 12.8.4 (`cdxgen -t js`) for a project whose src/index.js requires
			// lodash: the locations of a document syft did not write come from its evidence occurrences
			name:     "third-party-evidence-occurrences",
			file:     "cdxgen-evidence-occurrences.json",
			packages: []string{"evidence-demo:1.0.0", "lodash:4.17.21"},
			locations: map[string][]string{
				"lodash": {"/src/index.js"},
			},
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

			if test.distro != "" {
				split := strings.SplitN(test.distro, ":", 2)
				distroName := split[0]
				distroVersion := split[1]
				assert.Equal(t, bom.Artifacts.LinuxDistribution.ID, distroName)
				assert.Equal(t, bom.Artifacts.LinuxDistribution.Version, distroVersion)
			}

			var pkgs []string
			for p := range bom.Artifacts.Packages.Enumerate() {
				pkgs = append(pkgs, fmt.Sprintf("%s:%s", p.Name, p.Version))
			}

			assert.ElementsMatch(t, test.packages, pkgs)

			for name, want := range test.locations {
				var got []string
				for _, p := range bom.Artifacts.Packages.PackagesByName(name) {
					for _, l := range p.Locations.ToSlice() {
						got = append(got, l.RealPath)
					}
				}
				assert.ElementsMatch(t, want, got, "locations of %s", name)
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

// The component from https://github.com/anchore/syft/issues/3880, as the reporter posted it: a third-party
// CycloneDX 1.6 document whose only location is a (Windows, relative) evidence occurrence.
func TestDecoder_Decode_issue3880ThirdPartyOccurrence(t *testing.T) {
	f, err := os.Open("testdata/issue-3880-third-party-deb.json")
	require.NoError(t, err)
	defer f.Close()

	s, _, _, err := NewFormatDecoder().Decode(f)
	require.NoError(t, err)

	var got *pkg.Package
	for p := range s.Artifacts.Packages.Enumerate() {
		if p.Name == "zeromq3" {
			got = &p
		}
	}
	require.NotNil(t, got)
	locations := got.Locations.ToSlice()
	require.Len(t, locations, 1)
	assert.Equal(t, "/packages\\libzmq5_4.3.2-2ubuntu1.20.04.1~esm2_amd64.deb", locations[0].RealPath)
}

// Occurrences change the derived package ID of a component that has no bom-ref. A real cdxgen 12.8.4 document gives
// every component a bom-ref, so its packages keep the bom-ref as their ID while
// gaining the location.
func TestDecoder_Decode_cdxgenDocumentKeepsBomRefAsID(t *testing.T) {
	f, err := os.Open("testdata/cdxgen-evidence-occurrences.json")
	require.NoError(t, err)
	defer f.Close()

	s, _, _, err := NewFormatDecoder().Decode(f)
	require.NoError(t, err)

	pkgs := s.Artifacts.Packages.PackagesByName("lodash")
	require.Len(t, pkgs, 1)
	assert.Equal(t, "pkg:npm/lodash@4.17.21", string(pkgs[0].ID()))
	assert.Equal(t, []string{"/src/index.js"}, realPaths(pkgs[0]))
}

func realPaths(p pkg.Package) []string {
	var out []string
	for _, l := range p.Locations.ToSlice() {
		out = append(out, l.RealPath)
	}
	return out
}
