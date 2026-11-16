package cyclonedxjson

import (
	"bytes"
	"encoding/json"
	"flag"
	"regexp"
	"strings"
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/format/common/cyclonedxhelpers"
	"github.com/anchore/syft/syft/format/internal/cyclonedxutil"
	"github.com/anchore/syft/syft/format/internal/testutil"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
)

var updateSnapshot = flag.Bool("update-cyclonedx-json", false, "update the *.golden files for cyclone-dx JSON encoders")
var updateImage = flag.Bool("update-image", false, "update the golden image used for image encoder testing")

func getEncoder(t testing.TB) sbom.FormatEncoder {
	cfg := DefaultEncoderConfig()
	cfg.Pretty = true

	enc, err := NewFormatEncoderWithConfig(cfg)
	require.NoError(t, err)
	return enc
}

func TestPrettyOutput(t *testing.T) {
	run := func(opt bool) string {
		enc, err := NewFormatEncoderWithConfig(EncoderConfig{
			Version: cyclonedxutil.DefaultVersion,
			Pretty:  opt,
		})
		require.NoError(t, err)

		dir := t.TempDir()
		s := testutil.DirectoryInput(t, dir)

		var buffer bytes.Buffer
		err = enc.Encode(&buffer, s)
		require.NoError(t, err)

		return strings.TrimSpace(buffer.String())
	}

	t.Run("pretty", func(t *testing.T) {
		actual := run(true)
		assert.Contains(t, actual, "\n")
	})

	t.Run("compact", func(t *testing.T) {
		actual := run(false)
		assert.NotContains(t, actual, "\n")
	})
}

func TestEscapeHTML(t *testing.T) {
	dir := t.TempDir()
	s := testutil.DirectoryInput(t, dir)
	s.Artifacts.Packages.Add(pkg.Package{
		Name: "<html-package>",
	})

	// by default we do not escape HTML
	t.Run("default", func(t *testing.T) {
		cfg := DefaultEncoderConfig()

		enc, err := NewFormatEncoderWithConfig(cfg)
		require.NoError(t, err)

		var buffer bytes.Buffer
		err = enc.Encode(&buffer, s)
		require.NoError(t, err)

		actual := buffer.String()
		assert.Contains(t, actual, "<html-package>")
		assert.NotContains(t, actual, "\\u003chtml-package\\u003e")
	})

}

func TestCycloneDxDirectoryEncoder(t *testing.T) {
	dir := t.TempDir()
	testutil.AssertEncoderAgainstGoldenSnapshot(t,
		testutil.EncoderSnapshotTestConfig{
			Subject:                     testutil.DirectoryInput(t, dir),
			Format:                      getEncoder(t),
			UpdateSnapshot:              *updateSnapshot,
			PersistRedactionsInSnapshot: true,
			IsJSON:                      true,
			Redactor:                    redactor(dir),
		},
	)
}

func TestCycloneDxImageEncoder(t *testing.T) {
	testImage := "image-simple"
	testutil.AssertEncoderAgainstGoldenImageSnapshot(t,
		testutil.ImageSnapshotTestConfig{
			Image:               testImage,
			UpdateImageSnapshot: *updateImage,
		},
		testutil.EncoderSnapshotTestConfig{
			Subject:                     testutil.ImageInput(t, testImage),
			Format:                      getEncoder(t),
			UpdateSnapshot:              *updateSnapshot,
			PersistRedactionsInSnapshot: true,
			IsJSON:                      true,
			Redactor:                    redactor(),
		},
	)
}

func TestCycloneDxSourcePackageEncoder(t *testing.T) {
	dir := t.TempDir()
	testutil.AssertEncoderAgainstGoldenSnapshot(t,
		testutil.EncoderSnapshotTestConfig{
			Subject:                     testutil.SourcePackagesInput(t, dir),
			Format:                      getEncoder(t),
			UpdateSnapshot:              *updateSnapshot,
			PersistRedactionsInSnapshot: true,
			IsJSON:                      true,
			Redactor:                    redactor(dir),
		},
	)
}

func TestCycloneDxSourcePackageEncoder_SpecVersions(t *testing.T) {
	s := testutil.SourcePackagesInput(t, t.TempDir())
	tests := []struct {
		version string
		want    bool
	}{
		{version: "1.4", want: false},
		{version: "1.5", want: false},
		{version: "1.6", want: true},
		{version: cyclonedxutil.DefaultVersion, want: true},
	}
	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			enc, err := NewFormatEncoderWithConfig(EncoderConfig{Version: tt.version})
			require.NoError(t, err)

			var buf bytes.Buffer
			require.NoError(t, enc.Encode(&buf, s))

			// the source-distribution reference type only exists from spec 1.6
			assert.Equal(t, tt.want, strings.Contains(buf.String(), `"source-distribution"`))
		})
	}
}

func TestCycloneDxLocations_SpecVersions(t *testing.T) {
	s, _ := testutil.LocationsInput(t)
	tests := []struct {
		version         string
		wantProperties  bool
		wantOccurrences bool
	}{
		{version: "1.2"},
		{version: "1.3", wantProperties: true},
		{version: "1.4", wantProperties: true},
		{version: "1.5", wantProperties: true, wantOccurrences: true},
		{version: "1.6", wantProperties: true, wantOccurrences: true},
		{version: cyclonedxutil.DefaultVersion, wantProperties: true, wantOccurrences: true},
	}
	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			enc, err := NewFormatEncoderWithConfig(EncoderConfig{Version: tt.version})
			require.NoError(t, err)

			var buf bytes.Buffer
			require.NoError(t, enc.Encode(&buf, s))

			// evidence occurrences only exist from spec 1.5, and no emptied evidence element is left behind before that
			assert.Equal(t, tt.wantOccurrences, strings.Contains(buf.String(), `"occurrences"`))
			assert.Equal(t, tt.wantOccurrences, strings.Contains(buf.String(), `"evidence"`))

			// every spec version that has properties (1.3 and later) keeps the syft:location properties, which state the
			// layer and the full path, so the occurrences are one per distinct path
			assert.Equal(t, tt.wantProperties, strings.Contains(buf.String(), `"syft:location:`))
			wantExampleOccurrences := 0
			if tt.wantOccurrences {
				wantExampleOccurrences = 1
			}
			assert.Equal(t, wantExampleOccurrences, strings.Count(buf.String(), `"location":"/usr/bin/example"`))
		})
	}
}

func TestCycloneDxLocations_RoundTrip(t *testing.T) {
	for _, version := range []string{"1.2", "1.3", "1.4", "1.5", "1.6", cyclonedxutil.DefaultVersion} {
		t.Run(version, func(t *testing.T) {
			s, want := testutil.LocationsInput(t)
			if version == "1.2" {
				// properties exist from spec 1.3 and occurrences from 1.5, so a 1.2 document states no locations
				want = nil
			}

			cfg := DefaultEncoderConfig()
			cfg.Version = version
			enc, err := NewFormatEncoderWithConfig(cfg)
			require.NoError(t, err)

			var buf bytes.Buffer
			require.NoError(t, enc.Encode(&buf, s))

			decoded, _, _, err := NewFormatDecoder().Decode(bytes.NewReader(buf.Bytes()))
			require.NoError(t, err)

			pkgs := decoded.Artifacts.Packages.PackagesByName(testutil.LocationsInputPackageName)
			require.Len(t, pkgs, 1)
			// a file found in several layers is a location per layer, each with its layer
			assert.ElementsMatch(t, want, pkgs[0].Locations.CoordinateSet().ToSlice())
		})
	}
}

// cyclonedxhelpers.ToFormatModel is public: library callers (grype's CycloneDX presenter is one) encode its model with
// cyclonedx.BOMEncoder.EncodeVersion, at the BOM's own spec version or an older one. The locations of a component
// should come out the same as from syft's own encoder at that version, and decode to the same locations.
func TestCycloneDxLocations_ToFormatModelMatchesEncoder(t *testing.T) {
	require.Equal(t, cyclonedx.SpecVersion1_7, cyclonedxhelpers.ToFormatModel(sbom.SBOM{}).SpecVersion)

	tests := []struct {
		version cyclonedx.SpecVersion
		// properties exist from spec 1.3, so a 1.2 document states no locations
		wantProperties  bool
		wantOccurrences bool
		// cyclonedx-go removes the occurrences for 1.3 and 1.4 and leaves the evidence object, which those schemas
		// allow to be empty; 1.2 has no evidence at all
		wantEmptyEvidence bool
	}{
		{version: cyclonedx.SpecVersion1_2},
		{version: cyclonedx.SpecVersion1_3, wantProperties: true, wantEmptyEvidence: true},
		{version: cyclonedx.SpecVersion1_4, wantProperties: true, wantEmptyEvidence: true},
		{version: cyclonedx.SpecVersion1_5, wantProperties: true, wantOccurrences: true},
		{version: cyclonedx.SpecVersion1_6, wantProperties: true, wantOccurrences: true},
		{version: cyclonedx.SpecVersion1_7, wantProperties: true, wantOccurrences: true},
	}
	for _, tt := range tests {
		t.Run(tt.version.String(), func(t *testing.T) {
			s, want := testutil.LocationsInput(t)

			enc, err := NewFormatEncoderWithConfig(EncoderConfig{Version: tt.version.String()})
			require.NoError(t, err)
			var encoderOut bytes.Buffer
			require.NoError(t, enc.Encode(&encoderOut, s))

			var modelOut bytes.Buffer
			modelEncoder := cyclonedx.NewBOMEncoder(&modelOut, cyclonedx.BOMFileFormatJSON)
			require.NoError(t, modelEncoder.EncodeVersion(cyclonedxhelpers.ToFormatModel(s), tt.version))

			got := locationsOf(t, modelOut.Bytes())
			assert.Equal(t, locationsOf(t, encoderOut.Bytes()), got)
			assert.Equal(t, tt.wantProperties, len(got.Properties) > 0)
			assert.Equal(t, tt.wantOccurrences, len(got.Occurrences) > 0)
			assert.Equal(t, tt.wantEmptyEvidence, strings.Contains(modelOut.String(), `"evidence":{}`))

			if !tt.wantProperties {
				want = nil
			}
			decoded, _, _, err := NewFormatDecoder().Decode(bytes.NewReader(modelOut.Bytes()))
			require.NoError(t, err)
			pkgs := decoded.Artifacts.Packages.PackagesByName(testutil.LocationsInputPackageName)
			require.Len(t, pkgs, 1)
			assert.ElementsMatch(t, want, pkgs[0].Locations.CoordinateSet().ToSlice())
		})
	}
}

type componentLocations struct {
	Properties  []string
	Occurrences []cyclonedx.EvidenceOccurrence
}

func locationsOf(t *testing.T, doc []byte) componentLocations {
	t.Helper()
	var bom cyclonedx.BOM
	require.NoError(t, json.Unmarshal(doc, &bom))
	var out componentLocations
	for _, c := range *bom.Components {
		if c.Name != testutil.LocationsInputPackageName {
			continue
		}
		if c.Properties != nil {
			for _, p := range *c.Properties {
				if strings.HasPrefix(p.Name, "syft:location:") {
					out.Properties = append(out.Properties, p.Name+"="+p.Value)
				}
			}
		}
		if c.Evidence != nil && c.Evidence.Occurrences != nil {
			out.Occurrences = *c.Evidence.Occurrences
		}
	}
	return out
}

// Released versions of syft and grype read package locations only from the syft:location properties, so
// a default (JSON, 1.7) document without them decodes with no locations in those readers.
func TestCycloneDxLocations_DefaultKeepsLocationProperties(t *testing.T) {
	s, _ := testutil.LocationsInput(t)
	enc, err := NewFormatEncoderWithConfig(DefaultEncoderConfig())
	require.NoError(t, err)
	var out bytes.Buffer
	require.NoError(t, enc.Encode(&out, s))

	got := locationsOf(t, out.Bytes())
	assert.Contains(t, got.Properties, "syft:location:0:path=/opt/example")
	assert.NotEmpty(t, got.Occurrences)
}

func redactor(values ...string) testutil.Redactor {
	return testutil.NewRedactions().
		WithValuesRedacted(values...).
		WithPatternRedactorSpec(
			testutil.PatternReplacement{
				// only the source component bom-ref (not package or other component bom-refs)
				Search:  regexp.MustCompile(`"component": \{[^}]*"bom-ref":\s*"(?P<redact>.+)"[^}]*}`),
				Groups:  []string{"redact"}, // use the regex to anchore the search, but only replace bytes within the capture group
				Replace: "redacted",
			},
		).
		WithPatternRedactors(
			map[string]string{
				// UUIDs
				`urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`: `urn:uuid:redacted`,

				// timestamps
				`([0-9]+)-(0[1-9]|1[012])-(0[1-9]|[12][0-9]|3[01])[Tt]([01][0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9]|60)(\.[0-9]+)?(([Zz])|([+|\-]([01][0-9]|2[0-3]):[0-5][0-9]))`: `timestamp:redacted`,

				// image hashes
				`sha256:[A-Fa-f0-9]{64}`: `sha256:redacted`,
			},
		)
}

func TestSupportedVersions(t *testing.T) {
	encs := defaultFormatEncoders()
	require.NotEmpty(t, encs)

	versions := SupportedVersions()
	require.Equal(t, len(versions), len(encs))

	subject := testutil.DirectoryInput(t, t.TempDir())
	dec := NewFormatDecoder()

	for _, enc := range encs {
		t.Run(enc.Version(), func(t *testing.T) {
			require.Contains(t, versions, enc.Version())

			var buf bytes.Buffer
			require.NoError(t, enc.Encode(&buf, subject))

			id, version := dec.Identify(bytes.NewReader(buf.Bytes()))
			require.Equal(t, enc.ID(), id)
			require.Equal(t, enc.Version(), version)

			var s *sbom.SBOM
			var err error
			s, id, version, err = dec.Decode(bytes.NewReader(buf.Bytes()))
			require.NoError(t, err)
			require.Equal(t, enc.ID(), id)
			require.Equal(t, enc.Version(), version)

			require.NotEmpty(t, s.Artifacts.Packages.PackageCount())

			assert.Equal(t, len(subject.Relationships), len(s.Relationships), "mismatched relationship count")

			if !assert.Equal(t, subject.Artifacts.Packages.PackageCount(), s.Artifacts.Packages.PackageCount(), "mismatched package count") {
				t.Logf("expected: %d", subject.Artifacts.Packages.PackageCount())
				for _, p := range subject.Artifacts.Packages.Sorted() {
					t.Logf("  - %s", p.String())
				}
				t.Logf("actual: %d", s.Artifacts.Packages.PackageCount())
				for _, p := range s.Artifacts.Packages.Sorted() {
					t.Logf("  - %s", p.String())
				}
			}
		})
	}
}

func defaultFormatEncoders() []sbom.FormatEncoder {
	var encs []sbom.FormatEncoder
	for _, version := range SupportedVersions() {
		enc, err := NewFormatEncoderWithConfig(EncoderConfig{Version: version})
		if err != nil {
			panic(err)
		}
		encs = append(encs, enc)
	}
	return encs
}
