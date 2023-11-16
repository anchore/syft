package spdxjson

import (
	"bytes"
	"flag"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/format/internal/testutil"
	"github.com/anchore/syft/syft/sbom"
)

var updateSnapshot = flag.Bool("update-spdx-json", false, "update the *.golden files for spdx-json encoders")
var updateImage = flag.Bool("update-image", false, "update the golden image used for image encoder testing")

func getEncoder(t testing.TB) sbom.FormatEncoder {
	enc, err := NewFormatEncoderWithConfig(DefaultEncoderConfig())
	require.NoError(t, err)
	return enc
}

func TestSPDXJSONDirectoryEncoder(t *testing.T) {
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

func TestSPDXJSONImageEncoder(t *testing.T) {
	testImage := "image-simple"
	testutil.AssertEncoderAgainstGoldenImageSnapshot(t,
		testutil.ImageSnapshotTestConfig{
			Image:               testImage,
			UpdateImageSnapshot: *updateImage,
		},
		testutil.EncoderSnapshotTestConfig{
			Subject:                     testutil.ImageInput(t, testImage, testutil.FromSnapshot()),
			Format:                      getEncoder(t),
			UpdateSnapshot:              *updateSnapshot,
			PersistRedactionsInSnapshot: true,
			IsJSON:                      true,
			Redactor:                    redactor(),
		},
	)
}

func TestSPDXRelationshipOrder(t *testing.T) {
	testImage := "image-simple"

	s := testutil.ImageInput(t, testImage, testutil.FromSnapshot())
	testutil.AddSampleFileRelationships(&s)

	testutil.AssertEncoderAgainstGoldenImageSnapshot(t,
		testutil.ImageSnapshotTestConfig{
			Image:               testImage,
			UpdateImageSnapshot: *updateImage,
		},
		testutil.EncoderSnapshotTestConfig{
			Subject:                     s,
			Format:                      getEncoder(t),
			UpdateSnapshot:              *updateSnapshot,
			PersistRedactionsInSnapshot: true,
			IsJSON:                      true,
			Redactor:                    redactor(),
		},
	)
}

func redactor(values ...string) testutil.Redactor {
	return testutil.NewRedactions().
		WithValuesRedacted(values...).
		WithPatternRedactors(
			map[string]string{
				// each SBOM reports the time it was generated, which is not useful during snapshot testing
				`"created":\s+"[^"]*"`: `"created":"redacted"`,

				// each SBOM reports a unique documentNamespace when generated, this is not useful for snapshot testing
				`"documentNamespace":\s+"[^"]*"`: `"documentNamespace":"redacted"`,

				// the license list will be updated periodically, the value here should not be directly tested in snapshot tests
				`"licenseListVersion":\s+"[^"]*"`: `"licenseListVersion":"redacted"`,
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

	relationshipOffsetPerVersion := map[string]int{
		// the package representing the source gets a relationship from the source package to all other packages found
		// these relationships cannot be removed until the primaryPackagePurpose info is available in 2.3
		"2.1": 2,
		"2.2": 2,
		// the source-to-package relationships can be removed since the primaryPackagePurpose info is available in 2.3
		"2.3": 0,
	}

	pkgCountOffsetPerVersion := map[string]int{
		"2.1": 1, // the source is mapped as a package, but cannot distinguish it since the primaryPackagePurpose info is not available until 2.3
		"2.2": 1, // the source is mapped as a package, but cannot distinguish it since the primaryPackagePurpose info is not available until 2.3
		"2.3": 0, // the source package can be removed since the primaryPackagePurpose info is available
	}

	for _, enc := range encs {
		t.Run(enc.Version(), func(t *testing.T) {
			require.Contains(t, versions, enc.Version())

			var buf bytes.Buffer
			require.NoError(t, enc.Encode(&buf, subject))

			id, version := dec.Identify(bytes.NewReader(buf.Bytes()))
			assert.Equal(t, enc.ID(), id)
			assert.Equal(t, enc.Version(), version)

			var s *sbom.SBOM
			var err error
			s, id, version, err = dec.Decode(bytes.NewReader(buf.Bytes()))
			require.NoError(t, err)

			assert.Equal(t, enc.ID(), id)
			assert.Equal(t, enc.Version(), version)

			require.NotEmpty(t, s.Artifacts.Packages.PackageCount())

			offset := relationshipOffsetPerVersion[enc.Version()]

			assert.Equal(t, len(subject.Relationships)+offset, len(s.Relationships), "mismatched relationship count")

			offset = pkgCountOffsetPerVersion[enc.Version()]

			if !assert.Equal(t, subject.Artifacts.Packages.PackageCount()+offset, s.Artifacts.Packages.PackageCount(), "mismatched package count") {
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
