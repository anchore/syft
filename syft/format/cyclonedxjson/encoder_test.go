package cyclonedxjson

import (
	"bytes"
	"flag"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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

// Test_ComponentAuthorByVersion asserts which of the two author fields a document is written with, and that
// either one is read back to the same package. The author field on a component is deprecated as of CycloneDX
// 1.6 in favor of a list of authors, and the two do not coexist in syft's output.
//
// see anchore/syft#4580
func Test_ComponentAuthorByVersion(t *testing.T) {
	subject := testutil.DirectoryInputWithAuthorField(t)

	for _, version := range SupportedVersions() {
		t.Run("v"+version, func(t *testing.T) {
			enc, err := NewFormatEncoderWithConfig(EncoderConfig{Version: version})
			require.NoError(t, err)

			var buf bytes.Buffer
			require.NoError(t, enc.Encode(&buf, subject))

			doc := buf.String()

			if version < "1.6" {
				assert.Contains(t, doc, `"author":"test-author"`, "the deprecated field is all this version has")
				assert.NotContains(t, doc, `"authors":`, "the authors list does not exist before 1.6")
			} else {
				assert.Contains(t, doc, `"authors":[{"name":"test-author"}]`)
				assert.NotContains(t, doc, `"author":`, "the deprecated field should not be written when the list can be")
			}

			if version == "1.2" {
				// package metadata is carried in component properties, which 1.2 has no place for, so there is
				// no metadata to read an author back into
				return
			}

			decoded, _, _, err := NewFormatDecoder().Decode(bytes.NewReader(buf.Bytes()))
			require.NoError(t, err)

			assert.Equal(t, "test-author", decodedPythonAuthor(t, decoded), "the author did not survive the round trip")
		})
	}
}

func decodedPythonAuthor(t *testing.T, s *sbom.SBOM) string {
	t.Helper()

	for p := range s.Artifacts.Packages.Enumerate() {
		if metadata, ok := p.Metadata.(pkg.PythonPackage); ok {
			return metadata.Author
		}
	}

	t.Fatal("no python package in the decoded document")
	return ""
}
