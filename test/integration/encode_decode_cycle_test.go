package integration

import (
	"bytes"
	"regexp"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/sergi/go-diff/diffmatchpatch"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/formats"
	"github.com/anchore/syft/syft/formats/cyclonedxjson"
	"github.com/anchore/syft/syft/formats/cyclonedxxml"
	"github.com/anchore/syft/syft/formats/syftjson"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

// TestEncodeDecodeEncodeCycleComparison is testing for differences in how SBOM documents get encoded on multiple cycles.
// By encoding and decoding the sbom we can compare the differences between the set of resulting objects. However,
// this requires specific comparisons being done, and select redactions/omissions being made. Additionally, there are
// already unit tests on each format encoder-decoder for properly functioning comparisons in depth, so there is no need
// to do an object-to-object comparison. For this reason this test focuses on a bytes-to-bytes comparison after an
// encode-decode-encode loop which will detect lossy behavior in both directions.
func TestEncodeDecodeEncodeCycleComparison(t *testing.T) {
	// use second image for relationships
	images := []string{
		"image-pkg-coverage",
		"image-owning-package",
	}
	tests := []struct {
		formatOption sbom.FormatID
		redactor     func(in []byte) []byte
		json         bool
	}{
		{
			formatOption: syftjson.ID,
			redactor: func(in []byte) []byte {
				// no redactions necessary
				return in
			},
			json: true,
		},
		{
			formatOption: cyclonedxjson.ID,
			redactor: func(in []byte) []byte {
				// unstable values
				in = regexp.MustCompile(`"(timestamp|serialNumber|bom-ref|ref)":\s*"(\n|[^"])+"`).ReplaceAll(in, []byte(`"$1": "redacted"`))
				in = regexp.MustCompile(`"(dependsOn)":\s*\[(?:\s|[^]])+]`).ReplaceAll(in, []byte(`"$1": []`))
				return in
			},
			json: true,
		},
		{
			formatOption: cyclonedxxml.ID,
			redactor: func(in []byte) []byte {
				// unstable values
				in = regexp.MustCompile(`(serialNumber|bom-ref|ref)="[^"]+"`).ReplaceAll(in, []byte{})
				in = regexp.MustCompile(`<timestamp>[^<]+</timestamp>`).ReplaceAll(in, []byte{})

				return in
			},
		},
	}

	for _, test := range tests {
		t.Run(string(test.formatOption), func(t *testing.T) {
			for _, image := range images {
				originalSBOM, _ := catalogFixtureImage(t, image, source.SquashedScope, nil)

				format := formats.ByName(string(test.formatOption))
				require.NotNil(t, format)

				by1, err := formats.Encode(originalSBOM, format)
				require.NoError(t, err)

				newSBOM, newFormat, err := formats.Decode(bytes.NewReader(by1))
				require.NoError(t, err)
				require.Equal(t, format.ID(), newFormat.ID())

				by2, err := formats.Encode(*newSBOM, format)
				require.NoError(t, err)

				if test.redactor != nil {
					by1 = test.redactor(by1)
					by2 = test.redactor(by2)
				}

				if test.json {
					s1 := string(by1)
					s2 := string(by2)
					if diff := cmp.Diff(s1, s2); diff != "" {
						t.Errorf("Encode/Decode mismatch (-want +got) [image %q]:\n%s", image, diff)
					}
				} else if !assert.True(t, bytes.Equal(by1, by2)) {
					dmp := diffmatchpatch.New()
					diffs := dmp.DiffMain(string(by1), string(by2), true)
					t.Errorf("diff: %s", dmp.DiffPrettyText(diffs))
				}
			}
		})
	}
}
