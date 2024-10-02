package integration

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/sergi/go-diff/diffmatchpatch"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/cmd/syft/internal/options"
	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/format/syftjson"
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
		name     string
		redactor func(in []byte) []byte
		json     bool
	}{
		{
			name: syftjson.ID.String(),
			redactor: func(in []byte) []byte {
				// no redactions necessary
				return in
			},
			json: true,
		},
		// TODO: ignoring the `ref` field though does create stable results to compare, but the SBOM is fundamentally gutted and not worth comparing (find a better redaction or compare method)
		//{
		//	name: cyclonedxjson.ID.String(),
		//	redactor: func(in []byte) []byte {
		//		// unstable values
		//		in = regexp.MustCompile(`"(timestamp|serialNumber|bom-ref|ref)":\s*"(\n|[^"])+"`).ReplaceAll(in, []byte(`"$1": "redacted"`))
		//		in = regexp.MustCompile(`"(dependsOn)":\s*\[(?:\s|[^]])+]`).ReplaceAll(in, []byte(`"$1": []`))
		//		return in
		//	},
		//	json: true,
		//},
		//{
		//	name: cyclonedxxml.ID.String(),
		//	redactor: func(in []byte) []byte {
		//		// unstable values
		//		in = regexp.MustCompile(`(serialNumber|bom-ref|ref)="[^"]+"`).ReplaceAll(in, []byte{})
		//		in = regexp.MustCompile(`<timestamp>[^<]+</timestamp>`).ReplaceAll(in, []byte{})
		//
		//		return in
		//	},
		//},
	}

	opts := options.DefaultOutput()
	require.NoError(t, opts.PostLoad())
	encoderList, err := opts.Encoders()
	require.NoError(t, err)

	encoders := format.NewEncoderCollection(encoderList...)
	decoders := format.NewDecoderCollection(format.Decoders()...)

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for _, image := range images {
				originalSBOM, _ := catalogFixtureImage(t, image, source.SquashedScope)

				f := encoders.GetByString(test.name)
				require.NotNil(t, f)

				var buff1 bytes.Buffer
				err := f.Encode(&buff1, originalSBOM)
				require.NoError(t, err)

				newSBOM, formatID, formatVersion, err := decoders.Decode(bytes.NewReader(buff1.Bytes()))
				require.NoError(t, err)
				require.Equal(t, f.ID(), formatID)
				require.Equal(t, f.Version(), formatVersion)

				var buff2 bytes.Buffer
				err = f.Encode(&buff2, *newSBOM)
				require.NoError(t, err)

				by1 := buff1.Bytes()
				by2 := buff2.Bytes()
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

				// write raw IMAGE@NAME-start and IMAGE@NAME-finish to files within the results dir
				// ... this is helpful for debugging
				require.NoError(t, os.MkdirAll("results", 0700))

				suffix := "sbom"
				switch {
				case strings.Contains(test.name, "json"):
					suffix = "json"
				case strings.Contains(test.name, "xml"):
					suffix = "xml"
				}

				require.NoError(t, os.WriteFile(filepath.Join("results", image+"@"+test.name+"-start."+suffix), by1, 0600))
				require.NoError(t, os.WriteFile(filepath.Join("results", image+"@"+test.name+"-finish."+suffix), by2, 0600))
			}
		})
	}
}
