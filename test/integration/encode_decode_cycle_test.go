package integration

import (
	"bytes"
	"regexp"
	"testing"

	"github.com/anchore/syft/syft"

	"github.com/sergi/go-diff/diffmatchpatch"

	"github.com/anchore/syft/syft/format"
	"github.com/stretchr/testify/assert"
)

// TestEncodeDecodeEncodeCycleComparison is testing for differences in how SBOM documents get encoded on multiple cycles.
// By encding and decoding the sbom we can compare the differences between the set of resulting objects. However,
// this requires specific comparisons being done, and select redactions/omissions being made. Additionally, there are
// already unit tests on each format encoder-decoder for properly functioning comparisons in depth, so there is no need
// to do an object-to-object comparison. For this reason this test focuses on a bytes-to-bytes comparison after an
// encode-decode-encode loop which will detect lossy behavior in both directions.
func TestEncodeDecodeEncodeCycleComparison(t *testing.T) {
	tests := []struct {
		format   format.Option
		redactor func(in []byte) []byte
		json     bool
	}{
		{
			format: format.JSONOption,
			json:   true,
		},
		{
			format: format.CycloneDxJSONOption,
			redactor: func(in []byte) []byte {
				in = regexp.MustCompile("\"(timestamp|serialNumber|bom-ref)\": \"[^\"]+\",").ReplaceAll(in, []byte{})
				return in
			},
			json: true,
		},
		{
			format: format.CycloneDxXMLOption,
			redactor: func(in []byte) []byte {
				in = regexp.MustCompile("(serialNumber|bom-ref)=\"[^\"]+\"").ReplaceAll(in, []byte{})
				in = regexp.MustCompile("<timestamp>[^<]+</timestamp>").ReplaceAll(in, []byte{})
				return in
			},
		},
	}
	for _, test := range tests {
		t.Run(string(test.format), func(t *testing.T) {

			originalSBOM, _ := catalogFixtureImage(t, "image-pkg-coverage")

			by1, err := syft.Encode(originalSBOM, test.format)
			assert.NoError(t, err)

			newSBOM, newFormat, err := syft.Decode(bytes.NewReader(by1))
			assert.NoError(t, err)
			assert.Equal(t, test.format, newFormat)

			by2, err := syft.Encode(*newSBOM, test.format)
			assert.NoError(t, err)

			if test.redactor != nil {
				by1 = test.redactor(by1)
				by2 = test.redactor(by2)
			}

			if test.json {
				s1 := string(by1)
				s2 := string(by2)
				assert.JSONEq(t, s1, s2)
			} else {
				if !assert.True(t, bytes.Equal(by1, by2)) {
					dmp := diffmatchpatch.New()
					diffs := dmp.DiffMain(string(by1), string(by2), true)
					t.Errorf("diff: %s", dmp.DiffPrettyText(diffs))
				}
			}
		})
	}
}
