package syft

import (
	"bytes"
	"testing"

	"github.com/anchore/syft/syft/sbom"

	"github.com/go-test/deep"

	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/source"
	"github.com/stretchr/testify/assert"
)

// TestEncodeDecodeEncodeCycleComparison is testing for differences in how SBOM documents get encoded on multiple cycles.
// By encding and decoding the sbom we can compare the differences between the set of resulting objects. However,
// this requires specific comparisons being done, and select redactions/omissions being made. Additionally, there are
// already unit tests on each format encoder-decoder for properly functioning comparisons in depth, so there is no need
// to do an object-to-object comparison. For this reason this test focuses on a bytes-to-bytes comparison after an
// encode-decode-encode loop which will detect lossy behavior in both directions.
func TestEncodeDecodeEncodeCycleComparison(t *testing.T) {
	testImage := "image-simple"
	tests := []struct {
		format format.Option
	}{
		{
			format: format.JSONOption,
		},
	}
	for _, test := range tests {
		t.Run(testImage, func(t *testing.T) {

			src, err := source.NewFromDirectory("./test-fixtures/pkgs")
			if err != nil {
				t.Fatalf("cant get dir")
			}
			originalCatalog, d, err := CatalogPackages(&src, source.SquashedScope)

			originalSBOM := sbom.SBOM{
				Artifacts: sbom.Artifacts{
					PackageCatalog: originalCatalog,
					Distro:         d,
				},
				Source: src.Metadata,
			}

			by1, err := Encode(originalSBOM, test.format)
			assert.NoError(t, err)

			newSBOM, newFormat, err := Decode(bytes.NewReader(by1))
			assert.NoError(t, err)
			assert.Equal(t, test.format, newFormat)

			by2, err := Encode(*newSBOM, test.format)
			assert.NoError(t, err)
			for _, diff := range deep.Equal(by1, by2) {
				t.Errorf(diff)
			}
			assert.True(t, bytes.Equal(by1, by2))
		})
	}
}
