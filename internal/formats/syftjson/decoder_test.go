package syftjson

import (
	"bytes"
	"strings"
	"testing"

	"github.com/anchore/syft/internal/formats/common/testutils"
	"github.com/go-test/deep"
	"github.com/stretchr/testify/assert"
)

func TestEncodeDecodeCycle(t *testing.T) {
	testImage := "image-simple"
	originalSBOM := testutils.ImageInput(t, testImage)

	var buf bytes.Buffer
	assert.NoError(t, encoder(&buf, originalSBOM))

	actualSBOM, err := decoder(bytes.NewReader(buf.Bytes()))
	assert.NoError(t, err)

	for _, d := range deep.Equal(originalSBOM.Source, actualSBOM.Source) {
		if strings.HasSuffix(d, "<nil slice> != []") {
			// semantically the same
			continue
		}
		t.Errorf("metadata difference: %+v", d)
	}

	actualPackages := actualSBOM.Artifacts.PackageCatalog.Sorted()
	for idx, p := range originalSBOM.Artifacts.PackageCatalog.Sorted() {
		if !assert.Equal(t, p.Name, actualPackages[idx].Name) {
			t.Errorf("different package at idx=%d: %s vs %s", idx, p.Name, actualPackages[idx].Name)
			continue
		}

		for _, d := range deep.Equal(p, actualPackages[idx]) {
			if strings.Contains(d, ".VirtualPath: ") {
				// location.Virtual path is not exposed in the json output
				continue
			}
			if strings.HasSuffix(d, "<nil slice> != []") {
				// semantically the same
				continue
			}
			t.Errorf("package difference (%s): %+v", p.Name, d)
		}
	}
}
