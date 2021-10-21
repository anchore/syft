package spdx22json

import (
	"bytes"
	"strings"
	"testing"

	"github.com/anchore/syft/syft/source"

	"github.com/anchore/syft/internal/formats/common/testutils"
	"github.com/go-test/deep"
	"github.com/stretchr/testify/assert"
)

func TestEncodeDecodeCycle(t *testing.T) {
	testImage := "image-simple"
	originalCatalog, originalMetadata, _ := testutils.ImageInput(t, testImage)

	var buf bytes.Buffer
	assert.NoError(t, encoder(&buf, originalCatalog, &originalMetadata, nil, source.SquashedScope))

	actualCatalog, actualMetadata, _, _, err := decoder(bytes.NewReader(buf.Bytes()))
	assert.NoError(t, err)

	for _, d := range deep.Equal(originalMetadata, *actualMetadata) {
		t.Errorf("metadata difference: %+v", d)
	}

	actualPackages := actualCatalog.Sorted()
	for idx, p := range originalCatalog.Sorted() {
		if !assert.Equal(t, p.Name, actualPackages[idx].Name) {
			t.Errorf("different package at idx=%d: %s vs %s", idx, p.Name, actualPackages[idx].Name)
			continue
		}

		// ids will never be equal
		p.ID = ""
		actualPackages[idx].ID = ""

		for _, d := range deep.Equal(*p, *actualPackages[idx]) {
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
