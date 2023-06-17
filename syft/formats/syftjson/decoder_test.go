package syftjson

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/go-test/deep"
	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/formats/internal/testutils"
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

	actualPackages := actualSBOM.Artifacts.Packages.Sorted()
	for idx, p := range originalSBOM.Artifacts.Packages.Sorted() {
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

func TestOutOfDateParser(t *testing.T) {
	tests := []struct {
		name            string
		documentVersion string
		parserVersion   string
		want            error
	}{{
		name:            "no warning when doc version is older",
		documentVersion: "1.0.9",
		parserVersion:   "3.1.0",
	}, {
		name:            "warning when parser is older",
		documentVersion: "4.3.2",
		parserVersion:   "3.1.0",
		want:            fmt.Errorf("document has schema version %s, but parser has older schema version (%s)", "4.3.2", "3.1.0"),
	}, {
		name:            "warning when document version is unparseable",
		documentVersion: "some-nonsense",
		parserVersion:   "3.1.0",
		want:            fmt.Errorf("error comparing document schema version with parser schema version: %w", errors.New("Invalid Semantic Version")),
	}, {
		name:            "warning when parser version is unparseable",
		documentVersion: "7.1.0",
		parserVersion:   "some-nonsense",
		want:            fmt.Errorf("error comparing document schema version with parser schema version: %w", errors.New("Invalid Semantic Version")),
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := checkSupportedSchema(tt.documentVersion, tt.parserVersion)
			assert.Equal(t, tt.want, got)
		})
	}
}
