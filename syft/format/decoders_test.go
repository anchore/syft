package format

import (
	"fmt"
	"github.com/anchore/syft/syft/format/syftjson"
	"github.com/anchore/syft/syft/sbom"
	"github.com/stretchr/testify/assert"
	"io"
	"os"
	"strings"
	"testing"
)

func TestIdentify(t *testing.T) {
	tests := []struct {
		fixture string
		id      sbom.FormatID
		version string
	}{
		{
			fixture: "test-fixtures/alpine-syft.json",
			id:      syftjson.ID,
			version: "1.1.0",
		},
	}
	for _, test := range tests {
		t.Run(test.fixture, func(t *testing.T) {
			f, err := os.Open(test.fixture)
			assert.NoError(t, err)
			by, err := io.ReadAll(f)
			assert.NoError(t, err)
			id, version := Identify(by)
			assert.Equal(t, test.id, id)
			assert.Equal(t, test.version, version)

		})
	}
}

func TestFormats_EmptyInput(t *testing.T) {
	for _, format := range DefaultDecoders() {
		name := strings.Split(fmt.Sprintf("%#v", format), "{")[0]

		t.Run(name, func(t *testing.T) {
			t.Run("Decode", func(t *testing.T) {
				assert.NotPanics(t, func() {
					decodedSBOM, _, _, err := format.Decode(nil)
					assert.Error(t, err)
					assert.Nil(t, decodedSBOM)
				})
			})

			t.Run("Identify", func(t *testing.T) {
				assert.NotPanics(t, func() {
					id, version := format.Identify(nil)
					assert.Empty(t, id)
					assert.Empty(t, version)
				})
			})
		})
	}
}
