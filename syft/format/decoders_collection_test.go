package format

import (
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/format/spdxjson"
	"github.com/anchore/syft/syft/format/syftjson"
	"github.com/anchore/syft/syft/sbom"
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
			reader, err := os.Open(test.fixture)
			assert.NoError(t, err)

			id, version := Identify(reader)
			assert.Equal(t, test.id, id)
			assert.Equal(t, test.version, version)

		})
	}
}

func TestDecodeUnseekable(t *testing.T) {
	reader, err := os.Open("spdxjson/test-fixtures/spdx/example7-go-module.spdx.json")
	assert.NoError(t, err)

	// io.NopCloser wraps the reader in a non-seekable type
	unseekableReader := io.NopCloser(reader)
	_, formatID, _, err := Decode(unseekableReader)
	assert.NoError(t, err)
	assert.Equal(t, spdxjson.ID, formatID)
}

func TestFormats_EmptyInput(t *testing.T) {
	for _, format := range Decoders() {
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
