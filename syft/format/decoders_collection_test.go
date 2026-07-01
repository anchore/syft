package format

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/text/encoding/unicode"
	"golang.org/x/text/transform"

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
			fixture: "testdata/alpine-syft.json",
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
	reader, err := os.Open("spdxjson/testdata/spdx/example7-go-module.spdx.json")
	assert.NoError(t, err)

	// io.NopCloser wraps the reader in a non-seekable type
	unseekableReader := io.NopCloser(reader)
	_, formatID, _, err := Decode(unseekableReader)
	assert.NoError(t, err)
	assert.Equal(t, spdxjson.ID, formatID)
}

// TestDecodeWithBOMEncoding pins the end-to-end behavior from issue #4916: a
// syft-json SBOM produced with a UTF-8 BOM (older tools) or in UTF-16LE / UTF-16BE
// (e.g. PowerShell's `>` redirect on Windows) must still be identified as syftjson
// and decode without error. The byte-level transcoding in stream.SeekableReader is
// covered by its own unit tests; this asserts the user-facing invariant the issue
// actually complained about, at the format.Identify / format.Decode boundary.
func TestDecodeWithBOMEncoding(t *testing.T) {
	utf8Content, err := os.ReadFile("testdata/alpine-syft.json")
	require.NoError(t, err)

	cases := []struct {
		name   string
		encode func([]byte) ([]byte, error)
	}{
		{
			name: "utf-8 with BOM",
			encode: func(b []byte) ([]byte, error) {
				return append([]byte{0xEF, 0xBB, 0xBF}, b...), nil
			},
		},
		{
			name: "utf-16le with BOM",
			encode: func(b []byte) ([]byte, error) {
				enc := unicode.UTF16(unicode.LittleEndian, unicode.UseBOM).NewEncoder()
				out, _, encErr := transform.Bytes(enc, b)
				return out, encErr
			},
		},
		{
			name: "utf-16be with BOM",
			encode: func(b []byte) ([]byte, error) {
				enc := unicode.UTF16(unicode.BigEndian, unicode.UseBOM).NewEncoder()
				out, _, encErr := transform.Bytes(enc, b)
				return out, encErr
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			encoded, err := tc.encode(utf8Content)
			require.NoError(t, err)

			id, version := Identify(bytes.NewReader(encoded))
			assert.Equal(t, syftjson.ID, id, "Identify should detect syft-json after BOM transcoding")
			assert.NotEmpty(t, version)

			decodedSBOM, formatID, _, err := Decode(bytes.NewReader(encoded))
			assert.NoError(t, err)
			assert.Equal(t, syftjson.ID, formatID)
			assert.NotNil(t, decodedSBOM)
		})
	}
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
