package syftjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/syft/format/internal/stream"
	"github.com/anchore/syft/syft/format/internal/testutil"
)

const (
	testIdentifySchemaURL   = "https://raw.githubusercontent.com/anchore/syft/main/schema/json/schema-16.0.0.json"
	testIdentifySchemaBlock = `"schema":{"version":"16.0.0","url":"` + testIdentifySchemaURL + `"}`
)

func Test_identifyFromTailBytes(t *testing.T) {
	tests := []struct {
		name        string
		doc         string
		wantVersion string
		wantOK      bool
	}{
		{
			name:        "syft key order (schema is the last key)",
			doc:         `{"artifacts":[],"descriptor":{"name":"syft"},` + testIdentifySchemaBlock + `}`,
			wantVersion: "16.0.0",
			wantOK:      true,
		},
		{
			name:        "alphabetical key order (schema is followed by source)",
			doc:         `{"artifacts":[],` + testIdentifySchemaBlock + `,"source":{"id":"x","name":"img","type":"image","metadata":{"tags":["a","b"],"layers":[{"digest":"sha256:1"}]}}}`,
			wantVersion: "16.0.0",
			wantOK:      true,
		},
		{
			name:        "pretty printed with a trailing newline",
			doc:         "{\n  \"artifacts\": [],\n  \"schema\": {\n    \"version\": \"16.0.0\",\n    \"url\": \"" + testIdentifySchemaURL + "\"\n  }\n}\n",
			wantVersion: "16.0.0",
			wantOK:      true,
		},
		{
			name:   "nested schema key is not mistaken for the document schema",
			doc:    `{"artifacts":[{"metadata":{` + testIdentifySchemaBlock + `}}],"descriptor":{}}`,
			wantOK: false,
		},
		{
			name:        "top-level schema wins over an earlier nested one",
			doc:         `{"artifacts":[{"metadata":{"schema":{"version":"1","url":"anchore/syft"}}}],` + testIdentifySchemaBlock + `}`,
			wantVersion: "16.0.0",
			wantOK:      true,
		},
		{
			name:        "escaped schema text (with braces) inside a trailing string is ignored",
			doc:         `{"artifacts":[],` + testIdentifySchemaBlock + `,"source":{"name":"contains \"schema\":{\"version\":\"9\"} text"}}`,
			wantVersion: "16.0.0",
			wantOK:      true,
		},
		{
			name:   "array wrapped document",
			doc:    `[{"artifacts":[],` + testIdentifySchemaBlock + `}]`,
			wantOK: false,
		},
		{
			name:   "truncated document",
			doc:    `{"artifacts":[],` + testIdentifySchemaBlock,
			wantOK: false,
		},
		{
			name:   "trailing content after the document",
			doc:    `{"artifacts":[],` + testIdentifySchemaBlock + `}{"another":"document"}`,
			wantOK: false,
		},
		{
			name:   "schema value is not an object",
			doc:    `{"artifacts":[],"schema":"16.0.0"}`,
			wantOK: false,
		},
		{
			name:   "schema is a string value rather than a key",
			doc:    `{"artifacts":[],"kind":"schema"}`,
			wantOK: false,
		},
		{
			name:   "not a syft schema url",
			doc:    `{"artifacts":[],"schema":{"version":"1.0","url":"https://example.com/schema.json"}}`,
			wantOK: false,
		},
		{
			name:   "no schema key at all",
			doc:    `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}`,
			wantOK: false,
		},
		{
			name:   "schema key at the very start of the tail cannot be vouched for",
			doc:    testIdentifySchemaBlock + `}`,
			wantOK: false,
		},
		{
			name:   "empty",
			doc:    "",
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, version, ok := identifyFromTailBytes([]byte(tt.doc))
			assert.Equal(t, tt.wantOK, ok)
			assert.Equal(t, tt.wantVersion, version)
			if tt.wantOK {
				assert.Equal(t, ID, id)
			} else {
				assert.Empty(t, id)
			}
		})
	}
}

func Test_Identify_largeDocument(t *testing.T) {
	// build a document comfortably larger than the tail window so only the tail path could avoid a full parse
	unit := `{"name":"pkg","version":"1.0"},`
	padding := strings.Repeat(unit, (identifyTailSize/len(unit))+1024)
	doc := `{"artifacts":[` + padding + `{"name":"last"}],` + testIdentifySchemaBlock + `}`
	require.Greater(t, len(doc), identifyTailSize)

	t.Run("seekable reader", func(t *testing.T) {
		r := strings.NewReader(doc)

		id, version := NewFormatDecoder().Identify(r)
		assert.Equal(t, ID, id)
		assert.Equal(t, "16.0.0", version)

		// the reader is left where it started so callers can go on to read the document
		pos, err := r.Seek(0, io.SeekCurrent)
		require.NoError(t, err)
		assert.Equal(t, int64(0), pos)
	})

	t.Run("non-seekable reader falls back to a full parse", func(t *testing.T) {
		r := struct{ io.Reader }{strings.NewReader(doc)}

		id, version := NewFormatDecoder().Identify(r)
		assert.Equal(t, ID, id)
		assert.Equal(t, "16.0.0", version)
	})

	t.Run("reader positioned at a later document", func(t *testing.T) {
		first := `{"artifacts":[],"schema":{"version":"1.0.0","url":"` + testIdentifySchemaURL + `"}}`
		r := strings.NewReader(first + "\n" + doc)
		_, err := r.Seek(int64(len(first)+1), io.SeekStart)
		require.NoError(t, err)

		// mirror what the decoder collection does: seeks become relative to the current position
		sr, err := stream.SeekableReader(r)
		require.NoError(t, err)

		id, version := NewFormatDecoder().Identify(sr)
		assert.Equal(t, ID, id)
		assert.Equal(t, "16.0.0", version)

		pos, err := sr.Seek(0, io.SeekCurrent)
		require.NoError(t, err)
		assert.Equal(t, int64(0), pos)
	})
}

func Test_encoderWritesSchemaLast(t *testing.T) {
	// identification reads the schema block from the tail of the document (see model.Document), which depends on
	// the encoder always writing it as the final key
	s := testutil.DirectoryInput(t, t.TempDir())

	for _, pretty := range []bool{false, true} {
		cfg := DefaultEncoderConfig()
		cfg.Pretty = pretty

		enc, err := NewFormatEncoderWithConfig(cfg)
		require.NoError(t, err)

		var buf bytes.Buffer
		require.NoError(t, enc.Encode(&buf, s))

		keys := topLevelKeys(t, buf.Bytes())
		require.NotEmpty(t, keys)
		assert.Equal(t, "schema", keys[len(keys)-1], "pretty=%v", pretty)

		id, version, ok := identifyFromTailBytes(buf.Bytes())
		assert.True(t, ok, "pretty=%v", pretty)
		assert.Equal(t, ID, id)
		assert.Equal(t, internal.JSONSchemaVersion, version)
	}
}

// noEndSeeker behaves like a reader that buffers a stream as it goes: it can seek within what it has, but cannot
// seek relative to the end.
type noEndSeeker struct {
	io.ReadSeeker
}

func (s noEndSeeker) Seek(offset int64, whence int) (int64, error) {
	if whence == io.SeekEnd {
		return 0, errors.New("SeekEnd is not supported")
	}
	return s.ReadSeeker.Seek(offset, whence)
}

func Test_Identify_fallsBackWhenTailIsUnavailable(t *testing.T) {
	doc := `{"artifacts":[],` + testIdentifySchemaBlock + `}`
	r := noEndSeeker{strings.NewReader(doc)}

	id, version := NewFormatDecoder().Identify(r)
	assert.Equal(t, ID, id)
	assert.Equal(t, "16.0.0", version)
}

func Test_identifyFromTail_readerEdgeCases(t *testing.T) {
	doc := `{"artifacts":[],` + testIdentifySchemaBlock + `}`

	t.Run("empty reader", func(t *testing.T) {
		r := strings.NewReader("")

		_, _, ok := identifyFromTail(r)
		assert.False(t, ok)
	})

	t.Run("reader already at the end has nothing to inspect and keeps its position", func(t *testing.T) {
		r := strings.NewReader(doc)
		_, err := r.Seek(0, io.SeekEnd)
		require.NoError(t, err)

		_, _, ok := identifyFromTail(r)
		assert.False(t, ok)

		pos, err := r.Seek(0, io.SeekCurrent)
		require.NoError(t, err)
		assert.Equal(t, int64(len(doc)), pos)
	})

	t.Run("whitespace around the colon and CRLF line endings", func(t *testing.T) {
		crlf := "{\r\n  \"artifacts\": [],\r\n  \"schema\" : {\r\n    \"version\": \"16.0.0\",\r\n    \"url\": \"" + testIdentifySchemaURL + "\"\r\n  }\r\n}\r\n"

		id, version, ok := identifyFromTailBytes([]byte(crlf))
		require.True(t, ok)
		assert.Equal(t, ID, id)
		assert.Equal(t, "16.0.0", version)
	})

	t.Run("document ending inside a string is not trusted", func(t *testing.T) {
		truncated := `{"artifacts":[],` + testIdentifySchemaBlock + `,"source":{"name":"unterminated`

		_, _, ok := identifyFromTailBytes([]byte(truncated))
		assert.False(t, ok)
	})
}

func topLevelKeys(t *testing.T, doc []byte) []string {
	dec := json.NewDecoder(bytes.NewReader(doc))

	tok, err := dec.Token()
	require.NoError(t, err)
	require.Equal(t, json.Delim('{'), tok)

	var keys []string
	for dec.More() {
		tok, err := dec.Token()
		require.NoError(t, err)
		keys = append(keys, tok.(string))

		var value json.RawMessage
		require.NoError(t, dec.Decode(&value))
	}
	return keys
}
