package ai

import (
	"errors"
	"path/filepath"
	"testing"

	gguf_parser "github.com/gpustack/gguf-parser-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// gguf-parser-go derives tensor sizes from header values without validating them and
// panics on arithmetic overflow rather than returning an error - seen in production as
// "uint64 overflow in Bytes stride" on a file whose header claimed an implausible
// dimension. The header comes from an arbitrary file on disk, so that is input to reject,
// not a crash to take down the cataloger.
func TestParseGGUFFileSafelyReportsAPanicAsAnError(t *testing.T) {
	original := parseGGUFFile
	t.Cleanup(func() { parseGGUFFile = original })
	parseGGUFFile = func(string) (*gguf_parser.GGUFFile, error) {
		panic("gguf: uint64 overflow in Bytes stride: 51881467707308113 * 6400")
	}

	parsed, err := parseGGUFFileSafely("/models/llama.gguf")

	require.Error(t, err, "a panic must surface as an error")
	assert.Contains(t, err.Error(), "recovered from panic")
	assert.Contains(t, err.Error(), "uint64 overflow", "the cause must survive")
	assert.Nil(t, parsed)
}

// Ordinary parse failures must stay ordinary, not be relabelled as panics.
func TestParseGGUFFileSafelyPropagatesOrdinaryErrors(t *testing.T) {
	original := parseGGUFFile
	t.Cleanup(func() { parseGGUFFile = original })
	sentinel := errors.New("not a GGUF file")
	parseGGUFFile = func(string) (*gguf_parser.GGUFFile, error) { return nil, sentinel }

	parsed, err := parseGGUFFileSafely("/models/x.gguf")

	assert.ErrorIs(t, err, sentinel)
	assert.NotContains(t, err.Error(), "recovered from panic")
	assert.Nil(t, parsed)
}

// The real parser is still what runs in production.
func TestParseGGUFFileDefaultsToTheRealParser(t *testing.T) {
	parsed, err := parseGGUFFileSafely(filepath.Join(t.TempDir(), "absent.gguf"))

	require.Error(t, err)
	assert.NotContains(t, err.Error(), "recovered from panic")
	assert.Nil(t, parsed)
}
