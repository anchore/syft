package java

import (
	"bytes"
	"io"
	"math"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/internal/unionreader"
)

func TestSymbolOffset(t *testing.T) {
	tests := []struct {
		name        string
		addr        uint64
		sectionBase uint64
		wantOffset  uint64
		wantErr     bool
	}{
		{
			name:        "addr below section base underflows if unchecked, so it must error instead",
			addr:        0x900,
			sectionBase: 0x1000,
			wantErr:     true,
		},
		{
			name:        "addr equal to section base gives offset zero",
			addr:        0x1000,
			sectionBase: 0x1000,
			wantOffset:  0,
		},
		{
			name:        "addr above section base gives the exact delta",
			addr:        0x1010,
			sectionBase: 0x1000,
			wantOffset:  0x10,
		},
		{
			name:        "zero section base succeeds for any addr",
			addr:        0x2a,
			sectionBase: 0,
			wantOffset:  0x2a,
		},
		{
			name:        "max addr and max section base are equal, so offset is zero",
			addr:        math.MaxUint64,
			sectionBase: math.MaxUint64,
			wantOffset:  0,
		},
		{
			name:        "max addr against a zero section base gives the max delta",
			addr:        math.MaxUint64,
			sectionBase: 0,
			wantOffset:  math.MaxUint64,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := symbolOffset(tt.addr, tt.sectionBase)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantOffset, got)
		})
	}
}

// readerFromFixture opens a testdata fixture and wraps it the same way processLocation does before
// handing it to fetchPkgs.
func readerFromFixture(t *testing.T, path string) unionreader.UnionReader {
	t.Helper()
	f, err := os.Open(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = f.Close() })

	reader, err := unionreader.GetUnionReader(io.NopCloser(f))
	require.NoError(t, err)
	return reader
}

// neither fixture is a native image, so both exercise the path where a format matches and its fetchPkgs
// then fails, which the break at the end of the format loop makes final.
//
// the break itself cannot be distinguished from the old fall-through here: ELF, Mach-O and PE magics are
// mutually exclusive, so no fixture can validly parse as two formats. Nothing reaches the branch that
// attaches location to each package either, since no committed fixture is a real native image with an
// embedded SBOM.
func TestFetchPkgs(t *testing.T) {
	tests := []struct {
		name    string
		fixture string
	}{
		{
			name:    "real native image without SBOM symbols",
			fixture: "testdata/java-builds/packages/example-java-app",
		},
		{
			name:    "real Mach-O that is not a native image",
			fixture: "testdata/java-builds/packages/gcc-amd64-darwin-exec-debug",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := readerFromFixture(t, tt.fixture)
			location := file.NewLocation(tt.fixture)

			require.NotPanics(t, func() {
				gotPkgs, gotRels := fetchPkgs(reader, location)
				assert.Empty(t, gotPkgs)
				assert.Empty(t, gotRels)
			})
		})
	}
}

// covers macho.NewFile failing with something other than *macho.FormatError. Garbage bytes take the
// FormatError branch and return (nil, nil); a valid magic with nothing behind it does not.
func TestNewMachO_TruncatedFileIsARealFailure(t *testing.T) {
	// a valid Mach-O magic with nothing behind it yields io.ErrUnexpectedEOF, not a *macho.FormatError
	_, err := newMachO("truncated", bytes.NewReader([]byte{0xcf, 0xfa, 0xed, 0xfe}))
	require.ErrorContains(t, err, "unable to read executable")
}

func TestFetchPkgs_GarbageBytesYieldsNothing(t *testing.T) {
	// bytes that match none of ELF, Mach-O or PE magic numbers
	garbage := bytes.Repeat([]byte{0xDE, 0xAD, 0xBE, 0xEF}, 256)
	reader, err := unionreader.GetUnionReader(io.NopCloser(bytes.NewReader(garbage)))
	require.NoError(t, err)

	location := file.NewLocation("garbage.bin")
	require.NotPanics(t, func() {
		pkgs, rels := fetchPkgs(reader, location)
		assert.Empty(t, pkgs)
		assert.Empty(t, rels)
	})
}
