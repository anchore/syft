package java

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"io"
	"math"
	"testing"
	"time"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	intFile "github.com/anchore/syft/internal/file"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
)

// pins the bound at the byte where an attribute ends flush with the directory: `j+sz > n` (not `>=`) is
// what lets attribute 3 be read out of a 36-byte exports buffer, since bytes 32:36 are entirely present.
func TestFetchExportAttribute(t *testing.T) {
	// the four attributes fetchExportContent reads start right after this header
	require.EqualValues(t, 20, unsafe.Sizeof(exportPrefixPE{}))

	tests := []struct {
		name      string
		exports   []byte
		index     int
		wantValue uint32
		wantErr   bool
	}{
		{
			name:    "one byte short of attribute 3 is rejected",
			exports: make([]byte, 35),
			index:   3,
			wantErr: true,
		},
		{
			name: "attribute 3 flush with the end of exports is read",
			exports: func() []byte {
				b := make([]byte, 36)
				binary.LittleEndian.PutUint32(b[32:36], 0xDEADBEEF)
				return b
			}(),
			index:     3,
			wantValue: 0xDEADBEEF,
		},
		{
			name: "attribute 0 reads the first attribute slot",
			exports: func() []byte {
				b := make([]byte, 24)
				binary.LittleEndian.PutUint32(b[20:24], 42)
				return b
			}(),
			index:     0,
			wantValue: 42,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ni := nativeImagePE{exports: tt.exports}
			got, err := ni.fetchExportAttribute(tt.index)
			if tt.wantErr {
				require.ErrorContains(t, err, nativeImageInvalidIndexError)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantValue, got)
		})
	}
}

// pins the uint32->uint64 widening: computing `functionsBase + i*sz` in uint32 wraps a huge base back
// into range instead of erroring.
func TestFetchExportFunctionPointer(t *testing.T) {
	tests := []struct {
		name          string
		exports       []byte
		functionsBase uint32
		index         uint32
		wantValue     uint32
		wantErr       bool
	}{
		{
			name:          "functionsBase near the uint32 max must not wrap back into range",
			exports:       make([]byte, 64),
			functionsBase: 0xFFFFFFFF,
			index:         1,
			wantErr:       true,
		},
		{
			name: "an in-range function pointer is read",
			exports: func() []byte {
				b := make([]byte, 64)
				binary.LittleEndian.PutUint32(b[16:20], 0xCAFEBABE)
				return b
			}(),
			functionsBase: 8,
			index:         2,
			wantValue:     0xCAFEBABE,
		},
		{
			name: "a pointer flush with the end of exports is read",
			exports: func() []byte {
				b := make([]byte, 64)
				binary.LittleEndian.PutUint32(b[60:64], 0x11223344)
				return b
			}(),
			functionsBase: 60,
			index:         0,
			wantValue:     0x11223344,
		},
		{
			name:          "a pointer straddling the end of exports",
			exports:       make([]byte, 64),
			functionsBase: 62,
			index:         0,
			wantErr:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ni := nativeImagePE{exports: tt.exports}
			var got uint32
			var err error
			require.NotPanics(t, func() {
				got, err = ni.fetchExportFunctionPointer(tt.functionsBase, tt.index)
			})
			if tt.wantErr {
				require.ErrorContains(t, err, nativeImageInvalidIndexError)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantValue, got)
		})
	}
}

// addressOfNames below the directory's VirtualAddress. VirtualAddress is deliberately huge so the
// underflow lands back in range; a small one would let an unrelated bound mask this guard's absence.
func TestFetchSbomSymbols_NameArrayPrecedingDirectoryGuard(t *testing.T) {
	va := uint32(0xFFFFFFF0)
	addressOfNames := uint32(5)
	wrapped := addressOfNames - va // what addressBase would be if the guard were missing
	require.Less(t, wrapped, uint32(32), "the fixture only proves the guard's necessity if the wrap lands in range")

	exports := make([]byte, 32)
	le := binary.LittleEndian
	// a name pointer table here would only be reached without the guard
	le.PutUint32(exports[wrapped:], va+10)  // index 0: resolves to a non-matching name
	le.PutUint32(exports[wrapped+4:], va+5) // index 1: resolves to "sbom"
	copy(exports[10:], "zzzz\x00")
	copy(exports[5:], nativeImageSbomSymbol+"\x00")

	ni := nativeImagePE{exports: exports, exportSymbols: pe.DataDirectory{VirtualAddress: va}}
	content := &exportContentPE{addressOfNames: addressOfNames, numberOfNames: 2}

	require.NotPanics(t, func() { ni.fetchSbomSymbols(content) })
	assert.Zero(t, content.addressOfSbom, "addressOfNames below the directory must not be read at all")
	assert.Zero(t, content.addressOfSbomLength)
	assert.Zero(t, content.addressOfSvmVersion)
}

// a name pointer entry resolving below the directory. Same reasoning as the addressOfNames guard above.
func TestFetchSbomSymbols_SymbolAddressPrecedingDirectoryGuard(t *testing.T) {
	va := uint32(0xFFFFFFF0)
	exports := make([]byte, 32)
	le := binary.LittleEndian
	le.PutUint32(exports[0:4], va+10) // index 0: resolves to a non-matching name
	le.PutUint32(exports[4:8], 5)     // index 1: a symbolAddress below the directory

	wrapped := uint32(5) - va // what symbolBase would be for index 1 if the guard were missing
	require.Less(t, wrapped, uint32(32), "the fixture only proves the guard's necessity if the wrap lands in range")
	copy(exports[10:], "zzzz\x00")
	copy(exports[wrapped:], nativeImageSbomSymbol+"\x00")

	ni := nativeImagePE{exports: exports, exportSymbols: pe.DataDirectory{VirtualAddress: va}}
	content := &exportContentPE{addressOfNames: va, numberOfNames: 2}

	require.NotPanics(t, func() { ni.fetchSbomSymbols(content) })
	assert.Zero(t, content.addressOfSbom, "a symbolAddress below the directory must not be read as a name")
	assert.Zero(t, content.addressOfSbomLength)
	assert.Zero(t, content.addressOfSvmVersion)
}

// a symbolBase past the end of exports. Needs no wraparound: without the guard the slice is simply out
// of range and panics.
func TestFetchSbomSymbols_SymbolBaseOutOfRangeGuard(t *testing.T) {
	const va = uint32(0x2000)
	exports := make([]byte, 8)
	binary.LittleEndian.PutUint32(exports[0:4], va+13) // symbolBase would be 13, past an 8-byte buffer

	ni := nativeImagePE{exports: exports, exportSymbols: pe.DataDirectory{VirtualAddress: va}}
	content := &exportContentPE{addressOfNames: va, numberOfNames: 1}

	require.NotPanics(t, func() { ni.fetchSbomSymbols(content) })
	assert.Zero(t, content.addressOfSbom)
	assert.Zero(t, content.addressOfSbomLength)
	assert.Zero(t, content.addressOfSvmVersion)
}

// addressBase past the end of exports. Every other fixture has addressBase == 0, so this is the only case
// reaching the `k > n` half: without it `n-k` underflows, clears the size check, and the slice panics.
func TestFetchSbomSymbols_AddressBaseOutOfRangeGuard(t *testing.T) {
	const va = uint32(0x2000)
	exports := make([]byte, 16)

	ni := nativeImagePE{exports: exports, exportSymbols: pe.DataDirectory{VirtualAddress: va}}
	content := &exportContentPE{addressOfNames: 0x2064, numberOfNames: 1} // addressBase = 0x64 = 100, past exports

	require.NotPanics(t, func() { ni.fetchSbomSymbols(content) })
	assert.Zero(t, content.addressOfSbom)
	assert.Zero(t, content.addressOfSbomLength)
	assert.Zero(t, content.addressOfSvmVersion)
}

// TestFetchSbomSymbols_FindsAllThreeSymbols is the happy path. fetchSbomSymbols records the loop index
// of a match, not its address.
func TestFetchSbomSymbols_FindsAllThreeSymbols(t *testing.T) {
	const va = 0x2000
	exports := make([]byte, 96)
	le := binary.LittleEndian

	// name pointer table: one uint32 RVA per name, in loop order.
	// name pointer table: one uint32 RVA per name, in loop order. note fetchPkgs treats a stored index of 0
	// as "symbol not found", so no symbol may sit at index 0 or this would pass for the wrong reason
	le.PutUint32(exports[0:4], va+52)   // index 0: an unrelated name
	le.PutUint32(exports[4:8], va+57)   // index 1: "sbom"
	le.PutUint32(exports[8:12], va+62)  // index 2: "sbom_length"
	le.PutUint32(exports[12:16], va+74) // index 3: "__svm_version_info"

	copy(exports[52:], "xxxx\x00")
	copy(exports[57:], nativeImageSbomSymbol+"\x00")
	copy(exports[62:], nativeImageSbomLengthSymbol+"\x00")
	copy(exports[74:], nativeImageSbomVersionSymbol+"\x00")

	ni := nativeImagePE{exports: exports, exportSymbols: pe.DataDirectory{VirtualAddress: va}}
	content := &exportContentPE{addressOfNames: va, numberOfNames: 4}
	ni.fetchSbomSymbols(content)

	assert.EqualValues(t, 1, content.addressOfSbom)
	assert.EqualValues(t, 2, content.addressOfSbomLength)
	assert.EqualValues(t, 3, content.addressOfSvmVersion)
}

// numberOfNames is read straight out of the file, so a hostile binary can claim ~4 billion names. The
// scan must stop when the name pointer table runs off the end of exports, not iterate that far.
func TestFetchSbomSymbols_HugeNameCountTerminatesQuickly(t *testing.T) {
	exports := make([]byte, 16) // room for exactly 4 name pointer table entries
	ni := nativeImagePE{exports: exports, exportSymbols: pe.DataDirectory{VirtualAddress: 0}}
	content := &exportContentPE{addressOfNames: 0, numberOfNames: math.MaxUint32}

	start := time.Now()
	require.NotPanics(t, func() { ni.fetchSbomSymbols(content) })
	assert.Less(t, time.Since(start), time.Second,
		"the scan must stop at the end of exports, not loop numberOfNames times")
}

// the one guard in fetchPkgs reachable without a real *pe.File: addressOfFunctions below the export
// directory base must error rather than underflow into a huge functionsBase.
func TestFetchPkgs_AddressOfFunctionsPrecedingDirectoryErrors(t *testing.T) {
	const va = 0x2000
	exports := make([]byte, 96)
	le := binary.LittleEndian

	// the four attributes fetchExportContent reads
	le.PutUint32(exports[20:24], 10)   // numberOfFunctions (unused before the guard under test)
	le.PutUint32(exports[24:28], 4)    // numberOfNames
	le.PutUint32(exports[28:32], va-1) // addressOfFunctions: precedes the export directory
	le.PutUint32(exports[32:36], va+36)

	// name pointer table at offset 36, resolving all three SBOM symbols so the guard under test is
	// reached instead of the earlier "missing symbols" return
	le.PutUint32(exports[36:40], va+52)
	le.PutUint32(exports[40:44], va+57)
	le.PutUint32(exports[44:48], va+62)
	le.PutUint32(exports[48:52], va+74)
	copy(exports[52:], "xxxx\x00")
	copy(exports[57:], nativeImageSbomSymbol+"\x00")
	copy(exports[62:], nativeImageSbomLengthSymbol+"\x00")
	copy(exports[74:], nativeImageSbomVersionSymbol+"\x00")

	ni := nativeImagePE{exports: exports, exportSymbols: pe.DataDirectory{VirtualAddress: va}}

	var pkgs []pkg.Package
	var rels []artifact.Relationship
	var err error
	require.NotPanics(t, func() {
		pkgs, rels, err = ni.fetchPkgs()
	})
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "recovered from panic",
		"the guard must reject this cleanly, not rely on the recover")
	assert.Contains(t, err.Error(), "exported function array precedes the export directory")
	assert.Empty(t, pkgs)
	assert.Empty(t, rels)
}

// the three outcomes of weighing a declared size against both the cap and the bytes the file really has.
func TestReadExportDirectory(t *testing.T) {
	t.Run("size over the cap is rejected", func(t *testing.T) {
		dir := pe.DataDirectory{VirtualAddress: 0, Size: nativeImageMaxExportDirectorySize + 1}
		_, err := readExportDirectory(bytes.NewReader(make([]byte, 1024)), dir)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "byte limit")
	})

	t.Run("a size the file cannot satisfy is rejected", func(t *testing.T) {
		dir := pe.DataDirectory{VirtualAddress: 0, Size: 600}
		_, err := readExportDirectory(bytes.NewReader(make([]byte, 512)), dir)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "remain")
	})

	t.Run("a size the file can exactly satisfy succeeds", func(t *testing.T) {
		data := make([]byte, 200)
		binary.LittleEndian.PutUint32(data[100:104], 0xABCDEF01)
		dir := pe.DataDirectory{VirtualAddress: 100, Size: 100} // remaining bytes (200-100) exactly

		got, err := readExportDirectory(bytes.NewReader(data), dir)
		require.NoError(t, err)
		require.Len(t, got, 100)
		assert.Equal(t, uint32(0xABCDEF01), binary.LittleEndian.Uint32(got[0:4]))
	})

	t.Run("a reader that cannot report its size is rejected", func(t *testing.T) {
		data := make([]byte, 64)
		r := struct{ io.ReaderAt }{bytes.NewReader(data)} // promotes ReadAt only, no Size() or Seek
		dir := pe.DataDirectory{VirtualAddress: 0, Size: 32}

		_, err := readExportDirectory(r, dir)
		require.ErrorContains(t, err, "unable to measure the binary")
	})
}

// proves the remaining-bytes guard, not just the cap: a small, cheap file can still declare a size under
// the cap, and only the bytes really present can reject it before the read and its allocation.
func TestReadExportDirectory_DoesNotReadThePhantomBytes(t *testing.T) {
	const realSize = 4096
	rec := &readSizeRecorder{Reader: bytes.NewReader(make([]byte, realSize))}
	dir := pe.DataDirectory{VirtualAddress: 0, Size: nativeImageMaxExportDirectorySize}

	allocated := measureAlloc(t, func() {
		_, err := readExportDirectory(rec, dir)
		// a Size exactly at the cap must fall through to the remaining-bytes check, not be capped away;
		// pins the `>` (not `>=`) in the cap comparison
		require.ErrorContains(t, err, "remain")
	})

	t.Logf("allocated %d bytes for a directory declaring %d against a %d byte file", allocated, dir.Size, realSize)
	assert.Less(t, allocated, uint64(intFile.MB),
		"rejecting an oversized declaration must not first allocate against it")
	assert.LessOrEqual(t, rec.maxRead, realSize,
		"no read should ask for more than the file actually holds")
}

// shortReader has 64 addressable bytes but hands back fewer than asked with a nil error, the
// non-conforming shape syft/internal/unionreader documents for squashfs
type shortReader struct {
	b       []byte
	perRead int
}

func (s shortReader) Size() int64 { return int64(len(s.b)) }

func (s shortReader) ReadAt(p []byte, off int64) (int, error) {
	if len(p) == 1 { // intFile.ReaderSize probes the last byte, and that probe has to succeed
		p[0] = s.b[off]
		return 1, nil
	}
	return copy(p[:s.perRead], s.b[off:off+int64(s.perRead)]), nil
}

// regression for the real defect: a ReadAt handing back fewer bytes than asked with a nil error used to
// be accepted, and the zeroed tail of the buffer parsed as export directory data.
func TestReadExportDirectory_RejectsShortReadWithNilError(t *testing.T) {
	tests := []struct {
		name    string
		perRead int
	}{
		{name: "reader answers with zero bytes and a nil error", perRead: 0},
		{name: "reader answers with a partial read and a nil error", perRead: 4},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := shortReader{b: make([]byte, 64), perRead: tt.perRead}
			dir := pe.DataDirectory{VirtualAddress: 0, Size: 32}

			_, err := readExportDirectory(r, dir)
			require.ErrorContains(t, err, "read")
		})
	}
}
