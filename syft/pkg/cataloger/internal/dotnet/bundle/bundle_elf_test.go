package bundle

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// readSeekCloser adapts a *bytes.Reader to the unionreader.UnionReader interface (adds Close).
type readSeekCloser struct {
	*bytes.Reader
}

func (readSeekCloser) Close() error { return nil }

// buildELFWithHugeFilesz returns a minimal, parseable ELF64 whose single program header
// declares an absurd p_filesz. calculateELFEndOffset will compute a huge end offset; the
// clamp in findBundleHeaderOffsetInELF must keep the allocation bounded to the real file.
func buildELFWithHugeFilesz() []byte {
	const (
		ehSize  = 64
		phSize  = 56
		phOff   = ehSize
		phCount = 1
	)
	buf := make([]byte, ehSize+phSize)

	// e_ident
	copy(buf[0:4], []byte{0x7f, 'E', 'L', 'F'})
	buf[4] = 2 // ELFCLASS64
	buf[5] = 1 // ELFDATA2LSB
	buf[6] = 1 // EV_CURRENT

	le := binary.LittleEndian
	le.PutUint16(buf[16:], 2)       // e_type = ET_EXEC
	le.PutUint16(buf[18:], 0x3e)    // e_machine = x86-64
	le.PutUint32(buf[20:], 1)       // e_version
	le.PutUint64(buf[32:], phOff)   // e_phoff
	le.PutUint16(buf[52:], ehSize)  // e_ehsize
	le.PutUint16(buf[54:], phSize)  // e_phentsize
	le.PutUint16(buf[56:], phCount) // e_phnum
	// e_shoff/e_shnum left zero so no sections are parsed

	ph := buf[phOff:]
	le.PutUint32(ph[0:], 1)      // p_type = PT_LOAD
	le.PutUint64(ph[16:], 0)     // p_offset
	le.PutUint64(ph[32:], 1<<60) // p_filesz (bogus, attacker-controlled)
	le.PutUint64(ph[40:], 1<<60) // p_memsz
	return buf
}

func TestExtractDepsJSONFromELFBundle_MalformedFileszDoesNotOverAllocate(t *testing.T) {
	data := buildELFWithHugeFilesz()
	r := readSeekCloser{bytes.NewReader(data)}

	// must not OOM/panic on the bogus p_filesz, and find no bundle signature
	content, err := ExtractDepsJSONFromELFBundle(r)
	require.NoError(t, err)
	assert.Empty(t, content)
}
