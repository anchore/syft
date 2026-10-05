package pe

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	syftFile "github.com/anchore/syft/syft/file"
)

// buildPE32 assembles a minimal but genuinely parseable PE32 with one section, wiring the resource and COM
// descriptor data directories to the RVAs given. A zero size leaves that directory absent.
func buildPE32(t *testing.T, resourceRVA, resourceSize, clrRVA, clrSize uint32, sectionData []byte) []byte {
	t.Helper()

	const peAt = 0x80
	const sectionRVA = 0x1000
	const sectionRaw = 0x400

	buf := make([]byte, sectionRaw)
	copy(buf, "MZ")
	binary.LittleEndian.PutUint32(buf[60:], peAt)
	copy(buf[peAt:], "PE\x00\x00")

	fh := pe.FileHeader{
		Machine:              0x14c,
		NumberOfSections:     1,
		SizeOfOptionalHeader: uint16(binary.Size(pe.OptionalHeader32{})),
	}
	hdr := new(bytes.Buffer)
	require.NoError(t, binary.Write(hdr, binary.LittleEndian, fh))

	opt := pe.OptionalHeader32{Magic: 0x10B}
	opt.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_RESOURCE] = pe.DataDirectory{VirtualAddress: resourceRVA, Size: resourceSize}
	opt.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR] = pe.DataDirectory{VirtualAddress: clrRVA, Size: clrSize}
	require.NoError(t, binary.Write(hdr, binary.LittleEndian, opt))

	sec := pe.SectionHeader32{
		VirtualAddress:   sectionRVA,
		VirtualSize:      0x1000,
		SizeOfRawData:    uint32(sectionRaw),
		PointerToRawData: uint32(sectionRaw),
	}
	copy(sec.Name[:], ".rsrc")
	require.NoError(t, binary.Write(hdr, binary.LittleEndian, sec))

	copy(buf[peAt+4:], hdr.Bytes())

	return append(buf, sectionData...)
}

func readPE(t *testing.T, data []byte) (*File, error) {
	t.Helper()

	loc := syftFile.NewLocation("test.dll")
	return Read(syftFile.NewLocationReadCloser(loc, readSeekCloser{bytes.NewReader(data)}))
}

type readSeekCloser struct{ *bytes.Reader }

func (readSeekCloser) Close() error { return nil }

func TestRead_MalformedResourceDirectoryStillYieldsAFile(t *testing.T) {
	// one malformed directory costs us the fields it would have held, not the package. Failing the whole
	// file here used to drop it from the SBOM entirely, and the pe-binary cataloger then reported an error
	// instead of a package.
	section := make([]byte, 0x400)
	// a root directory claiming counts that sum past 0xFFFF, which is rejected outright
	binary.LittleEndian.PutUint16(section[12:], 0x8000)
	binary.LittleEndian.PutUint16(section[14:], 0x8001)

	// a valid CLR header lives further into the same section, so there is still evidence to recover
	clr := peImageCore20{Cb: 72, MajorRuntimeVersion: 2, MinorRuntimeVersion: 5}
	clrBytes := new(bytes.Buffer)
	require.NoError(t, binary.Write(clrBytes, binary.LittleEndian, clr))
	copy(section[0x200:], clrBytes.Bytes())

	data := buildPE32(t, 0x1000, 0x400, 0x1200, uint32(clrBytes.Len()), section)

	f, err := readPE(t, data)

	require.NoError(t, err, "a malformed resource directory must not fail the whole file")
	require.NotNil(t, f)

	// the partial parse has to be reported rather than only reaching a trace log, or the unknowns task
	// cannot see that this file was cataloged on incomplete evidence
	require.Error(t, f.ParseErr, "the resource directory failure must be recorded")
	assert.Contains(t, f.ParseErr.Error(), "resource directory")

	// and the evidence that did parse has to survive
	assert.True(t, f.CLR.HasEvidenceOfCLR(), "the CLR header parsed fine and must still be reported")
	assert.Equal(t, uint16(2), f.CLR.MajorVersion)
}

func TestRead_UnreadableDataDirectoryStillYieldsAFile(t *testing.T) {
	// the same rule one layer down: a directory whose bytes cannot be read at all is recorded and skipped.
	// This used to be fatal, which was inconsistent with the resource walk being non-fatal a line away.
	section := make([]byte, 0x400)

	// a resource directory declaring far more than the file holds
	data := buildPE32(t, 0x1000, 0xFFFFFFF, 0, 0, section)

	f, err := readPE(t, data)

	require.NoError(t, err)
	require.NotNil(t, f)
	require.Error(t, f.ParseErr)
	assert.Contains(t, f.ParseErr.Error(), "Resource")
	assert.Empty(t, f.VersionResources)
}

func TestRead_WellFormedFileReportsNoParseError(t *testing.T) {
	// the guard against the above turning every file into a partial parse
	section := make([]byte, 0x400)
	putResourceDirN(section, 0x000, 1, 0x100, false) // root -> data entry
	binary.LittleEndian.PutUint32(section[0x100:], 0x1000+0x200)
	binary.LittleEndian.PutUint32(section[0x104:], 0x100)
	copy(section[0x200:], buildVersionResource(true))

	data := buildPE32(t, 0x1000, 0x400, 0, 0, section)

	f, err := readPE(t, data)

	require.NoError(t, err)
	require.NotNil(t, f)
	assert.NoError(t, f.ParseErr, "a file that parsed cleanly must not report a partial parse")
	assert.Equal(t, "9.9.9.9", f.VersionResources["FileVersion"])
}
