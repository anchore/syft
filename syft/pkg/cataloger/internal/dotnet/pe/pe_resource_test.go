package pe

import (
	"bytes"
	"encoding/binary"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// putResourceDir writes a resource directory header declaring a single ID entry, followed by that
// entry pointing at offsetToData. isDir sets the high bit, which marks the target as a subdirectory.
func putResourceDir(buf []byte, at int, offsetToData uint32, isDir bool) {
	le := binary.LittleEndian
	le.PutUint16(buf[at+12:], 0) // NumberOfNamedEntries
	le.PutUint16(buf[at+14:], 1) // NumberOfIDEntries

	entry := at + 16
	le.PutUint32(buf[entry:], 1) // Name (ID, not a string)
	if isDir {
		offsetToData |= 0x80000000
	}
	le.PutUint32(buf[entry+4:], offsetToData)
}

const (
	testSectionRVA  = 0x1000
	testSectionSize = 0x400
)

// putResourceDirN is putResourceDir for directories with more than one entry, all of them pointing at the
// same target. Aliasing like this is what the format permits and no real toolchain emits.
func putResourceDirN(buf []byte, at, n int, offsetToData uint32, isDir bool) {
	le := binary.LittleEndian
	le.PutUint16(buf[at+12:], 0)         // NumberOfNamedEntries
	le.PutUint16(buf[at+14:], uint16(n)) // NumberOfIDEntries

	if isDir {
		offsetToData |= 0x80000000
	}
	for i := range n {
		entry := at + 16 + i*8
		le.PutUint32(buf[entry:], uint32(i)) // Name (distinct IDs, not strings)
		le.PutUint32(buf[entry+4:], offsetToData)
	}
}

// boundWalk returns a walk bound to data as its resource section, as parseResourceDirectory would.
func boundWalk(data []byte) *resourceWalk {
	w := newResourceWalk()
	w.bind(bytes.NewReader(data), testSectionRVA)
	return w
}

// measureAlloc reports the bytes allocated while fn runs. The property these guards exist for is "a small
// section cannot make us reserve a large buffer", and only a byte count states that: asserting an error
// comes back would keep passing if the allocation were hoisted above the check.
func measureAlloc(t *testing.T, fn func()) uint64 {
	t.Helper()

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	fn()
	runtime.ReadMemStats(&after)

	return after.TotalAlloc - before.TotalAlloc
}

func TestParseResourceDataEntry_SizePastSectionIsRejected(t *testing.T) {
	// OffsetToData and Size are user-controlled uint32s. A data entry may only describe bytes its section
	// actually holds, otherwise Size drives the allocation.
	buf := make([]byte, testSectionSize)
	le := binary.LittleEndian
	le.PutUint32(buf[0x100:], testSectionRVA) // OffsetToData, resolves to section offset 0
	le.PutUint32(buf[0x104:], 256*1024*1024)  // a size far past the 1KB section

	w := boundWalk(buf)

	var err error
	allocated := measureAlloc(t, func() {
		err = parseResourceDataEntry(testSectionRVA+0x100, w)
	})

	require.ErrorContains(t, err, "extends past its section end")
	assert.Less(t, allocated, uint64(1<<20),
		"the declared 256MB must never be reserved, so the guard has to run before the allocation")
}

func TestParseResourceDataEntry_OffsetBeforeSectionBaseIsRejected(t *testing.T) {
	// OffsetToData is independent of baseRVA, so it can name an RVA before the section starts. The
	// subtraction that turns it into a section offset would otherwise underflow to near 4GB.
	buf := make([]byte, testSectionSize)
	le := binary.LittleEndian
	le.PutUint32(buf[0x100:], testSectionRVA-1) // OffsetToData, one byte before the section base
	le.PutUint32(buf[0x104:], 16)

	err := parseResourceDataEntry(testSectionRVA+0x100, boundWalk(buf))
	require.ErrorContains(t, err, "precedes its section base")
}

func TestParseResourceDataEntry_EntryRVAPastSectionIsRejected(t *testing.T) {
	// the entry's own RVA is as user-controlled as the data it points at
	buf := make([]byte, testSectionSize)

	err := parseResourceDataEntry(testSectionRVA+testSectionSize, boundWalk(buf))
	require.ErrorContains(t, err, "lies past its section end")
}

func TestParseResourceDirectory_SubdirectoryPastSectionIsRejected(t *testing.T) {
	// a subdirectory RVA is derived from baseRVA plus a user-controlled offset, so a child can name bytes
	// past the section its parent lives in
	buf := make([]byte, testSectionSize)
	putResourceDir(buf, 0x000, testSectionSize, true) // root -> subdirectory at the section end

	w := boundWalk(buf)
	err := parseResourceDirectoryAt(testSectionRVA, w)

	// the root loop logs and continues past a bad child, so the rejection shows up as an unvisited tree
	require.NoError(t, err)
	assert.Empty(t, w.fields)
}

func TestParseResourceDirectory_EntryCountsCannotWrap(t *testing.T) {
	// NumberOfNamedEntries and NumberOfIDEntries are uint16s that a crafted file can make sum past 0xFFFF.
	// Adding them at uint16 width would wrap to a small number and hide entries a real loader still walks.
	buf := make([]byte, testSectionSize)
	le := binary.LittleEndian
	le.PutUint16(buf[12:], 0x8000)
	le.PutUint16(buf[14:], 0x8001) // sums to 0x10001, which wraps to 1

	err := parseResourceDirectoryAt(testSectionRVA, boundWalk(buf))
	require.ErrorContains(t, err, "too many entries in resource directory")
}

func TestParseResourceDirectory_AliasedEntriesCannotAmplifyWork(t *testing.T) {
	// nothing in the format stops thousands of entries from naming one fat blob, and every individual
	// offset here is inside the section. Without a bound on total bytes read, a section this size drives
	// tens of GB of allocation and minutes of parsing, so peak memory stays flat while the scan hangs.
	const secSize = 256 * 1024
	buf := make([]byte, secSize)
	le := binary.LittleEndian

	// root: 16 subdirectories at distinct RVAs, since aliased directories are already deduped
	le.PutUint16(buf[14:], 16)
	for i := range 16 {
		entry := 16 + i*8
		le.PutUint32(buf[entry:], uint32(i))
		le.PutUint32(buf[entry+4:], uint32(0x1000+i*0x800)|0x80000000)
	}

	// each subdirectory: 4096 leaf entries, every one pointing at the same near-section-sized blob
	for i := range 16 {
		putResourceDirN(buf, 0x1000+i*0x800, 4096, 0x10000, false)
	}
	le.PutUint32(buf[0x10000:], testSectionRVA+0x20000)
	le.PutUint32(buf[0x10004:], secSize-0x20000)

	// make the blob a version resource, so each leaf that reaches it also pays for a full string-table walk
	copy(buf[0x20000:], buildVersionResource(true))

	w := newResourceWalk()
	w.bind(bytes.NewReader(buf), testSectionRVA)

	var err error
	var timedOut bool
	allocated := measureAlloc(t, func() {
		done := make(chan error, 1)
		go func() { done <- parseResourceDirectoryAt(testSectionRVA, w) }()
		select {
		case err = <-done:
		case <-time.After(30 * time.Second):
			timedOut = true
		}
	})

	require.False(t, timedOut, "the walk did not terminate")
	require.ErrorIs(t, err, errResourceBudget,
		"the walk must stop once it has read more than a well-formed section could justify")
	// the point is the asymptote, not the constant: each byte the budget allows may still be copied into a
	// blob buffer and walked, so a small multiple of the section is expected. Before the bound this same
	// input allocated about 24GB, so anything proportional is three orders of magnitude away from the bug.
	assert.Less(t, allocated, uint64(32*secSize),
		"total work must stay proportional to the section, not to the entries that alias into it")
}

// buildVersionResource returns a well-formed VS_VERSION_INFO blob whose last child is a VarFileInfo
// block, which is the layout real toolchains emit. It ends exactly on a struct boundary. When
// withFileVersionString is set, a StringFileInfo table supplies FileVersion directly.
func buildVersionResource(withFileVersionString bool) []byte {
	buf := new(bytes.Buffer)
	le := binary.LittleEndian

	putHeader := func(length, valueLength, typ uint16) {
		_ = binary.Write(buf, le, [3]uint16{length, valueLength, typ})
	}
	putUTF16 := func(s string) {
		for _, r := range s {
			_ = binary.Write(buf, le, uint16(r))
		}
		_ = binary.Write(buf, le, uint16(0))
	}
	pad := func() {
		for buf.Len()%4 != 0 {
			buf.WriteByte(0)
		}
	}

	putHeader(0, 52, 0)
	putUTF16("VS_VERSION_INFO")
	pad()

	// peVsFixedFileInfo, with FileVersionMS/LS encoding 1.2.3.4
	ffi := make([]byte, 52)
	le.PutUint32(ffi[0:], 0xFEEF04BD)  // signature
	le.PutUint32(ffi[4:], 0x00010000)  // strucVersion
	le.PutUint32(ffi[8:], 0x00010002)  // FileVersionMS -> 1.2
	le.PutUint32(ffi[12:], 0x00030004) // FileVersionLS -> 3.4
	buf.Write(ffi)

	if withFileVersionString {
		pad()
		putHeader(0, 0, 1)
		putUTF16("StringFileInfo")
		pad()
		putHeader(38, 0, 1)
		putUTF16("040904b0")
		pad()
		putHeader(0, 8, 1)
		putUTF16("FileVersion")
		pad()
		putUTF16("9.9.9.9")
	}

	// the final child: VarFileInfo -> Var("Translation") with a 4 byte value
	pad()
	putHeader(0, 0, 1)
	putUTF16("VarFileInfo")
	pad()
	putHeader(0, 4, 0)
	putUTF16("Translation")
	pad()
	_ = binary.Write(buf, le, uint32(0x04b00409))

	return buf.Bytes()
}

func TestParseVersionResourceSection_FileVersionFallback(t *testing.T) {
	// a resource ending on a struct boundary is normal termination, not a parse failure. Treating it as
	// an error skips the VS_FIXEDFILEINFO fallback below, which is the only source of a version for
	// binaries that carry no FileVersion string entry.
	tests := []struct {
		name                  string
		withFileVersionString bool
		want                  string
	}{
		{
			name: "derived from fixed file info when no string entry exists",
			want: "1.2.3.4",
		},
		{
			name:                  "string entry wins when present",
			withFileVersionString: true,
			want:                  "9.9.9.9",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fields := map[string]string{}
			require.NoError(t, parseVersionResourceSection(bytes.NewReader(buildVersionResource(tt.withFileVersionString)), fields))
			assert.Equal(t, tt.want, fields["FileVersion"])
		})
	}
}

// buildTruncatedStringTable returns version resource bytes that end exactly on a struct boundary while
// the string table header still claims 0xFFFF bytes remain. Landing precisely at EOF is the case that
// matters: one to five trailing bytes yield io.ErrUnexpectedEOF, which was always handled.
func buildTruncatedStringTable() []byte {
	buf := new(bytes.Buffer)
	putHeader := func() {
		_ = binary.Write(buf, binary.LittleEndian, [3]uint16{}) // Length, ValueLength, Type
	}
	putUTF16 := func(s string) {
		for _, r := range s {
			_ = binary.Write(buf, binary.LittleEndian, uint16(r))
		}
		_ = binary.Write(buf, binary.LittleEndian, uint16(0)) // null terminator
	}

	putHeader()
	putUTF16("VS_VERSION_INFO") // offset 38
	buf.Write([]byte{0, 0})     // pad to the DWORD boundary at 40
	buf.Write(make([]byte, 52)) // peVsFixedFileInfo -> 92

	putHeader()
	putUTF16("StringFileInfo") // -> 128

	// the string table header claims far more content than the file carries
	_ = binary.Write(buf, binary.LittleEndian, [3]uint16{0xFFFF, 0, 0})
	putUTF16("040904b0") // -> 152, then EOF

	return buf.Bytes()
}

func TestParseVersionResourceSection_TruncatedStringTableTerminates(t *testing.T) {
	data := buildTruncatedStringTable()

	done := make(chan error, 1)
	go func() {
		done <- parseVersionResourceSection(bytes.NewReader(data), map[string]string{})
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		// a reader parked at EOF used to be reported as a successful read of a zeroed struct, so the
		// string table loop consumed nothing, advanced nothing, and never reached its length bound
		require.FailNow(t, "parseVersionResourceSection did not terminate",
			"a %d-byte resource blob must not spin forever", len(data))
	}
}
