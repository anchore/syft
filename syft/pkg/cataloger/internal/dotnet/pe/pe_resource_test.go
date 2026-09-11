package pe

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	intFile "github.com/anchore/syft/internal/file"
)

const (
	testSectionRVA  = 0x1000
	testSectionSize = 0x400
)

// putResourceDirN writes a resource directory header declaring n ID entries, all of them pointing at the
// same target. isDir sets the high bit, which marks that target as a subdirectory. Aliasing every entry
// onto one target is what the format permits and no real toolchain emits.
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

// boundWalk returns a walk over data as its resource section, as parseResourceDirectory would.
func boundWalk(data []byte) *resourceWalk {
	return newResourceWalk(bytes.NewReader(data), testSectionRVA)
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
	le.PutUint32(buf[0x104:], 256*intFile.MB) // a size far past the 1KB section

	err := parseResourceDataEntry(testSectionRVA+0x100, boundWalk(buf))

	// note: this pins the bound, not an allocation. A single-level entry was already rejected before this
	// change (by comparing against the section size), it just said so differently, so an allocation
	// assertion here would pass with or without the fix. TestParseResourceDirectory_NestedOffsetsCannotUnderflow
	// is the one that holds the allocation property, because that is the shape that used to slip through.
	require.ErrorContains(t, err, "extends past its section end")
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
	putResourceDirN(buf, 0x000, 1, testSectionSize, true) // root -> subdirectory at the section end

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
	const secSize = 256 * intFile.KB
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

	w := boundWalk(buf)

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
	// expressed in terms of the factor so raising the budget cannot silently widen what this accepts
	assert.Less(t, allocated, uint64(8*peResourceBudgetFactor*secSize),
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
// the string table header still claims 0xFFFF bytes remain. Landing precisely at EOF is one of two cases
// that matter; trailing bytes that cut a struct in half are the other, covered by
// TestParseVersionResourceSection_TrailingBytesKeepFileVersion.
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

func TestParseResourceDirectory_DeepChainCannotOverflowTheStack(t *testing.T) {
	// a chain of directories at distinct RVAs, each naming the next. Every offset is inside the section and
	// every RVA is distinct, so neither the dirs set (which only catches a repeated RVA) nor the byte budget
	// (which scales with the section) stops it. Unbounded, this recurses until the goroutine stack hits the
	// process limit, and Go answers that with a fatal error no recover() can catch: the whole scan dies.
	//
	// the stride is 12 bytes, the tightest packing where each directory's counts and its single entry do not
	// collide with its neighbours' (dir k reads counts at 12k+12 and its entry at 12k+16, while dir k+1 reads
	// counts at 12k+24).
	const stride = 12
	const levels = 200

	buf := make([]byte, stride*(levels+4))
	le := binary.LittleEndian
	for k := range levels {
		at := stride * k
		le.PutUint16(buf[at+14:], 1)                               // one ID entry
		le.PutUint32(buf[at+16:], uint32(k))                       // Name (distinct ID)
		le.PutUint32(buf[at+20:], uint32(stride*(k+1))|0x80000000) // -> next directory
	}

	w := boundWalk(buf)
	err := parseResourceDirectoryAt(testSectionRVA, w)

	require.ErrorIs(t, err, errResourceDepth,
		"a chain deeper than the cap must be rejected rather than recursed into")
	assert.LessOrEqual(t, w.depth, peMaxResourceDirectoryDepth,
		"the depth counter must unwind as the walk returns")
}

func TestParseResourceDirectory_NestedOffsetsCannotUnderflow(t *testing.T) {
	// the shape that used to authorize a ~4.29GB allocation out of a 1KB section. Each level's offset is
	// individually smaller than the section, so each directory header reads fine, but the old walk tracked a
	// uint32 "remaining size" and subtracted each level's offset from it. By the third level that subtraction
	// underflowed to near 4GB, and a leaf declaring a size just under it then passed the bounds check and
	// sized the buffer from it.
	buf := make([]byte, testSectionSize)
	le := binary.LittleEndian

	putResourceDirN(buf, 0x000, 1, 0x300, true)  // root -> level 2
	putResourceDirN(buf, 0x300, 1, 0x300, true)  // level 2 -> level 3 (same offset, deeper)
	putResourceDirN(buf, 0x300, 1, 0x200, false) // level 3 -> data entry

	// the leaf claims almost 4GB, which the underflowed remaining size used to permit
	le.PutUint32(buf[0x200:], testSectionRVA) // OffsetToData -> section offset 0
	le.PutUint32(buf[0x204:], 0xFFFFFF00)     // Size

	w := boundWalk(buf)

	var err error
	allocated := measureAlloc(t, func() {
		err = parseResourceDirectoryAt(testSectionRVA, w)
	})

	require.NoError(t, err, "bad children are logged and skipped, so the walk itself completes")
	assert.Less(t, allocated, uint64(intFile.MB),
		"a 1KB section must never authorize a multi-gigabyte read, however deeply it is nested")
	assert.Empty(t, w.fields, "nothing in this tree is a real version resource")
}

func TestParseResourceDirectory_SelfReferentialEntryTerminates(t *testing.T) {
	// a directory whose entry names its own RVA. The dirs set is what catches this, and it is the guard the
	// budget and depth bounds cannot express, since one level of aliasing costs almost nothing.
	buf := make([]byte, testSectionSize)
	putResourceDirN(buf, 0x000, 1, 0, true) // root -> itself (offset 0)

	w := boundWalk(buf)

	done := make(chan error, 1)
	go func() { done <- parseResourceDirectoryAt(testSectionRVA, w) }()

	select {
	case err := <-done:
		require.NoError(t, err, "the self-reference is logged and skipped, not fatal")
		assert.Empty(t, w.fields)
	case <-time.After(5 * time.Second):
		require.FailNow(t, "a self-referential resource directory did not terminate")
	}
}

func TestProcessResourceEntry_HostileNameLengthIsRejected(t *testing.T) {
	// a named entry's length prefix is a user-controlled uint16, and binary.Read allocates a buffer of its
	// own on top of ours, so a name the section cannot satisfy has to be rejected before either is sized.
	//
	// note: a name that cannot be read is not fatal to the entry. The name is optional evidence (only
	// CLRDEBUGINFO matters downstream), so the walk carries on and simply does not learn it. That is why
	// these assert on the allocation and on the name not being recorded, rather than on an error: only the
	// allocation states the property these guards exist for.
	tests := []struct {
		name       string
		nameOffset uint32
		length     uint16
	}{
		{
			name:       "declared length past the end of the section",
			nameOffset: testSectionSize - 4,
			length:     0xFFFF,
		},
		{
			name:       "name offset past the end of the section",
			nameOffset: testSectionSize,
			length:     1,
		},
		{
			name:       "declared length of MaxUint16 at the section start",
			nameOffset: 0,
			length:     0xFFFF,
		},
		{
			// a zero-length name is legal and must not drive a read
			name:       "zero length name",
			nameOffset: 0x100,
			length:     0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := make([]byte, testSectionSize)
			if int(tt.nameOffset) < len(buf)-2 {
				binary.LittleEndian.PutUint16(buf[tt.nameOffset:], tt.length)
			}

			// a data entry (high bit clear on OffsetToData) with a string name (high bit set on Name)
			entry := peImageResourceDirectoryEntry{
				Name:         tt.nameOffset | 0x80000000,
				OffsetToData: 0x100,
			}

			w := boundWalk(buf)

			allocated := measureAlloc(t, func() {
				_ = processResourceEntry(entry, w)
			})

			assert.Less(t, allocated, uint64(intFile.MB),
				"a declared name length must never size a buffer the section cannot back")
			assert.False(t, w.hasCLRDebugInfo,
				"no name was readable, so none should have been recorded")
		})
	}
}

func TestProcessResourceEntry_CLRDebugInfoNameIsRecorded(t *testing.T) {
	// the one name that matters downstream, so the happy path through the length-prefixed reader is pinned
	// alongside the hostile ones above
	buf := make([]byte, testSectionSize)
	le := binary.LittleEndian

	const nameAt = 0x100
	le.PutUint16(buf[nameAt:], uint16(len(clrDebugInfoResourceName)))
	for i, r := range clrDebugInfoResourceName {
		le.PutUint16(buf[nameAt+2+i*2:], uint16(r))
	}

	w := boundWalk(buf)
	entry := peImageResourceDirectoryEntry{Name: nameAt | 0x80000000, OffsetToData: 0x200}

	_ = processResourceEntry(entry, w)

	assert.True(t, w.hasCLRDebugInfo, "a CLRDEBUGINFO resource name must be recorded")
}

func TestParseVersionResourceSection_TrailingBytesKeepFileVersion(t *testing.T) {
	// the case the isTruncated guard exists for. A version resource whose last child leaves 1 to 5 trailing
	// bytes cuts the next struct in half, which binary.Read reports as io.ErrUnexpectedEOF rather than
	// io.EOF. That used to propagate out as a parse failure, and because the failure returned early it also
	// skipped the VS_FIXEDFILEINFO fallback, so the binary lost its version entirely.
	for trailing := 0; trailing <= 6; trailing++ {
		t.Run(fmt.Sprintf("%d trailing bytes", trailing), func(t *testing.T) {
			data := append(buildVersionResource(false), make([]byte, trailing)...)

			fields := map[string]string{}
			require.NoError(t, parseVersionResourceSection(bytes.NewReader(data), fields))
			assert.Equal(t, "1.2.3.4", fields["FileVersion"],
				"a resource that runs out mid-struct must still yield the fields already collected")
		})
	}
}

func TestParseResourceDataEntry_ZeroSizeIsHandled(t *testing.T) {
	// a zero-size data entry is degenerate rather than hostile, and must not be reported as a version
	// resource or drive a read
	buf := make([]byte, testSectionSize)
	le := binary.LittleEndian
	le.PutUint32(buf[0x100:], testSectionRVA) // OffsetToData
	le.PutUint32(buf[0x104:], 0)              // Size

	w := boundWalk(buf)
	err := parseResourceDataEntry(testSectionRVA+0x100, w)

	require.Error(t, err, "an empty blob carries no version info")
	assert.Empty(t, w.fields)
}

func TestParseResourceDirectory_EmptySectionIsRejected(t *testing.T) {
	// a zero-length section means every offset is out of range, including the root's
	w := newResourceWalk(bytes.NewReader(nil), testSectionRVA)

	err := parseResourceDirectoryAt(testSectionRVA, w)
	require.ErrorContains(t, err, "lies past its section end")
}
