package arch

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

func TestDatabaseParser(t *testing.T) {
	tests := []struct {
		name     string
		fixture  string
		expected *parsedData
	}{
		{
			name:    "simple desc parsing",
			fixture: "testdata/files",
			expected: &parsedData{
				AlpmDBEntry: pkg.AlpmDBEntry{
					Backup: []pkg.AlpmFileRecord{
						{
							Path: "/etc/pacman.conf",
							Digests: []file.Digest{{
								Algorithm: "md5",
								Value:     "de541390e52468165b96511c4665bff4",
							}},
						},
						{
							Path: "/etc/makepkg.conf",
							Digests: []file.Digest{{
								Algorithm: "md5",
								Value:     "79fce043df7dfc676ae5ecb903762d8b",
							}},
						},
					},
					Files: []pkg.AlpmFileRecord{
						{
							Path: "/etc/",
						},
						{
							Path: "/etc/makepkg.conf",
						},
						{
							Path: "/etc/pacman.conf",
						},
						{
							Path: "/usr/",
						},
						{
							Path: "/usr/bin/",
						},
						{
							Path: "/usr/bin/makepkg",
						},
						{
							Path: "/usr/bin/makepkg-template",
						},
						{
							Path: "/usr/bin/pacman",
						},
						{
							Path: "/usr/bin/pacman-conf",
						},
						{
							Path: "/var/",
						},
						{
							Path: "/var/cache/",
						},
						{
							Path: "/var/cache/pacman/",
						},
						{
							Path: "/var/cache/pacman/pkg/",
						},
						{
							Path: "/var/lib/",
						},
						{
							Path: "/var/lib/pacman/",
						},
					},
				},
			},
		},
		{
			name:    "with dependencies",
			fixture: "testdata/installed/var/lib/pacman/local/gmp-6.2.1-2/desc",
			expected: &parsedData{
				Licenses: "LGPL3\nGPL",
				AlpmDBEntry: pkg.AlpmDBEntry{
					BasePackage:  "gmp",
					Package:      "gmp",
					Version:      "6.2.1-2",
					Description:  "A free library for arbitrary precision arithmetic",
					Architecture: "x86_64",
					Size:         1044438,
					Packager:     "Antonio Rojas <arojas@archlinux.org>",
					URL:          "https://gmplib.org/",
					Validation:   "pgp",
					Reason:       1,
					Files:        []pkg.AlpmFileRecord{},
					Backup:       []pkg.AlpmFileRecord{},
					Depends:      []string{"gcc-libs", "sh", "libtree-sitter.so=1-64"},
				},
			},
		},
		{
			name:    "with provides",
			fixture: "testdata/installed/var/lib/pacman/local/tree-sitter-0.22.6-1/desc",
			expected: &parsedData{
				Licenses: "MIT",
				AlpmDBEntry: pkg.AlpmDBEntry{
					BasePackage:  "tree-sitter",
					Package:      "tree-sitter",
					Version:      "0.22.6-1",
					Description:  "Incremental parsing library",
					Architecture: "x86_64",
					Size:         223539,
					Packager:     "Daniel M. Capella <polyzen@archlinux.org>",
					URL:          "https://github.com/tree-sitter/tree-sitter",
					Validation:   "pgp",
					Reason:       1,
					Files:        []pkg.AlpmFileRecord{},
					Backup:       []pkg.AlpmFileRecord{},
					Provides:     []string{"libtree-sitter.so=0-64"},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f, err := os.Open(test.fixture)
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, f.Close()) })

			reader := bufio.NewReader(f)

			entry, err := parseAlpmDBEntry(reader)
			require.NoError(t, err)

			if diff := cmp.Diff(test.expected, entry); diff != "" {
				t.Errorf("parsed data mismatch (-want +got):\n%s", diff)
			}

		})
	}
}

func parseTime(stime string) time.Time {
	t, _ := time.Parse(time.RFC3339, stime)
	return t
}

func TestMtreeParse(t *testing.T) {
	tests := []struct {
		name     string
		expected []pkg.AlpmFileRecord
	}{
		{
			name: "test mtree parsing",
			expected: []pkg.AlpmFileRecord{
				{
					Path:    "/etc",
					Type:    "dir",
					Time:    parseTime("2022-04-10T14:59:52+02:00"),
					Digests: make([]file.Digest, 0),
				},
				{
					Path:    "/etc/pacman.d",
					Type:    "dir",
					Time:    parseTime("2022-04-10T14:59:52+02:00"),
					Digests: make([]file.Digest, 0),
				},
				{
					Path: "/etc/pacman.d/mirrorlist",
					Size: "44683",
					Time: parseTime("2022-04-10T14:59:52+02:00"),
					Digests: []file.Digest{
						{
							Algorithm: "md5",
							Value:     "81c39827e38c759d7e847f05db62c233",
						},
						{
							Algorithm: "sha256",
							Value:     "fc135ab26f2a227b9599b66a2f1ba325c445acb914d60e7ecf6e5997a87abe1e",
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f, err := os.Open("testdata/mtree")
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, f.Close()) })

			reader := bufio.NewReader(f)

			// a normal listing must not be misidentified as a line continuation or otherwise rejected;
			// this is also the regression guard for the continuation refusal
			entry, err := parseMtree(reader)
			require.NoError(t, err)

			if diff := cmp.Diff(entry, test.expected); diff != "" {
				t.Errorf("Files mismatch (-want +got):\n%s", diff)
			}
		})
	}

}

// mtreeSpec builds a valid listing naming n files, shaped like a real one: a signature, a /set of
// shared keywords, then one line per file. The boundary tests need the parser to actually reach the
// end of the listing, which a payload of filler bytes never does.
func mtreeSpec(n int) []byte {
	var buf bytes.Buffer
	buf.WriteString("#mtree\n")
	buf.WriteString("/set type=file uid=0 gid=0 mode=644\n")
	for i := range n {
		fmt.Fprintf(&buf, "./file%d time=1649595592.0 size=10 sha256digest=%064x\n", i, i)
	}
	return buf.Bytes()
}

func gzipOf(t *testing.T, data []byte) io.Reader {
	t.Helper()

	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	_, err := w.Write(data)
	require.NoError(t, err)
	require.NoError(t, w.Close())

	return bytes.NewReader(buf.Bytes())
}

// gzipOfRepeated returns a gzip member that decompresses to n bytes of payload repeated. The payload
// is highly compressible, which is the whole point: the caller supplies kilobytes and the
// decompressed stream is whatever size it asks for.
func gzipOfRepeated(t *testing.T, payload byte, n int64) *bytes.Reader {
	t.Helper()

	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	chunk := bytes.Repeat([]byte{payload}, 32*1024)
	for remaining := n; remaining > 0; {
		size := min(remaining, int64(len(chunk)))
		written, err := w.Write(chunk[:size])
		require.NoError(t, err)
		remaining -= int64(written)
	}
	require.NoError(t, w.Close())

	return bytes.NewReader(buf.Bytes())
}

// gzipOfRepeatedLines returns a gzip member decompressing to a valid mtree listing (header plus a file
// line repeated with a padded digest) that runs past minSize. It streams the lines straight into the
// gzip writer rather than building the listing in memory first, since the repeated line compresses to
// almost nothing; only the small compressed result is ever buffered. The digest is padded rather than
// adding more keywords so each line stays well over maxMtreeSize/maxMtreeLines bytes, which keeps the
// byte cap the one that trips rather than the line cap.
func gzipOfRepeatedLines(t *testing.T, minSize int64) *bytes.Reader {
	t.Helper()

	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	_, err := w.Write([]byte("#mtree\n/set type=file uid=0 gid=0 mode=644\n"))
	require.NoError(t, err)

	var written int64
	for i := 0; written < minSize; i++ {
		n, err := fmt.Fprintf(w, "./file%d time=1649595592.0 size=10 sha256digest=%0400x\n", i, i)
		require.NoError(t, err)
		written += int64(n)
	}
	require.NoError(t, w.Close())

	return bytes.NewReader(buf.Bytes())
}

func Test_parseMtree_boundsDecompressedSize(t *testing.T) {
	// the limits come from the fixture rather than the production constants so both sides of the
	// boundary are exact and neither case has to allocate its way up to the shipped cap
	spec := mtreeSpec(50)

	t.Run("a listing at the cap parses whole", func(t *testing.T) {
		records, err := parseMtreeWithLimits(gzipOf(t, spec), int64(len(spec)), maxMtreeLines)

		// asserting the records, not just the absence of an error: hitting the cap exactly must not
		// quietly truncate the listing, which is the failure a size check invites
		require.NoError(t, err)
		require.Len(t, records, 50)
		require.Equal(t, "/file0", records[0].Path)
		require.Equal(t, "/file49", records[49].Path)
	})

	t.Run("rejects a listing one byte past the cap", func(t *testing.T) {
		_, err := parseMtreeWithLimits(gzipOf(t, spec), int64(len(spec))-1, maxMtreeLines)

		require.ErrorIs(t, err, errMtreeTooLarge)
	})
}

// Test_parseMtree_enforcesShippedSizeCap pins the actual production constant rather than a fixture
// value. The boundary tests above parameterize maxSize on the spec they build, so they would still
// pass unchanged even if maxMtreeSize regressed to something far smaller; this drives parseMtree,
// which uses the real constants, with a listing generated on the fly so exceeding it doesn't mean
// holding tens of megabytes in the test.
func Test_parseMtree_enforcesShippedSizeCap(t *testing.T) {
	bomb := gzipOfRepeatedLines(t, maxMtreeSize+1)

	_, err := parseMtree(bomb)

	require.ErrorIs(t, err, errMtreeTooLarge)
}

func Test_parseMtree_boundsLineCount(t *testing.T) {
	// the byte cap alone does not bound retained memory, since the parser keeps an entry per line
	// including blank ones
	spec := mtreeSpec(50)
	lines := bytes.Count(spec, []byte("\n")) // the two header lines get entries of their own

	t.Run("a listing at the cap parses whole", func(t *testing.T) {
		records, err := parseMtreeWithLimits(gzipOf(t, spec), maxMtreeSize, lines)

		require.NoError(t, err)
		require.Len(t, records, 50)
	})

	t.Run("rejects a listing one line past the cap", func(t *testing.T) {
		_, err := parseMtreeWithLimits(gzipOf(t, spec), maxMtreeSize, lines-1)

		require.ErrorIs(t, err, errTooManyMtreeLines)
	})

	t.Run("rejects a bomb at the production limits without the allocation the bomb is asking for", func(t *testing.T) {
		// the case the cap exists for: a few KB expanding to many times the line cap, well inside the
		// byte cap. Runs against parseMtree so the shipped constants are what gets exercised.
		bomb := gzipOfRepeated(t, '\n', 4*1024*1024)
		require.Less(t, bomb.Size(), int64(64*1024), "payload should be small enough to be worth rejecting")

		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)

		_, err := parseMtree(bomb)

		runtime.ReadMemStats(&after)

		// it has to give up while reading rather than after materializing the whole listing
		require.ErrorIs(t, err, errTooManyMtreeLines)

		// loose on purpose: pinning "an order of magnitude below what letting the bomb through would
		// cost", not a precise budget. Tripping the cap still means parsing up to maxMtreeLines blank
		// entries before the error surfaces, which alone runs in the hundreds of MB.
		const margin = 512 * 1024 * 1024
		require.Less(t, after.TotalAlloc-before.TotalAlloc, uint64(margin),
			"parsing allocated far more than tripping the cap warrants")
	})
}

// Test_parseMtree_sizeCapTakesPrecedenceOverLineCap pins the order in parseMtreeWithLimits: the size
// check runs before the line-count error is inspected, so when both bounds are exceeded by the same
// underlying read, the size sentinel is what a caller sees. A future reorder that swapped this would
// flip this test rather than staying invisible in the boundary tests above, which never exceed both
// bounds at once.
func Test_parseMtree_sizeCapTakesPrecedenceOverLineCap(t *testing.T) {
	spec := mtreeSpec(50)

	// maxLines=0 guarantees the first newline in the listing already exceeds it, and maxSize=20 is
	// small enough that the single read delivering that newline also exhausts the byte budget
	_, err := parseMtreeWithLimits(gzipOf(t, spec), 20, 0)

	require.ErrorIs(t, err, errMtreeTooLarge)
	require.NotErrorIs(t, err, errTooManyMtreeLines)
}

func Test_parseMtree_rejectsLineContinuations(t *testing.T) {
	// go-mtree's scanner drops a trailing carriage return before testing the line for a backslash
	// suffix, so both spellings reach its quadratic collapse and both have to be refused. Matching
	// only the LF spelling leaves the CRLF one costing minutes inside both other bounds.
	for _, lineEnding := range []string{"\\\n", "\\\r\n"} {
		t.Run(fmt.Sprintf("%q", lineEnding), func(t *testing.T) {
			spec := mtreeSpec(5)
			spec = bytes.Replace(spec, []byte("size=10 sha256digest="), []byte("size=10 "+lineEnding+"sha256digest="), 1)

			_, err := parseMtree(gzipOf(t, spec))

			require.ErrorIs(t, err, errMtreeLineContinued)
		})
	}
}

// scriptedReader replays a fixed sequence of Read results, letting the straddling case be driven
// directly without a real gzip/mtree round trip.
type scriptedReader struct {
	chunks []string
}

func (r *scriptedReader) Read(p []byte) (int, error) {
	if len(r.chunks) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.chunks[0])
	// keep whatever did not fit rather than dropping it, so the helper obeys the io.Reader contract
	// even when a caller hands it a buffer shorter than a scripted chunk
	if n < len(r.chunks[0]) {
		r.chunks[0] = r.chunks[0][n:]
	} else {
		r.chunks = r.chunks[1:]
	}
	return n, nil
}

func Test_lineLimitedReader_rejectsStraddlingContinuation(t *testing.T) {
	// the backslash and the line ending it continues arrive in separate Read calls; lineLimitedReader
	// has to remember the trailing byte of the previous chunk to catch this. Reachable in production:
	// the io.LimitedReader truncates the buffer and flate returns short reads at window boundaries.
	tests := []struct {
		name   string
		chunks []string
	}{
		{name: "lf", chunks: []string{"...\\", "\n..."}},
		{name: "crlf", chunks: []string{"...\\", "\r\n..."}},
		{name: "crlf split at the carriage return", chunks: []string{"...\\\r", "\n..."}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lr := &lineLimitedReader{reader: &scriptedReader{chunks: tt.chunks}, max: 100}

			var err error
			buf := make([]byte, 16)
			for err == nil {
				_, err = lr.Read(buf)
			}

			require.ErrorIs(t, err, errMtreeLineContinued)
		})
	}
}

func Test_lineLimitedReader_latchesTheError(t *testing.T) {
	// a tripped bound must not come back clean on the next read, whatever that chunk holds
	lr := &lineLimitedReader{reader: &scriptedReader{chunks: []string{"a\\\nb", "clean"}}, max: 100}

	buf := make([]byte, 16)
	_, first := lr.Read(buf)
	require.ErrorIs(t, first, errMtreeLineContinued)

	n, second := lr.Read(buf)

	require.ErrorIs(t, second, errMtreeLineContinued)
	require.Zero(t, n)
}

func Test_parseMtree_malformedInput(t *testing.T) {
	t.Run("not gzip", func(t *testing.T) {
		_, err := parseMtree(bytes.NewReader(mtreeSpec(2)))

		require.ErrorIs(t, err, gzip.ErrHeader)
	})

	t.Run("truncated gzip", func(t *testing.T) {
		var buf bytes.Buffer
		_, err := io.Copy(&buf, gzipOf(t, mtreeSpec(50)))
		require.NoError(t, err)

		_, err = parseMtree(bytes.NewReader(buf.Bytes()[:buf.Len()/2]))

		// a truncated listing has to fail rather than come back as a package missing most of its files,
		// and it must not be misreported as tripping the size bound
		require.Error(t, err)
		require.NotErrorIs(t, err, errMtreeTooLarge)
	})
}
