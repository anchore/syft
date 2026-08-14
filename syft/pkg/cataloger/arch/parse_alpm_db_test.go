package arch

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"os"
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
func gzipOfRepeated(t *testing.T, payload byte, n int64) io.Reader {
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

func Test_parseMtree_boundsDecompressedSize(t *testing.T) {
	// the limits come from the fixture rather than the production constants so both sides of the
	// boundary are exact and neither case has to allocate its way up to 64MB
	spec := mtreeSpec(50)

	t.Run("a listing at the cap parses whole", func(t *testing.T) {
		records, err := parseMtreeWithLimits(gzipOf(t, spec), int64(len(spec)), maxMtreeEntries)

		// asserting the records, not just the absence of an error: hitting the cap exactly must not
		// quietly truncate the listing, which is the failure a size check invites
		require.NoError(t, err)
		require.Len(t, records, 50)
		require.Equal(t, "/file0", records[0].Path)
		require.Equal(t, "/file49", records[49].Path)
	})

	t.Run("rejects a listing one byte past the cap", func(t *testing.T) {
		_, err := parseMtreeWithLimits(gzipOf(t, spec), int64(len(spec))-1, maxMtreeEntries)

		require.ErrorContains(t, err, "larger than the max allowed size")
	})
}

func Test_parseMtree_boundsEntryCount(t *testing.T) {
	// the byte cap alone does not bound retained memory, since the parser keeps an entry per line
	// including blank ones. Measured on this parser before the entry cap existed: 16MB of newlines,
	// well inside the byte cap, cost 8GB of peak heap and returned no records and no error.
	spec := mtreeSpec(50)
	lines := bytes.Count(spec, []byte("\n")) // the two header lines get entries of their own

	t.Run("a listing at the cap parses whole", func(t *testing.T) {
		records, err := parseMtreeWithLimits(gzipOf(t, spec), maxMtreeSize, lines)

		require.NoError(t, err)
		require.Len(t, records, 50)
	})

	t.Run("rejects a listing one entry past the cap", func(t *testing.T) {
		_, err := parseMtreeWithLimits(gzipOf(t, spec), maxMtreeSize, lines-1)

		require.ErrorContains(t, err, "more entries than allowed")
	})

	t.Run("rejects a bomb at the production limits", func(t *testing.T) {
		// the case the caps exist for: a few KB expanding to 4MB of lines, twenty times the entry cap
		// and still well inside the byte cap. Runs against parseMtree so the shipped constants are what
		// gets exercised. Kept to 4MB so that a regression here fails on the deadline below rather than
		// taking the machine down with it.
		bomb := gzipOfRepeated(t, '\n', 4*1024*1024)
		compressed := bomb.(*bytes.Reader).Size()
		require.Less(t, compressed, int64(64*1024), "payload should be small enough to be worth rejecting")

		start := time.Now()
		_, err := parseMtree(bomb)

		require.ErrorContains(t, err, "more entries than allowed")
		// it has to give up while reading rather than after materializing the listing
		require.Less(t, time.Since(start), 10*time.Second)
	})
}

func Test_parseMtree_malformedInput(t *testing.T) {
	t.Run("not gzip", func(t *testing.T) {
		_, err := parseMtree(bytes.NewReader(mtreeSpec(2)))

		require.Error(t, err)
	})

	t.Run("truncated gzip", func(t *testing.T) {
		var buf bytes.Buffer
		_, err := io.Copy(&buf, gzipOf(t, mtreeSpec(50)))
		require.NoError(t, err)

		_, err = parseMtree(bytes.NewReader(buf.Bytes()[:buf.Len()/2]))

		// a truncated listing has to fail rather than come back as a package missing most of its files
		require.Error(t, err)
	})
}
