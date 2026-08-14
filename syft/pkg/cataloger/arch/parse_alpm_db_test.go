package arch

import (
	"bufio"
	"bytes"
	"compress/gzip"
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

// gzipOf returns a gzip member that decompresses to exactly n bytes of payload repeated. The
// payload is highly compressible, which is the whole point: the caller supplies kilobytes and
// the decompressed stream is whatever size it asks for.
func gzipOf(t *testing.T, payload byte, n int64) io.Reader {
	t.Helper()

	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	chunk := bytes.Repeat([]byte{payload}, 32*1024)
	for remaining := n; remaining > 0; {
		size := int64(len(chunk))
		if remaining < size {
			size = remaining
		}
		written, err := w.Write(chunk[:size])
		require.NoError(t, err)
		remaining -= int64(written)
	}
	require.NoError(t, w.Close())

	return bytes.NewReader(buf.Bytes())
}

func Test_parseMtree_boundsDecompressedSize(t *testing.T) {
	// note: a NUL payload holds no newlines, so these exercise the byte cap without tripping the
	// entry cap first

	t.Run("rejects a listing past the cap", func(t *testing.T) {
		r := gzipOf(t, 0x00, maxMtreeSize+1)

		_, err := parseMtree(r)

		require.ErrorContains(t, err, "larger than the max allowed size")
	})

	t.Run("a listing at the cap is not rejected on size", func(t *testing.T) {
		// guards the off-by-one: at exactly the cap the size check must not fire, so whatever
		// happens next is the mtree parser's business and not ours
		r := gzipOf(t, 0x00, maxMtreeSize)

		_, err := parseMtree(r)

		if err != nil {
			require.NotContains(t, err.Error(), "larger than the max allowed size")
		}
	})
}

func Test_parseMtree_boundsEntryCount(t *testing.T) {
	// the byte cap alone does not bound retained memory, since the parser keeps an entry per line
	// including blank ones. Measured on this parser before the entry cap existed: 16MB of newlines,
	// well inside the byte cap, cost 8GB of peak heap and returned no records and no error.

	t.Run("rejects a listing with too many entries", func(t *testing.T) {
		r := gzipOf(t, '\n', maxMtreeEntries+1)

		_, err := parseMtree(r)

		require.ErrorContains(t, err, "more entries than allowed")
	})

	t.Run("a listing at the entry cap is not rejected on count", func(t *testing.T) {
		r := gzipOf(t, '\n', maxMtreeEntries)

		_, err := parseMtree(r)

		if err != nil {
			require.NotContains(t, err.Error(), "more entries than allowed")
		}
	})
}
