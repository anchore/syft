package archive

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"io/fs"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mholt/archives"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	stereoscopeFile "github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/syft/syft/file"
)

var sampleFiles = map[string]string{
	"file1.txt":     "content1",
	"dir/file2.txt": "content2",
}

func Test_identifyFormat(t *testing.T) {
	ctx := context.Background()
	launcher := append([]byte("#!/bin/bash\nexec java -jar \"$0\" \"$@\"\nexit 0\n"), zipBytes(t, sampleFiles)...)

	tests := []struct {
		name        string
		data        []byte
		want        archives.Extractor
		unsupported bool
	}{
		{"test.zip", zipBytes(t, sampleFiles), archives.Zip{}, false},
		{"test.tar.gz", tarGzBytes(t, sampleFiles), archives.CompressedArchive{}, false},
		{"plain.txt", []byte("just text"), nil, false},
		// identified by mholt, but not opened until their decoders are deliberately supported
		{"test.7z", []byte("7z\xbc\xaf\x27\x1c\x00\x04"), nil, true},
		{"test.rar", []byte("Rar!\x1a\x07\x01\x00"), nil, true},
		// a bare compression format holds one stream, not files
		{"page.1.gz", gzBytes(t, "a man page"), nil, false},
		// a java resource adapter archive is a zip that shares rar's extension
		{"adapter.rar", zipBytes(t, sampleFiles), archives.Zip{}, false},
		// the name can be claimed by identification, so the probe alone must not admit prose
		{"app.jar", []byte("plain text, no central directory anywhere in it"), nil, false},
		{"bundle", []byte("plain text, no central directory anywhere in it"), nil, false},
		// content sniffing types this as a shell script; only its tail says zip
		{"app.jar", launcher, archives.Zip{}, false},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s/%d bytes", tt.name, len(tt.data)), func(t *testing.T) {
			got, err := identifyFormat(ctx, tt.name, bytes.NewReader(tt.data))
			if tt.unsupported {
				assert.ErrorIs(t, err, ErrUnsupportedFormat)
			} else {
				assert.NoError(t, err)
			}
			if tt.want == nil {
				assert.Nil(t, got)
				return
			}
			assert.IsType(t, tt.want, got)
		})
	}
}

func TestResolver_extract_storesEveryEntryInMemoryWhenUnbounded(t *testing.T) {
	for name, data := range map[string][]byte{
		"test.zip":    zipBytes(t, sampleFiles),
		"test.tar.gz": tarGzBytes(t, sampleFiles),
	} {
		t.Run(name, func(t *testing.T) {
			r, root := extractBytes(t, data, name, nil)
			assert.NoError(t, r.Truncated)
			assert.Zero(t, r.written)
			assert.Empty(t, filesIn(t, root))

			entries := readStore(t, r)
			assert.Equal(t, "content1", entries["file1.txt"].body)
			assert.Equal(t, "content2", entries["dir/file2.txt"].body)
		})
	}
}

func TestResolver_extract_diskLimitTruncatesAtTheEntryThatDoesNotFit(t *testing.T) {
	// each entry costs its index estimate plus its content on disk
	record := approxIndexBytes(tar.Header{Name: "file1.txt"})
	data := zipBytes(t, map[string]string{"file1.txt": "a", "file2.txt": "b", "file3.txt": "c"})

	r, _ := extractBytes(t, data, "test.zip", diskCharge(2*(record+1)+record))

	assert.Error(t, r.Truncated)
	assert.Equal(t, []string{"file1.txt", "file2.txt"}, storedNames(t, r), "the refused entry is not stored")
	entries := readStore(t, r)
	assert.Equal(t, "a", entries["file1.txt"].body)
	assert.Equal(t, "b", entries["file2.txt"].body)
}

func TestResolver_extract_diskLimitBitesMidEntry(t *testing.T) {
	// a tar is walked entry by entry, so the limit can bite part way through an entry
	data := tarGzBytes(t, map[string]string{
		"a/first.txt":  strings.Repeat("a", 40*1024),
		"b/second.txt": strings.Repeat("b", 40*1024),
	})
	const budget = 80 * 1024
	charge := diskCharge(budget)

	r, root := extractBytes(t, data, "test.tar.gz", charge)

	assert.Error(t, r.Truncated)
	assert.Equal(t, []string{"a", "a/first.txt", "b"}, storedNames(t, r), "the directory a refused entry implied stays")
	assert.Greater(t, r.written, int64(40*1024), "the first entry landed whole and the second part way")
	_, disk := charge.held()
	assert.LessOrEqual(t, disk, int64(budget))
	assert.Greater(t, disk, r.written, "the index estimate is charged to disk too")

	info, err := os.Stat(filepath.Join(root, spillFile(t, root)))
	require.NoError(t, err)
	assert.Equal(t, r.written, info.Size())
}

func TestResolver_extract_directoryOnlyArchivesAreBoundedByTheIndexEstimate(t *testing.T) {
	var entries []testEntry
	for i := range 50 {
		entries = append(entries, testEntry{name: fmt.Sprintf("d%04d/", i), dir: true})
	}
	room := approxIndexBytes(tar.Header{Name: "d0000"}) * 10

	for name, data := range map[string][]byte{
		"dirs.zip":    zipFromEntries(t, entries),
		"dirs.tar.gz": tarGzFromEntries(t, entries),
	} {
		t.Run(name, func(t *testing.T) {
			r, _ := extractBytes(t, data, name, diskCharge(room))
			assert.Error(t, r.Truncated)
			assert.Len(t, storedNames(t, r), 10)
		})
	}
}

func TestResolver_extract_entryNamesAreCleanedAndNothingIsWrittenUnderThem(t *testing.T) {
	entries := []testEntry{
		{name: "../../etc/passwd", body: "evil"},
		{name: "/etc/hosts", body: "pwned"},
		{name: "META-INF/", dir: true, mode: 0o555},
		{name: "META-INF/MANIFEST.MF", body: "Manifest-Version: 1.0"},
		{name: "passwd", link: "../../../../etc/passwd"},
		{name: "shadow", link: "/etc/shadow"},
		{name: "bin/link.txt", link: "../lib/real.txt"},
	}

	for name, data := range map[string][]byte{
		"evil.zip":    zipFromEntries(t, entries),
		"evil.tar.gz": tarGzFromEntries(t, entries),
	} {
		t.Run(name, func(t *testing.T) {
			r, root := extractBytes(t, data, name, nil)
			require.NoError(t, r.Truncated)

			assert.Equal(t, []string{"META-INF", "META-INF/MANIFEST.MF", "bin", "bin/link.txt", "etc", "etc/hosts", "etc/passwd", "passwd", "shadow"},
				storedNames(t, r))
			assert.Empty(t, filesIn(t, root), "entries live in the store, never under their own names")
			assert.NoFileExists(t, filepath.Join(t.TempDir(), "..", "etc", "passwd"))

			got := readStore(t, r)
			assert.Equal(t, "evil", got["etc/passwd"].body)
			assert.Equal(t, "pwned", got["etc/hosts"].body)
			assert.Equal(t, stereoscopeFile.TypeDirectory, got["META-INF"].kind)
			assert.Equal(t, fs.FileMode(0o555), got["META-INF"].mode.Perm())
			assert.Equal(t, "Manifest-Version: 1.0", got["META-INF/MANIFEST.MF"].body)

			// links are headers carrying their target verbatim; the index resolves them inside the archive
			for _, link := range []string{"passwd", "shadow", "bin/link.txt"} {
				assert.Equal(t, stereoscopeFile.TypeSymLink, got[link].kind)
				assert.Empty(t, got[link].body)
			}
			assert.Equal(t, "../../../../etc/passwd", got["passwd"].linkTarget)
			assert.Equal(t, "/etc/shadow", got["shadow"].linkTarget)
			assert.Equal(t, "../lib/real.txt", got["bin/link.txt"].linkTarget)
		})
	}
}

func TestResolver_extract_dataEdgeCases(t *testing.T) {
	t.Run("an empty archive is not an error", func(t *testing.T) {
		r, _ := extractBytes(t, zipBytes(t, map[string]string{}), "test.zip", nil)
		assert.Zero(t, r.entries)
		assert.NoError(t, r.Truncated)
	})

	t.Run("a zero-byte entry costs no disk", func(t *testing.T) {
		r, _ := extractBytes(t, zipBytes(t, map[string]string{"empty.txt": ""}), "test.zip", memCharge(0))
		assert.Equal(t, []string{"empty.txt"}, storedNames(t, r))
		assert.Zero(t, r.written)
		assert.Empty(t, readStore(t, r)["empty.txt"].body)
	})

	t.Run("unicode entry names survive", func(t *testing.T) {
		names := map[string]string{
			"café/naïve.txt": "accents",
			"日本語/ファイル.txt":   "japanese",
			"emoji-🎉.txt":    "emoji",
		}
		r, _ := extractBytes(t, zipBytes(t, names), "test.zip", nil)
		entries := readStore(t, r)
		for name, want := range names {
			assert.Equal(t, want, entries[name].body, name)
		}
	})

	t.Run("an entry name with too many path components is skipped and reported", func(t *testing.T) {
		atCap := strings.Repeat("a/", maxEntryNameDepth-1) + "f"
		data := zipBytes(t, map[string]string{
			atCap: "at the cap",
			strings.Repeat("b/", maxEntryNameDepth) + "f": "over the cap",
		})
		r, _ := extractBytes(t, data, "test.zip", nil)
		names := storedNames(t, r)
		assert.Contains(t, names, atCap)
		assert.Len(t, names, maxEntryNameDepth, "only the entry at the cap and its implied directories")
		assert.ErrorContains(t, r.Truncated, "path components")
	})

	t.Run("an entry whose chain is longer than a path is skipped and reported", func(t *testing.T) {
		// the chain is the archive's own path, the separator, then the name
		fits := strings.Repeat("a", MaxPathBytes-len("test-archive!/"))
		data := zipBytes(t, map[string]string{
			fits:       "at the cap",
			fits + "b": "over the cap",
		})
		r, _ := extractBytes(t, data, "test.zip", nil)
		assert.Equal(t, []string{fits}, storedNames(t, r))
		assert.ErrorContains(t, r.Truncated, "archive chain")
	})

	t.Run("an over-long entry name is skipped", func(t *testing.T) {
		data := zipBytes(t, map[string]string{
			strings.Repeat("a/", maxEntryNameBytes) + "f": "deep",
			"ok.txt": "fine",
		})
		r, _ := extractBytes(t, data, "test.zip", nil)
		assert.Equal(t, []string{"ok.txt"}, storedNames(t, r))
	})
}

func TestResolver_extract_unsafeEntryNamesAreRefusedAndReported(t *testing.T) {
	jar := string(zipBytes(t, map[string]string{"META-INF/MANIFEST.MF": "real"}))
	tests := []struct {
		name   string
		forged string
	}{
		{name: "archive path separator", forged: "a.jar!/META-INF/MANIFEST.MF"},
		{name: "line break", forged: "x\nlayerID: sha256:forged"},
		{name: "unicode line separator", forged: "x\u2028y"},
		{name: "C1 control", forged: "x\u0085y"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := zipBytes(t, map[string]string{"a.jar": jar, tt.forged: "forged"})
			r, _ := extractBytes(t, data, "outer.zip", nil)
			assert.Equal(t, []string{"a.jar"}, storedNames(t, r))
			require.Error(t, r.Truncated)
			assert.Contains(t, r.Truncated.Error(), fmt.Sprintf("%q", tt.forged))
		})
	}
}

func TestResolver_extract_excludedEntriesAreNeverStored(t *testing.T) {
	data := zipBytes(t, map[string]string{
		"keep.txt":          "kept",
		"vendor/lib.go":     "excluded by directory",
		"deep/down/pkg.rpm": "excluded by name",
	})
	limiter := NewLimiter(Limits{MaxMemoryBytes: 1 << 20, MaxDiskBytes: -1})
	r, _ := resolverIn(t, limiter.charge())
	content := bytes.NewReader(data)

	format, err := identifyFormat(context.Background(), "test.zip", content)
	require.NoError(t, err)
	err = r.extract(context.Background(), format, content,
		NewExclusions([]string{"**/vendor", "**/*.rpm"}))
	require.NoError(t, err)
	require.NoError(t, r.Truncated)

	assert.Equal(t, []string{"keep.txt"}, storedNames(t, r))
	mem, _ := limiter.InUse()
	assert.Equal(t, approxIndexBytes(tar.Header{Name: "keep.txt"})+4, mem, "an excluded entry costs nothing")
}

// a compressed tar reader decompresses a skipped entry to reach the next header, so skipping must still
// spend the budget or an excluded or oversized entry would decompress without bound
func TestResolver_extract_skippedCompressedTarBytesSpendTheBudget(t *testing.T) {
	big := strings.Repeat("\x00", 4<<20)
	tests := []struct {
		name       string
		exclusions []string
		entryCap   int64
	}{
		{name: "excluded entry", exclusions: []string{"**/*.bin"}, entryCap: maxEntryBytes},
		{name: "entry over the size cap", entryCap: 1 << 10},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func(prev int64) { maxEntryBytes = prev }(maxEntryBytes)
			maxEntryBytes = tt.entryCap

			data := tarGzFromEntries(t, []testEntry{{name: "bomb.bin", body: big}, {name: "after.txt", body: "after"}})
			r, _ := resolverIn(t, memCharge(1<<30))
			r.budget = NewBudget(1 << 20)
			content := bytes.NewReader(data)
			format, err := identifyFormat(context.Background(), "test.tar.gz", content)
			require.NoError(t, err)

			require.NoError(t, r.extract(context.Background(), format, content, NewExclusions(tt.exclusions)))
			require.Error(t, r.Truncated)
			assert.Empty(t, storedNames(t, r), "the walk stopped at the entry that spent the budget")
			assert.Zero(t, r.budget.remaining)
		})
	}
}

// a body behind a header that doesn't read as a regular file (here a socket per its mode bits) is never
// opened, but the tar reader still decompresses it to reach the next header
func TestResolver_extract_bodiesOfNonRegularTarEntriesSpendTheBudget(t *testing.T) {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	body := strings.Repeat("\x00", 4<<20)
	require.NoError(t, tw.WriteHeader(&tar.Header{Name: "sock", Typeflag: tar.TypeReg, Mode: 0o140644, Size: int64(len(body))}))
	_, err := tw.Write([]byte(body))
	require.NoError(t, err)
	require.NoError(t, tw.WriteHeader(&tar.Header{Name: "after.txt", Typeflag: tar.TypeReg, Mode: 0o644, Size: 5}))
	_, err = tw.Write([]byte("after"))
	require.NoError(t, err)
	require.NoError(t, tw.Close())
	require.NoError(t, gw.Close())

	r, _ := resolverIn(t, memCharge(1<<30))
	r.budget = NewBudget(1 << 20)
	content := bytes.NewReader(buf.Bytes())
	format, err := identifyFormat(context.Background(), "test.tar.gz", content)
	require.NoError(t, err)

	require.NoError(t, r.extract(context.Background(), format, content, nil))
	assert.ErrorIs(t, r.Truncated, errBudgetSpent)
	assert.Empty(t, storedNames(t, r))
	assert.Zero(t, r.budget.remaining)
}

// a zip or a plain tar seeks past what it skips, so an excluded entry there costs nothing
func TestResolver_extract_skippedSeekableBytesAreFree(t *testing.T) {
	entries := []testEntry{{name: "bomb.bin", body: strings.Repeat("\x00", 4<<20)}, {name: "after.txt", body: "after"}}
	var plainTar bytes.Buffer
	tw := tar.NewWriter(&plainTar)
	for _, e := range entries {
		hdr := e.header()
		require.NoError(t, tw.WriteHeader(&hdr))
		_, err := tw.Write([]byte(e.body))
		require.NoError(t, err)
	}
	require.NoError(t, tw.Close())

	for name, data := range map[string][]byte{"test.zip": zipFromEntries(t, entries), "test.tar": plainTar.Bytes()} {
		t.Run(name, func(t *testing.T) {
			r, _ := resolverIn(t, memCharge(1<<30))
			r.budget = NewBudget(1 << 20)
			content := bytes.NewReader(data)
			format, err := identifyFormat(context.Background(), name, content)
			require.NoError(t, err)

			require.NoError(t, r.extract(context.Background(), format, content, NewExclusions([]string{"**/*.bin"})))
			require.NoError(t, r.Truncated)
			assert.Equal(t, []string{"after.txt"}, storedNames(t, r))
		})
	}
}

func TestExtract_readsEntriesAndDigestsTheArchive(t *testing.T) {
	data := zipBytes(t, map[string]string{"dir/hello.txt": "hello world"})

	extracted, err := Extract(context.Background(), bytes.NewReader(data), file.Coordinates{RealPath: "app.war", FileSystemID: "parentFS", FullPath: "app.war!/some/path/app.zip"}, nil, nil)
	require.NoError(t, err)
	require.NotNil(t, extracted)
	t.Cleanup(extracted.Cleanup)

	assert.NoError(t, extracted.Truncated)
	require.Len(t, extracted.Digests, 1)
	assert.Equal(t, "sha1", extracted.Digests[0].Algorithm)

	locations, err := extracted.FilesByGlob("**/*.txt")
	require.NoError(t, err)
	require.Len(t, locations, 1)
	assert.Equal(t, file.Coordinates{RealPath: "app.war", FileSystemID: "parentFS", FullPath: "app.war!/some/path/app.zip!/dir/hello.txt"},
		locations[0].Coordinates)

	reader, err := extracted.FileContentsByLocation(locations[0])
	require.NoError(t, err)
	body, err := io.ReadAll(reader)
	require.NoError(t, err)
	assert.Equal(t, "hello world", string(body))
}

func TestExtract_heldContentIsReleasedOnceExtracted(t *testing.T) {
	// the archive's own bytes are only needed to extract and digest it; afterwards the limiter holds
	// the entries and the index estimate alone
	data := zipBytes(t, map[string]string{"hello.txt": "hi"})
	limiter := NewLimiter(Limits{MaxMemoryBytes: -1, MaxDiskBytes: -1})

	extracted, err := Extract(context.Background(), unseekable{bytes.NewReader(data)}, file.NewCoordinates("app.zip", ""), limiter, nil)
	require.NoError(t, err)
	t.Cleanup(extracted.Cleanup)

	mem, disk := limiter.InUse()
	assert.Equal(t, approxIndexBytes(tar.Header{Name: "hello.txt"})+2, mem)
	assert.Zero(t, disk)
}

func TestExtract_heldContentWrittenToDiskStaysUntilCleanup(t *testing.T) {
	// only a top-level stream is ever held; a nested archive is read out of its parent, which is held
	// for the whole descent anyway, so spilled bytes wait for Cleanup with the entries
	ctx, root := scanContext(t)
	data := zipBytes(t, map[string]string{"hello.txt": "hi"})
	limiter := NewLimiter(Limits{MaxMemoryBytes: 0, MaxDiskBytes: -1})

	extracted, err := Extract(ctx, unseekable{bytes.NewReader(data)}, file.NewCoordinates("app.zip", ""), limiter, nil)
	require.NoError(t, err)
	t.Cleanup(extracted.Cleanup)

	require.Len(t, filesIn(t, root), 1, "the archive's bytes and its entries share one file")
	_, disk := limiter.InUse()
	assert.Equal(t, approxIndexBytes(tar.Header{Name: "hello.txt"})+2+int64(len(data)), disk)

	extracted.Cleanup()
	assert.Empty(t, filesIn(t, root))
	_, disk = limiter.InUse()
	assert.Zero(t, disk)
}

func TestExtract_aTruncatedStreamKeepsWhatWasRead(t *testing.T) {
	// a .tar.gz cut off partway breaks the stream for every entry after the cut; the ones before it are
	// still good and must not be thrown away
	noise := make([]byte, 64*1024)
	rand.New(rand.NewSource(1)).Read(noise)
	data := tarGzBytes(t, map[string]string{"a.txt": "first", "b.bin": string(noise)})
	cut := data[:len(data)/2]

	extracted, err := Extract(context.Background(), bytes.NewReader(cut), file.NewCoordinates("app.tar.gz", ""), NewLimiter(unboundedLimits), nil)
	require.NoError(t, err)
	require.NotNil(t, extracted)
	t.Cleanup(extracted.Cleanup)

	assert.Error(t, extracted.Truncated)
	locations, err := extracted.FilesByGlob("**")
	require.NoError(t, err)
	assert.Equal(t, []string{"/a.txt"}, localPaths(locations))
}

func TestExtract_aPanicStillReleasesEverything(t *testing.T) {
	// a decoder panicking on hostile bytes must not leak the charge or the spill file
	ctx, root := scanContext(t)
	limiter := NewLimiter(Limits{MaxMemoryBytes: 0, MaxDiskBytes: -1})

	require.Panics(t, func() {
		_, _ = Extract(ctx, &panicsAfter{n: 4096}, file.NewCoordinates("app.zip", ""), limiter, nil)
	})

	mem, disk := limiter.InUse()
	assert.Zero(t, mem)
	assert.Zero(t, disk)
	assert.Empty(t, filesIn(t, root))
}

// panicsAfter hands out n zero bytes, then panics.
type panicsAfter struct{ n int }

func (p *panicsAfter) Read(b []byte) (int, error) {
	if p.n <= 0 {
		panic("decoder blew up")
	}
	n := min(len(b), p.n)
	clear(b[:n])
	p.n -= n
	return n, nil
}

func TestExtract_archiveBytesThatCannotBePlacedAreSkipped(t *testing.T) {
	data := zipBytes(t, sampleFiles)
	limiter := NewLimiter(Limits{MaxMemoryBytes: 0, MaxDiskBytes: 0})

	_, err := Extract(context.Background(), unseekable{bytes.NewReader(data)}, file.NewCoordinates("app.zip", ""), limiter, nil)
	assert.ErrorIs(t, err, ErrDiskLimitReached)

	// read in place, the same bytes cost nothing; only the entries are refused
	extracted, err := Extract(context.Background(), bytes.NewReader(data), file.NewCoordinates("app.zip", ""), limiter, nil)
	require.NoError(t, err)
	require.NotNil(t, extracted)
	t.Cleanup(extracted.Cleanup)
	assert.Error(t, extracted.Truncated)
	locations, err := extracted.FilesByGlob("**/*")
	require.NoError(t, err)
	assert.Empty(t, locations)
}

func Test_HasZipEndOfCentralDirectory(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{"a plain zip", zipBytes(t, sampleFiles), true},
		{"a zip behind a launcher script", append([]byte("#!/bin/bash\nexit 0\n"), zipBytes(t, sampleFiles)...), true},
		{"prose", []byte("this is not an archive, it is a sentence"), false},
		{"a tar.gz", tarGzBytes(t, sampleFiles), false},
		{"empty", nil, false},
		{"shorter than the signature", []byte("PK"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, HasZipEndOfCentralDirectory(bytes.NewReader(tt.data)))
		})
	}
}

func Test_MayHideAnAppendedArchive(t *testing.T) {
	launcher := append([]byte("#!/bin/bash\nexit 0\n"), zipBytes(t, sampleFiles)...)
	prose := []byte("plain text, whatever the extension claims")

	t.Run("a seekable reader is rewound and returned as is", func(t *testing.T) {
		reader := bytes.NewReader(launcher)
		got, found := MayHideAnAppendedArchive(reader)
		assert.True(t, found)
		assert.Same(t, reader, got)
		rest, err := io.ReadAll(got)
		require.NoError(t, err)
		assert.Equal(t, launcher, rest)
	})

	t.Run("an unseekable reader replays what was consumed", func(t *testing.T) {
		got, found := MayHideAnAppendedArchive(unseekable{bytes.NewReader(launcher)})
		assert.True(t, found)
		rest, err := io.ReadAll(got)
		require.NoError(t, err)
		assert.Equal(t, launcher, rest)
	})

	t.Run("prose hides nothing", func(t *testing.T) {
		got, found := MayHideAnAppendedArchive(unseekable{bytes.NewReader(prose)})
		assert.False(t, found)
		rest, err := io.ReadAll(got)
		require.NoError(t, err)
		assert.Equal(t, prose, rest)
	})
}

// zeros is a reader of n zero bytes: the most compressible content there is.
func zeros(n int64) io.Reader {
	return io.LimitReader(zeroSource{}, n)
}

type zeroSource struct{}

func (zeroSource) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

func TestExtract_decompressionBombIsBoundedByTheLimits(t *testing.T) {
	// 64 MiB of zeros compresses to a few hundred KiB. The declared size is never trusted: bytes are
	// charged as they land, so the limits hold whatever the archive claims
	const inflated = 64 << 20
	limits := Limits{MaxMemoryBytes: 1 << 20, MaxDiskBytes: 4 << 20}

	var zipBomb bytes.Buffer
	zw := zip.NewWriter(&zipBomb)
	w, err := zw.Create("bomb.bin")
	require.NoError(t, err)
	_, err = io.Copy(w, zeros(inflated))
	require.NoError(t, err)
	require.NoError(t, zw.Close())

	var tarBomb bytes.Buffer
	gw := gzip.NewWriter(&tarBomb)
	tw := tar.NewWriter(gw)
	require.NoError(t, tw.WriteHeader(&tar.Header{Name: "bomb.bin", Mode: 0o644, Size: inflated, Typeflag: tar.TypeReg}))
	_, err = io.Copy(tw, zeros(inflated))
	require.NoError(t, err)
	require.NoError(t, tw.Close())
	require.NoError(t, gw.Close())

	for name, data := range map[string][]byte{"bomb.zip": zipBomb.Bytes(), "bomb.tar.gz": tarBomb.Bytes()} {
		t.Run(name, func(t *testing.T) {
			require.Less(t, len(data), 1<<20, "the fixture must be a bomb: small on disk, huge inflated")
			ctx, root := scanContext(t)
			limiter := NewLimiter(limits)

			r, err := Extract(ctx, bytes.NewReader(data), file.NewCoordinates(name, ""), limiter, nil)
			require.NoError(t, err)
			require.NotNil(t, r)
			t.Cleanup(r.Cleanup)

			assert.Error(t, r.Truncated)
			locations, err := r.FilesByGlob("**/*")
			require.NoError(t, err)
			assert.Empty(t, locations, "the entry that did not fit is not cataloged in part")

			peakMemory, peakDisk := limiter.Peak()
			assert.LessOrEqual(t, peakMemory, limits.MaxMemoryBytes)
			assert.LessOrEqual(t, peakDisk, limits.MaxDiskBytes)

			r.Cleanup()
			assert.Empty(t, filesIn(t, root))
		})
	}
}

func TestExtract_entryCountBombIsBoundedByTheMemoryLimit(t *testing.T) {
	// every entry is a node in memory whatever the disk limit says, so a tiny archive of many entries
	// is bounded by the memory limit alone
	limits := Limits{MaxMemoryBytes: 1 << 20, MaxDiskBytes: -1}
	limiter := NewLimiter(limits)

	r, err := Extract(context.Background(), bytes.NewReader(manyEntryZip(t, 20_000)), file.NewCoordinates("many.zip", ""), limiter, nil)
	require.NoError(t, err)
	t.Cleanup(r.Cleanup)

	assert.Error(t, r.Truncated)
	assert.Less(t, r.entries, 20_000)
	assert.LessOrEqual(t, int64(nodeCount(r))*approxIndexBytesPerEntry, limits.MaxMemoryBytes+approxIndexBytesPerEntry,
		"nodes held must not exceed what the memory limit paid for")
	peakMemory, _ := limiter.Peak()
	assert.LessOrEqual(t, peakMemory, limits.MaxMemoryBytes)
}

func TestExtract_deepPathBombIsBoundedByTheMemoryLimit(t *testing.T) {
	// 100 entries whose names each imply 250 distinct directories would be 25,000 nodes; the implied
	// directories are charged as nodes, so the memory limit bounds them too
	files := map[string]string{}
	for i := range 100 {
		var b strings.Builder
		for j := range maxEntryNameDepth - 6 {
			fmt.Fprintf(&b, "%03d-%03d/", i, j)
		}
		b.WriteString("f")
		require.LessOrEqual(t, b.Len(), maxEntryNameBytes)
		files[b.String()] = "x"
	}
	limits := Limits{MaxMemoryBytes: 8 << 20, MaxDiskBytes: -1}
	limiter := NewLimiter(limits)

	r, err := Extract(context.Background(), bytes.NewReader(zipBytes(t, files)), file.NewCoordinates("deep.zip", ""), limiter, nil)
	require.NoError(t, err)
	t.Cleanup(r.Cleanup)

	assert.Error(t, r.Truncated)
	assert.LessOrEqual(t, int64(nodeCount(r))*approxIndexBytesPerEntry, limits.MaxMemoryBytes+approxIndexBytesPerEntry)
	peakMemory, _ := limiter.Peak()
	assert.LessOrEqual(t, peakMemory, limits.MaxMemoryBytes)
}

func TestExtract_locationsKeepTheTopLevelRealPath(t *testing.T) {
	data := zipBytes(t, map[string]string{"dir/hello.txt": "hello world"})

	// a top-level archive's coordinates, with FullPath unset or set to RealPath, name entries alike
	for _, archive := range []file.Coordinates{
		{RealPath: "/app.zip"},
		{RealPath: "/app.zip", FullPath: "/app.zip"},
	} {
		extracted, err := Extract(context.Background(), bytes.NewReader(data), archive, nil, nil)
		require.NoError(t, err)
		require.NotNil(t, extracted)
		t.Cleanup(extracted.Cleanup)

		locations, err := extracted.FilesByPath("dir/hello.txt")
		require.NoError(t, err)
		require.Len(t, locations, 1)
		assert.Equal(t, file.Coordinates{RealPath: "/app.zip", FullPath: "/app.zip!/dir/hello.txt"}, locations[0].Coordinates)
		assert.Equal(t, "/dir/hello.txt", locations[0].LocalPath())

		for _, loc := range []file.Location{
			locations[0],
			file.NewLocation("dir/hello.txt"),
			file.NewLocation("/dir/hello.txt"),
			file.NewLocationFromCoordinates(file.Coordinates{RealPath: "/app.zip", FullPath: "/app.zip!/dir/hello.txt"}),
		} {
			reader, err := extracted.FileContentsByLocation(loc)
			require.NoError(t, err, "location %s", loc)
			body, err := io.ReadAll(reader)
			require.NoError(t, err)
			assert.Equal(t, "hello world", string(body))

			metadata, err := extracted.FileMetadataByLocation(loc)
			require.NoError(t, err, "location %s", loc)
			assert.Equal(t, "/app.zip!/dir/hello.txt", metadata.Path)
		}

		_, err = extracted.FileContentsByLocation(file.NewLocationFromCoordinates(file.Coordinates{RealPath: "/other.zip", FullPath: "/other.zip!/dir/hello.txt"}))
		assert.Error(t, err, "an entry of another archive is not read from this one")
	}
}
