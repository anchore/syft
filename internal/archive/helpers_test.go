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
	"os"
	"path"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/internal/tmpdir"
	"github.com/anchore/syft/syft/file"
)

// held reports what this charge is currently holding, in memory and on disk.
func (c *charge) held() (memory, disk int64) {
	if c == nil {
		return 0, 0
	}
	c.limiter.mu.Lock()
	defer c.limiter.mu.Unlock()
	return c.inMemory, c.onDisk
}

// heldInMemory reports the content the resolver is still holding in memory.
func (r *Resolver) heldInMemory() int64 {
	var total int64
	for _, b := range r.held {
		total += int64(len(b.mem))
	}
	return total
}

// unseekable hides a reader's Seek and ReadAt, forcing content through the held path.
type unseekable struct{ io.Reader }

// testEntry is one entry of a fixture archive: a directory when dir is set, a link when link is set
// (hard when hard is set, otherwise symbolic), otherwise a regular file.
type testEntry struct {
	name string
	body string
	link string
	hard bool
	dir  bool
	mode fs.FileMode
}

// header is the tar header this entry would carry.
func (e testEntry) header() tar.Header {
	switch {
	case e.dir:
		return tar.Header{Name: e.name, Mode: int64(e.modeOr(0o755)), Typeflag: tar.TypeDir}
	case e.link != "" && e.hard:
		return tar.Header{Name: e.name, Mode: 0o644, Typeflag: tar.TypeLink, Linkname: e.link}
	case e.link != "":
		return tar.Header{Name: e.name, Mode: 0o777, Typeflag: tar.TypeSymlink, Linkname: e.link}
	}
	return tar.Header{Name: e.name, Mode: int64(e.modeOr(0o644)), Size: int64(len(e.body)), Typeflag: tar.TypeReg}
}

func fileEntries(files map[string]string) []testEntry {
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	// limits bite as the walk proceeds, so entry order decides what lands before a truncation
	sort.Strings(names)
	entries := make([]testEntry, 0, len(names))
	for _, name := range names {
		entries = append(entries, testEntry{name: name, body: files[name]})
	}
	return entries
}

func zipBytes(t testing.TB, files map[string]string) []byte {
	return zipFromEntries(t, fileEntries(files))
}

func zipFromEntries(t testing.TB, entries []testEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for _, e := range entries {
		hdr := &zip.FileHeader{Name: e.name}
		body := e.body
		switch {
		case e.dir:
			hdr.SetMode(fs.ModeDir | e.modeOr(0o755))
		case e.link != "":
			hdr.SetMode(fs.ModeSymlink | 0o777)
			body = e.link
		default:
			hdr.SetMode(e.modeOr(0o644))
		}
		fw, err := w.CreateHeader(hdr)
		require.NoError(t, err)
		_, err = fw.Write([]byte(body))
		require.NoError(t, err)
	}
	require.NoError(t, w.Close())
	return buf.Bytes()
}

func tarGzBytes(t testing.TB, files map[string]string) []byte {
	return tarGzFromEntries(t, fileEntries(files))
}

func tarGzFromEntries(t testing.TB, entries []testEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	for _, e := range entries {
		hdr := e.header()
		require.NoError(t, tw.WriteHeader(&hdr))
		_, err := tw.Write([]byte(e.body))
		require.NoError(t, err)
	}
	require.NoError(t, tw.Close())
	require.NoError(t, gw.Close())
	return buf.Bytes()
}

func (e testEntry) modeOr(fallback fs.FileMode) fs.FileMode {
	if e.mode != 0 {
		return e.mode
	}
	return fallback
}

func regularHeader(name string, size int64) tar.Header {
	return tar.Header{Name: name, Size: size, Mode: 0o600, Typeflag: tar.TypeReg}
}

// scanContext returns a context whose temp root is a fresh directory, and that directory.
func scanContext(t testing.TB) (context.Context, string) {
	t.Helper()
	root := t.TempDir()
	return tmpdir.WithValue(context.Background(), tmpdir.FromPath(root)), root
}

// filesIn lists the regular files directly in dir.
func filesIn(t testing.TB, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	var names []string
	for _, e := range entries {
		if !e.IsDir() {
			names = append(names, e.Name())
		}
	}
	return names
}

// spillFile is the one file a resolver has written, or "" when it has not.
func spillFile(t testing.TB, dir string) string {
	t.Helper()
	files := filesIn(t, dir)
	require.LessOrEqual(t, len(files), 1)
	if len(files) == 0 {
		return ""
	}
	return files[0]
}

// resolverIn makes an empty resolver over the given charge that spills into dir, along with that
// directory. Its entries are added by the test.
func resolverIn(t testing.TB, charge *charge) (*Resolver, string) {
	t.Helper()
	root := t.TempDir()
	ctx := tmpdir.WithValue(context.Background(), tmpdir.FromPath(root))
	r := newResolver(ctx, "", "test-archive", charge)
	t.Cleanup(r.Cleanup)
	return r, root
}

// addAll adds entries in the order given and finishes the resolver.
func addAll(t testing.TB, r *Resolver, entries []testEntry) {
	t.Helper()
	for _, e := range entries {
		require.NoError(t, r.add(e.header(), bytes.NewReader([]byte(e.body))))
	}
	r.finish()
}

// resolverOver builds a resolver holding the given files within a memory bound.
func resolverOver(t testing.TB, maxInMemory int64, files map[string]string) *Resolver {
	t.Helper()
	r, _ := resolverIn(t, memCharge(maxInMemory))
	r.archivePath = "outer.jar"
	addAll(t, r, fileEntries(files))
	return r
}

// resolverFrom builds a resolver holding the given entries, links and directories included, with
// ample memory.
func resolverFrom(t testing.TB, entries ...testEntry) *Resolver {
	t.Helper()
	r, _ := resolverIn(t, memCharge(1<<20))
	r.archivePath = "outer.jar"
	addAll(t, r, entries)
	return r
}

// indexCostOf is what add charges for the given entries in name order: every listed node and every
// directory their paths imply.
func indexCostOf(entries map[string]string) int64 {
	names := make([]string, 0, len(entries))
	for name := range entries {
		names = append(names, name)
	}
	sort.Strings(names)
	seen := map[string]bool{}
	var total int64
	for _, name := range names {
		p := path.Clean("/" + name)
		for i := 1; i < len(p); i++ {
			if p[i] == '/' && !seen[p[:i]] {
				seen[p[:i]] = true
				total += approxIndexBytesPerEntry
			}
		}
		seen[p] = true
		total += approxIndexBytes(tar.Header{Name: name})
	}
	return total
}

// extractBytes extracts an archive into a resolver built over the given charge.
func extractBytes(t testing.TB, data []byte, name string, charge *charge) (*Resolver, string) {
	t.Helper()
	r, root := resolverIn(t, charge)
	content := bytes.NewReader(data)
	format := identifyFormat(context.Background(), name, content)
	require.NotNil(t, format, "fixture must identify as an archive")
	require.NoError(t, r.extract(context.Background(), format, content, nil))
	return r, root
}

func readEntry(t testing.TB, r ReaderAtSeeker) string {
	t.Helper()
	_, err := r.Seek(0, io.SeekStart)
	require.NoError(t, err)
	b, err := io.ReadAll(r)
	require.NoError(t, err)
	return string(b)
}

// storedEntry is one entry read back out of a resolver.
type storedEntry struct {
	body       string
	linkTarget string
	mode       fs.FileMode
	typeflag   byte
}

// readStore reads every listed entry, files and directories alike, by name.
func readStore(t testing.TB, r *Resolver) map[string]storedEntry {
	t.Helper()
	out := map[string]storedEntry{}
	for _, n := range r.byPath {
		if n.header == nil {
			continue
		}
		out[n.header.Name] = storedEntry{
			body:       readEntry(t, r.open(&n.content)),
			linkTarget: n.header.Linkname,
			mode:       n.header.FileInfo().Mode(),
			typeflag:   n.header.Typeflag,
		}
	}
	return out
}

// storedNames lists every listed entry's name, files and directories alike.
func storedNames(t testing.TB, r *Resolver) []string {
	t.Helper()
	var names []string
	for _, n := range r.byPath {
		if n.header != nil {
			names = append(names, n.header.Name)
		}
	}
	sort.Strings(names)
	return names
}

// memCharge is a charge against a memory bound with disk unbounded.
func memCharge(maxMemory int64) *charge {
	return NewLimiter(Limits{MaxMemoryBytes: maxMemory, MaxDiskBytes: -1}).charge()
}

// diskCharge is a charge against a disk bound with memory refusing everything.
func diskCharge(maxDisk int64) *charge {
	return NewLimiter(Limits{MaxDiskBytes: maxDisk}).charge()
}

// realPaths lists the real path of every location, sorted.
func realPaths(locations []file.Location) []string {
	var out []string
	for _, loc := range locations {
		out = append(out, loc.RealPath)
	}
	sort.Strings(out)
	return out
}

// manyEntryZip is a zip of count one-byte files.
func manyEntryZip(t testing.TB, count int) []byte {
	t.Helper()
	files := make(map[string]string, count)
	for i := range count {
		files[fmt.Sprintf("e%06d.txt", i)] = "x"
	}
	return zipBytes(t, files)
}

// extractedResolver extracts one archive through Extract and returns the resolver, along with the scan
// temp root its spill file would appear under.
func extractedResolver(t testing.TB, data []byte, limits Limits) (*Resolver, string) {
	t.Helper()
	ctx, root := scanContext(t)

	r, err := Extract(ctx, bytes.NewReader(data), "", "app.zip", NewLimiter(limits), nil)
	require.NoError(t, err)
	require.NotNil(t, r)
	t.Cleanup(r.Cleanup)

	return r, root
}

var (
	unboundedLimits = Limits{MaxMemoryBytes: -1, MaxDiskBytes: -1}

	// spillingLimits hold nothing in memory, so every entry lands in the spill file
	spillingLimits = Limits{MaxMemoryBytes: 0, MaxDiskBytes: -1}
)
