package archive

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/internal/tmpdir"
)

// WorkDirAt returns a WorkDir over a directory that already exists, so a test can inspect it
// afterwards; Remove leaves it alone.
func WorkDirAt(dir string) *WorkDir {
	return &WorkDir{created: true, path: dir}
}

func (w *WorkDir) wasCreated() bool {
	return w != nil && w.remove != nil
}

// heldInMemory reports the entry content the store is still holding in memory.
func (s *EntryStore) heldInMemory() int64 {
	var total int64
	for _, entry := range s.entries {
		total += int64(len(entry.mem))
	}
	return total
}

// held reports what this charge is currently holding, in memory and on disk.
func (c *Charge) held() (memory, disk int64) {
	if c == nil {
		return 0, 0
	}
	c.limiter.mu.Lock()
	defer c.limiter.mu.Unlock()
	return c.memory, c.disk
}

// unseekable hides a reader's Seek and ReadAt, forcing content through the held path.
type unseekable struct{ io.Reader }

// testEntry is one entry of a fixture archive: a directory when dir is set, a symlink when link is
// set, otherwise a regular file.
type testEntry struct {
	name string
	body string
	link string
	dir  bool
	mode fs.FileMode
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
		hdr := &tar.Header{Name: e.name, Mode: int64(e.modeOr(0o644)), Size: int64(len(e.body))}
		switch {
		case e.dir:
			hdr.Typeflag, hdr.Mode, hdr.Size = tar.TypeDir, int64(e.modeOr(0o755)), 0
		case e.link != "":
			hdr.Typeflag, hdr.Linkname, hdr.Mode, hdr.Size = tar.TypeSymlink, e.link, 0o777, 0
		}
		require.NoError(t, tw.WriteHeader(hdr))
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

// storeFor makes a store in the test's own temp space with the given charge.
func storeFor(t testing.TB, charge *Charge) *EntryStore {
	t.Helper()
	s := NewEntryStore("test-archive", WorkDirAt(t.TempDir()), charge)
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// storeDir is the directory a store spills into.
func storeDir(t testing.TB, s *EntryStore) string {
	t.Helper()
	dir, err := s.workDir.Path()
	require.NoError(t, err)
	return dir
}

func readEntry(t testing.TB, r ReaderAtSeeker) string {
	t.Helper()
	_, err := r.Seek(0, io.SeekStart)
	require.NoError(t, err)
	b, err := io.ReadAll(r)
	require.NoError(t, err)
	return string(b)
}

// storedEntry is one entry read back out of a store.
type storedEntry struct {
	body       string
	linkTarget string
	mode       fs.FileMode
	typeflag   byte
}

func readStore(t testing.TB, s *EntryStore) map[string]storedEntry {
	t.Helper()
	out := map[string]storedEntry{}
	for _, entry := range s.Entries() {
		out[entry.Header.Name] = storedEntry{
			body:       readEntry(t, s.Open(entry)),
			linkTarget: entry.Header.Linkname,
			mode:       entry.Header.FileInfo().Mode(),
			typeflag:   entry.Header.Typeflag,
		}
	}
	return out
}

func storedNames(t testing.TB, s *EntryStore) []string {
	t.Helper()
	var names []string
	for _, entry := range s.Entries() {
		names = append(names, entry.Header.Name)
	}
	sort.Strings(names)
	return names
}

// memCharge is a charge against a memory bound with disk unbounded.
func memCharge(maxMemory int64) *Charge {
	return NewLimiter(Limits{MaxMemoryBytes: maxMemory, MaxDiskBytes: -1}).Charge()
}

// diskCharge is a charge against a disk bound with memory refusing everything.
func diskCharge(maxDisk int64) *Charge {
	return NewLimiter(Limits{MaxDiskBytes: maxDisk}).Charge()
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

// scanContext returns a context whose temp root is a fresh directory, and that directory.
func scanContext(t testing.TB) (context.Context, string) {
	t.Helper()
	root := t.TempDir()
	return tmpdir.WithValue(context.Background(), tmpdir.FromPath(root)), root
}

// workDirsUnder returns the archive work directories directly under a scan temp root.
func workDirsUnder(t testing.TB, root string) []string {
	t.Helper()
	children, err := os.ReadDir(root)
	require.NoError(t, err)
	var out []string
	for _, child := range children {
		if child.IsDir() && strings.HasPrefix(child.Name(), workDirName) {
			out = append(out, filepath.Join(root, child.Name()))
		}
	}
	return out
}

// extractBytes extracts an archive into a store built over the given charge.
func extractBytes(t testing.TB, data []byte, name string, charge *Charge) (*EntryStore, bool) {
	t.Helper()
	store := storeFor(t, charge)
	content := bytes.NewReader(data)
	format := identifyFormat(context.Background(), name, content)
	require.NotNil(t, format, "fixture must identify as an archive")
	truncated, err := extractInto(context.Background(), format, content, store, nil)
	require.NoError(t, err)
	return store, truncated
}
