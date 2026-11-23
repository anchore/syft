package testutils

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"
)

// Zip builds a zip of the entries in sorted name order: archive limits bite as entries are read, so
// order decides which land before a truncation.
func Zip[T ~string | ~[]byte](t testing.TB, entries map[string]T) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, name := range sortedNames(entries) {
		w, err := zw.Create(name)
		require.NoError(t, err)
		_, err = w.Write([]byte(entries[name]))
		require.NoError(t, err)
	}
	require.NoError(t, zw.Close())
	return buf.Bytes()
}

// Tar builds a tar of the entries in sorted name order.
func Tar[T ~string | ~[]byte](t testing.TB, entries map[string]T) []byte {
	t.Helper()
	var buf bytes.Buffer
	writeTar(t, &buf, entries)
	return buf.Bytes()
}

// TarGz builds a gzipped tar of the entries in sorted name order.
func TarGz[T ~string | ~[]byte](t testing.TB, entries map[string]T) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	writeTar(t, gw, entries)
	require.NoError(t, gw.Close())
	return buf.Bytes()
}

// Jar is the smallest jar the java cataloger identifies, a manifest naming the artifact, plus extra.
func Jar(t testing.TB, title, version string, extra map[string][]byte) []byte {
	t.Helper()
	entries := map[string][]byte{"META-INF/MANIFEST.MF": Manifest(title, version)}
	for name, body := range extra {
		entries[name] = body
	}
	return Zip(t, entries)
}

// Manifest is a jar manifest naming the artifact.
func Manifest(title, version string) []byte {
	return fmt.Appendf(nil, "Manifest-Version: 1.0\nImplementation-Title: %s\nImplementation-Version: %s\n", title, version)
}

func writeTar[T ~string | ~[]byte](t testing.TB, w io.Writer, entries map[string]T) {
	t.Helper()
	tw := tar.NewWriter(w)
	for _, name := range sortedNames(entries) {
		body := []byte(entries[name])
		require.NoError(t, tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}))
		_, err := tw.Write(body)
		require.NoError(t, err)
	}
	require.NoError(t, tw.Close())
}

func sortedNames[T any](entries map[string]T) []string {
	names := make([]string, 0, len(entries))
	for name := range entries {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
