package debian

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/blakesmith/ar"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/internal/unknown"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

func TestProcessControlTar(t *testing.T) {
	tarBytes := createTestTarWithControlFiles(t)

	metadata, err := processControlTar(io.NopCloser(bytes.NewReader(tarBytes)))

	require.NoError(t, err)
	require.NotNil(t, metadata)

	assert.Equal(t, "test-package", metadata.Package)
	assert.Equal(t, "1.0.0", metadata.Version)

	// md5sums should have been parsed into file records
	require.Len(t, metadata.Files, 1)
	assert.Equal(t, "/usr/bin/test-command", metadata.Files[0].Path)
	assert.Equal(t, "d41d8cd98f00b204e9800998ecf8427e", metadata.Files[0].Digest.Value)

	// conffiles should have marked config files
	assert.True(t, metadata.Files[0].IsConfigFile, "file listed in conffiles should be marked as config")
}

func TestProcessControlTar_ConfigFileMarking(t *testing.T) {
	// Create a tar where conffiles lists paths that overlap with md5sums entries
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	controlContent := "Package: test-package\nVersion: 1.0.0\nArchitecture: all\n"
	writeTarEntry(t, tw, "control", controlContent)

	md5Content := "d41d8cd98f00b204e9800998ecf8427e  usr/bin/test-command\n" +
		"d41d8cd98f00b204e9800998ecf8427e  etc/test/config.conf\n" +
		"d41d8cd98f00b204e9800998ecf8427e  usr/bin/other-command\n"
	writeTarEntry(t, tw, "md5sums", md5Content)

	conffilesContent := "/usr/bin/test-command\n/etc/test/config.conf\n"
	writeTarEntry(t, tw, "conffiles", conffilesContent)

	require.NoError(t, tw.Close())

	metadata, err := processControlTar(io.NopCloser(bytes.NewReader(buf.Bytes())))
	require.NoError(t, err)
	require.Len(t, metadata.Files, 3)

	assert.True(t, metadata.Files[0].IsConfigFile, "first file should be marked as config file")
	assert.True(t, metadata.Files[1].IsConfigFile, "second file should be marked as config file")
	assert.False(t, metadata.Files[2].IsConfigFile, "third file should not be marked as config file")
}

// createTestTarWithControlFiles creates a simple in-memory tar file with test control files
func createTestTarWithControlFiles(t *testing.T) []byte {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	controlContent := "Package: test-package\nVersion: 1.0.0\nArchitecture: all\nMaintainer: Test <test@example.com>\nDescription: Test package\n"
	writeTarEntry(t, tw, "control", controlContent)

	md5Content := "d41d8cd98f00b204e9800998ecf8427e  usr/bin/test-command\n"
	writeTarEntry(t, tw, "md5sums", md5Content)

	conffilesContent := "/usr/bin/test-command\n"
	writeTarEntry(t, tw, "conffiles", conffilesContent)

	require.NoError(t, tw.Close())
	return buf.Bytes()
}

func writeTarEntry(t *testing.T, tw *tar.Writer, name, content string) {
	t.Helper()
	require.NoError(t, tw.WriteHeader(&tar.Header{
		Name: name,
		Mode: 0644,
		Size: int64(len(content)),
	}))
	_, err := tw.Write([]byte(content))
	require.NoError(t, err)
}

func Test_boundedReadCloser(t *testing.T) {
	payload := []byte("0123456789")

	t.Run("a stream at exactly the cap reads through whole", func(t *testing.T) {
		// the positive assertion is the point: it proves the one-byte-past budget does not truncate
		// at-cap content, which a bare "did not error" check would not catch
		r := newBoundedReadCloser(io.NopCloser(bytes.NewReader(payload)), int64(len(payload)))

		got, err := io.ReadAll(r)

		require.NoError(t, err)
		assert.Equal(t, payload, got)
	})

	t.Run("a stream past the cap errors rather than truncating", func(t *testing.T) {
		r := newBoundedReadCloser(io.NopCloser(bytes.NewReader(payload)), int64(len(payload)-1))

		_, err := io.ReadAll(r)

		require.ErrorIs(t, err, errDecompressedTooLarge)
	})

	t.Run("the underlying read error is not masked", func(t *testing.T) {
		r := newBoundedReadCloser(io.NopCloser(iotest.ErrReader(errBoom)), 1024)

		_, err := io.ReadAll(r)

		require.ErrorIs(t, err, errBoom)
	})
}

var errBoom = errors.New("boom")

func Test_decompressionStream_boundsDecompressedSize(t *testing.T) {
	// a highly compressible payload standing in for a decompression bomb: tiny compressed, large out
	var raw bytes.Buffer
	raw.Write(make([]byte, 512*1024))

	var gz bytes.Buffer
	gw := gzip.NewWriter(&gz)
	_, err := gw.Write(raw.Bytes())
	require.NoError(t, err)
	require.NoError(t, gw.Close())

	require.Less(t, gz.Len(), 4096, "compressed payload should be tiny relative to what it expands to")

	rc, err := decompressionStream(context.Background(), bytes.NewReader(gz.Bytes()), "control.tar.gz", 64*1024)
	require.NoError(t, err, "the bound is enforced on read, not on open")
	t.Cleanup(func() { _ = rc.Close() })

	_, err = io.ReadAll(rc)

	require.ErrorIs(t, err, errDecompressedTooLarge)
}

func Test_processControlTar_rejectsABombedControlMember(t *testing.T) {
	// end to end through the real consumer: a tar reader treats a truncated stream as a clean end of
	// archive, so this asserts the bomb surfaces as an error instead of a package missing its files.
	// "control" parses fully before the md5sums stream dies, so this also covers the Fix C contract: a
	// control tar read failure must not drop the package that was already parsed.
	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	writeTarEntry(t, tw, "control", "Package: test-package\nVersion: 1.0.0\n")
	writeTarEntry(t, tw, "md5sums", strings.Repeat("d41d8cd98f00b204e9800998ecf8427e  usr/bin/x\n", 20000))
	require.NoError(t, tw.Close())

	metadata, err := processControlTar(newBoundedReadCloser(io.NopCloser(bytes.NewReader(tarBuf.Bytes())), 4096))

	require.ErrorIs(t, err, errDecompressedTooLarge)
	require.NotNil(t, metadata, "a control tar read failure after \"control\" was parsed must not drop the package")
	assert.Equal(t, "test-package", metadata.Package)
}

func Test_processControlTar_clippedListingIsUsableButReported(t *testing.T) {
	// the record cap must not drop the package: metadata comes back usable AND an error explains why the
	// file list is short, so the caller can record it as an unknown instead of discarding the package
	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	writeTarEntry(t, tw, "control", "Package: test-package\nVersion: 1.0.0\n")
	writeTarEntry(t, tw, "md5sums", strings.Repeat("d41d8cd98f00b204e9800998ecf8427e  usr/bin/x\n", maxDpkgFileRecords+10))
	require.NoError(t, tw.Close())

	metadata, err := processControlTar(io.NopCloser(bytes.NewReader(tarBuf.Bytes())))

	require.Error(t, err, "clipping must be reported")
	require.ErrorIs(t, err, errClippedFileListing)
	require.NotNil(t, metadata, "the package must survive a clipped file listing")
	assert.Equal(t, "test-package", metadata.Package)
	assert.Len(t, metadata.Files, maxDpkgFileRecords)
}

// buildDeb assembles a minimal .deb (an ar archive of debian-binary + control.tar.gz + data.tar.gz).
func buildDeb(t *testing.T, controlTar, dataTar []byte) []byte {
	t.Helper()

	gzipped := func(b []byte) []byte {
		var out bytes.Buffer
		w := gzip.NewWriter(&out)
		_, err := w.Write(b)
		require.NoError(t, err)
		require.NoError(t, w.Close())
		return out.Bytes()
	}

	var buf bytes.Buffer
	aw := ar.NewWriter(&buf)
	require.NoError(t, aw.WriteGlobalHeader())

	for _, m := range []struct {
		name string
		body []byte
	}{
		{"debian-binary", []byte("2.0\n")},
		{"control.tar.gz", gzipped(controlTar)},
		{"data.tar.gz", gzipped(dataTar)},
	} {
		require.NoError(t, aw.WriteHeader(&ar.Header{Name: m.name, Size: int64(len(m.body))}))
		_, err := aw.Write(m.body)
		require.NoError(t, err)
	}

	return buf.Bytes()
}

func Test_parseDebArchive_surfacesPartialParseAsUnknown(t *testing.T) {
	// guards a silent failure: unknownErr was accumulated and then dropped on return, so a data.tar that
	// failed to parse produced a clean-looking SBOM with no record that anything went wrong. The property
	// that actually matters is that the returned error is a *unknown.CoordinateError: that's what decides
	// between "recorded as an unknown" (this case) and "aborts the entire scan" (anything else), per
	// internal/task/executor.go and syft/create_sbom.go. A plain substring match on "data.tar" would pass
	// just as well if unknown.Append were swapped for errors.Join, which is the regression that matters.
	var controlTar bytes.Buffer
	ctw := tar.NewWriter(&controlTar)
	writeTarEntry(t, ctw, "control", "Package: test-package\nVersion: 1.0.0\nArchitecture: all\n")
	require.NoError(t, ctw.Close())

	// a data.tar that is not a valid tar at all, so processDataTar errors
	dataTar := []byte(strings.Repeat("not a tar file at all", 100))

	debBytes := buildDeb(t, controlTar.Bytes(), dataTar)

	loc := file.NewVirtualLocation("/test.deb", "/test.deb")
	pkgs, _, err := parseDebArchive(context.Background(), nil, &generic.Environment{},
		file.LocationReadCloser{
			Location:   loc,
			ReadCloser: io.NopCloser(bytes.NewReader(debBytes)),
		})

	require.Len(t, pkgs, 1, "the package must still be emitted")
	assert.Equal(t, "test-package", pkgs[0].Name)
	require.Error(t, err, "a failed data.tar parse must not be swallowed")

	coordinateErrors, remaining := unknown.ExtractCoordinateErrors(err)
	require.NoError(t, remaining, "no non-coordinate errors should remain in the chain")
	require.Len(t, coordinateErrors, 1)
	assert.Equal(t, loc.Coordinates, coordinateErrors[0].Coordinates)
	assert.Contains(t, coordinateErrors[0].Reason.Error(), "data.tar")
}

func Test_parseDebArchive_controlTarBombRejectedByRealSizeBound(t *testing.T) {
	// end to end through the real entrypoint using the real maxControlTarSize (16MB), not a swapped-in
	// test value: nothing else in this suite exercises that constant at its actual call site. The bomb
	// entry is written before "control", so "control" is never reached and processControlTar returns nil
	// metadata alongside the error -- this exercises parseDebArchive's fatal branch (metadata == nil).
	var controlTar bytes.Buffer
	ctw := tar.NewWriter(&controlTar)
	writeTarEntry(t, ctw, "bomb", strings.Repeat("\x00", 20*1024*1024))
	writeTarEntry(t, ctw, "control", "Package: test-package\nVersion: 1.0.0\n")
	require.NoError(t, ctw.Close())

	debBytes := buildDeb(t, controlTar.Bytes(), nil)
	require.Less(t, len(debBytes), 64*1024, "compressed .deb should stay tiny relative to what it expands to")

	loc := file.NewVirtualLocation("/bomb.deb", "/bomb.deb")
	pkgs, _, err := parseDebArchive(context.Background(), nil, &generic.Environment{},
		file.LocationReadCloser{
			Location:   loc,
			ReadCloser: io.NopCloser(bytes.NewReader(debBytes)),
		})

	require.Empty(t, pkgs, "no package should be emitted when the control tar never parses")
	require.Error(t, err)

	coordinateErrors, remaining := unknown.ExtractCoordinateErrors(err)
	require.NoError(t, remaining, "no non-coordinate errors should remain in the chain")
	require.Len(t, coordinateErrors, 1)
	require.ErrorIs(t, coordinateErrors[0].Reason, errDecompressedTooLarge)
}

// arMember is one named, already-encoded ar entry body, for tests that need control over the raw
// member list (order, duplicates) that buildDeb's fixed three-member shape does not allow.
type arMember struct {
	name string
	body []byte
}

// buildDebWithMembers is buildDeb generalized to an arbitrary member list.
func buildDebWithMembers(t *testing.T, members []arMember) []byte {
	t.Helper()

	var buf bytes.Buffer
	aw := ar.NewWriter(&buf)
	require.NoError(t, aw.WriteGlobalHeader())

	for _, m := range members {
		require.NoError(t, aw.WriteHeader(&ar.Header{Name: m.name, Size: int64(len(m.body))}))
		_, err := aw.Write(m.body)
		require.NoError(t, err)
	}

	return buf.Bytes()
}

func Test_parseDebArchive_ignoresDuplicateArMembers(t *testing.T) {
	// a .deb has exactly one control.tar.* and one data.tar.*; a second data.tar.* member is
	// attacker-supplied filler that would otherwise buy a fresh decompression budget, and here would also
	// fail to parse as a tar at all -- so this proves the walk stops after the first of each kind rather
	// than merely surviving a well-formed duplicate.
	gzipped := func(b []byte) []byte {
		var out bytes.Buffer
		w := gzip.NewWriter(&out)
		_, err := w.Write(b)
		require.NoError(t, err)
		require.NoError(t, w.Close())
		return out.Bytes()
	}

	var controlTar bytes.Buffer
	ctw := tar.NewWriter(&controlTar)
	writeTarEntry(t, ctw, "control", "Package: test-package\nVersion: 1.0.0\n")
	require.NoError(t, ctw.Close())

	var firstDataTar bytes.Buffer
	dtw := tar.NewWriter(&firstDataTar)
	require.NoError(t, dtw.Close())

	debBytes := buildDebWithMembers(t, []arMember{
		{"debian-binary", []byte("2.0\n")},
		// the duplicate sits before control.tar.gz on purpose: the loop cannot have stopped yet at that
		// point, so only the per-member guard can keep it from being read
		{"data.tar.gz", gzipped(firstDataTar.Bytes())},
		{"data.tar.gz", []byte("not a tar file at all")}, // not even gzipped; would error if ever read
		{"control.tar.gz", gzipped(controlTar.Bytes())},
	})

	pkgs, _, err := parseDebArchive(context.Background(), nil, &generic.Environment{},
		file.LocationReadCloser{
			Location:   file.NewVirtualLocation("/test.deb", "/test.deb"),
			ReadCloser: io.NopCloser(bytes.NewReader(debBytes)),
		})

	require.NoError(t, err, "the second data.tar.* member must never be reached")
	require.Len(t, pkgs, 1)
}

func Test_processDataTar_capsCopyrightFiles(t *testing.T) {
	// a real .deb ships exactly one copyright file per package; this asserts the walk stops and errors
	// rather than accumulating an unbounded number of license reads
	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	for i := 0; i < maxCopyrightFiles+10; i++ {
		writeTarEntry(t, tw, fmt.Sprintf("/usr/share/doc/pkg%d/copyright", i), "License: MIT\n")
	}
	require.NoError(t, tw.Close())

	_, err := processDataTar(io.NopCloser(bytes.NewReader(tarBuf.Bytes())))

	require.Error(t, err)
}
