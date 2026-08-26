package golang

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime/debug"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/internal/spillbuf"
	"github.com/anchore/syft/internal/tmpdir"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/internal/fileresolver"
	"github.com/anchore/syft/syft/internal/unionreader"
)

// TestScanFile_UnpackedBinaryReadsTheFileItWasGiven is the regression test for the shape of bug that
// modelling "not packed" as nil invites. The reader was once an io.ReadSeekCloser holding a nil pointer,
// which is a non-nil interface, so every ordinary Go binary took the packed branch: it seeked a nil file
// for its version and nil-dereferenced on close. The panic was recovered by the task executor, so the
// only symptom was the go-binary cataloger reporting nothing at all.
//
// The nil is now the signal rather than a hazard: unpacked is nil when there was nothing to unpack, and
// readerFor and seekerFor are the only two places that widen it into an interface.
//
// Docker-gated like everything else that needs a real Go binary; the point is that a plain binary reads
// from the file it was handed, which needs a real one.
func TestScanFile_UnpackedBinaryReadsTheFileItWasGiven(t *testing.T) {
	runMakeTarget(t, "archs")
	f, err := os.Open(filepath.Join("testdata", "archs", "binaries", "hello-linux-arm"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = f.Close() })

	ur, err := unionreader.GetUnionReader(f)
	require.NoError(t, err)

	builds, _ := scanFile(context.Background(), file.NewLocation("hello-linux-arm"), ur, false)
	require.NotEmpty(t, builds, "a plain Go binary must still produce build info")

	for _, b := range builds {
		assert.Nil(t, b.unpacked, "an unpacked binary must not have left a reconstruction behind")
		assert.Same(t, ur, seekerFor(b.unpacked, ur), "the readers after the scan must get the file itself")
		assert.NoError(t, b.unpacked.Close(), "Close is nil-safe, and a defer over every build calls it")
		assert.NoError(t, b.unpacked.Close(), "and it has to be idempotent")
	}
}

// TestParseGoBinary_PlainBinaryStillYieldsPackages is the same regression one layer out, at the entry
// point the cataloger actually calls. The typed-nil panic fired from a defer here and was swallowed by
// the task executor, so the failure mode is an empty result rather than an error.
func TestParseGoBinary_PlainBinaryStillYieldsPackages(t *testing.T) {
	runMakeTarget(t, "archs")
	f, err := os.Open(filepath.Join("testdata", "archs", "binaries", "hello-linux-arm"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = f.Close() })

	c := newGoBinaryCataloger(DefaultCatalogerConfig())
	pkgs, _, err := c.parseGoBinary(context.Background(), fileresolver.Empty{}, nil,
		file.NewLocationReadCloser(file.NewLocation("hello-linux-arm"), f))

	require.NoError(t, err)
	assert.NotEmpty(t, pkgs, "an ordinary Go binary must still produce packages")
}

// TestMakeGoMainPackage_VersionComesFromTheUnpackedContents pins the reader threading: for a packed
// binary the version scan has to read the reconstruction, since the packed bytes carry no readable
// version string. Nothing else covers this, because the from-contents scan is off by default and the
// Docker fixture gets its version from ldflags before the scan is reached.
func TestMakeGoMainPackage_VersionComesFromTheUnpackedContents(t *testing.T) {
	// the version pattern wants the string NUL-delimited
	unpacked := spillbuf.New(tmpdir.FromPath(t.TempDir()))
	t.Cleanup(func() { _ = unpacked.Close() })
	_, err := unpacked.WriteAt([]byte("\x00v9.9.9\x00"), 0)
	require.NoError(t, err)

	// what the packed file on disk would have said, which must not be what comes out
	packed := &nopReadSeekCloser{bytes.NewReader([]byte("\x00v1.1.1\x00"))}

	c := &goBinaryCataloger{
		licenseResolver:   newGoLicenseResolver("", CatalogerConfig{}),
		mainModuleVersion: MainModuleVersionConfig{FromContents: true},
	}
	mod := &extendedBuildInfo{
		BuildInfo: &debug.BuildInfo{Main: debug.Module{Path: "github.com/anchore/syft", Version: devel}},
		unpacked:  unpacked,
	}

	got := c.makeGoMainPackage(context.Background(), fileresolver.Empty{}, mod, "amd64",
		file.NewLocation("packed"), seekerFor(mod.unpacked, packed), nil)

	assert.Equal(t, "v9.9.9", got.Version, "the version must come from the reconstruction, not the packed bytes")
}
