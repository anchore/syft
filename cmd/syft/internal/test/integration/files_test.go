package integration

import (
	"crypto"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/clio"
	stereoscopeFile "github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/syft/cmd/syft/internal/options"
	"github.com/anchore/syft/syft/cataloging/filecataloging"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/file/cataloger/filecontent"
	"github.com/anchore/syft/syft/sbom"
)

func TestFileCataloging_Default(t *testing.T) {
	cfg := options.DefaultCatalog().ToSBOMConfig(clio.Identification{})
	cfg = cfg.WithFilesConfig(filecataloging.DefaultConfig())
	sbom, _ := catalogDirectoryWithConfig(t, "test-fixtures/files", cfg)

	var metadata map[file.Coordinates]file.Metadata

	var digests map[file.Coordinates][]file.Digest

	var contents map[file.Coordinates]string

	assertFileData(t, metadata, digests, contents, sbom)
}

func TestFileCataloging_AllFiles(t *testing.T) {
	cfg := options.DefaultCatalog().ToSBOMConfig(clio.Identification{})
	cfg = cfg.WithFilesConfig(filecataloging.Config{
		Selection: file.AllFilesSelection,
		Hashers: []crypto.Hash{
			crypto.SHA256,
		},
		Content: filecontent.Config{
			// this is enough to potentially capture a/file, a-small-file, a-symlink-to-a-small-file, and a-symlink-to-file
			// but the size of a/file will cause it to be filtered, and the symlinks will not be included since
			// they are not regular files
			Globs:              []string{"**/*file"},
			SkipFilesAboveSize: 30,
		},
	})
	sbom, _ := catalogDirectoryWithConfig(t, "test-fixtures/files", cfg)

	pwd, err := os.Getwd()
	require.NoError(t, err)

	testPath := func(path string) string {
		return filepath.Join(pwd, "test-fixtures/files", path)
	}

	metadata := map[file.Coordinates]file.Metadata{
		{RealPath: ""}: {
			Path: testPath(""),
			Type: stereoscopeFile.TypeDirectory,
		},
		{RealPath: "/somewhere"}: {
			Path: testPath("/somewhere"),
			Type: stereoscopeFile.TypeDirectory,
		},
		{RealPath: "/somewhere/there"}: {
			Path: testPath("/somewhere/there"),
			Type: stereoscopeFile.TypeDirectory,
		},
		{RealPath: "/somewhere/there/is"}: {
			Path: testPath("/somewhere/there/is"),
			Type: stereoscopeFile.TypeDirectory,
		},
		{RealPath: "/somewhere/there/is/a"}: {
			Path: testPath("/somewhere/there/is/a"),
			Type: stereoscopeFile.TypeDirectory,
		},
		{RealPath: "/somewhere/there/is/a-small-file"}: {
			Path:     testPath("/somewhere/there/is/a-small-file"),
			Type:     stereoscopeFile.TypeRegular,
			MIMEType: "text/plain",
		},
		{RealPath: "/somewhere/there/is/a-symlink-to-a-small-file"}: {
			Path:            testPath("/somewhere/there/is/a-symlink-to-a-small-file"),
			LinkDestination: testPath("/somewhere/there/is/a-small-file"),
			Type:            stereoscopeFile.TypeSymLink,
		},
		{RealPath: "/somewhere/there/is/a-symlink-to-file"}: {
			Path:            testPath("/somewhere/there/is/a-symlink-to-file"),
			LinkDestination: testPath("/somewhere/there/is/a/file"),
			Type:            stereoscopeFile.TypeSymLink,
		},
		{RealPath: "/somewhere/there/is/a/file"}: {
			Path:     testPath("/somewhere/there/is/a/file"),
			Type:     stereoscopeFile.TypeRegular,
			MIMEType: "text/plain",
		},
	}

	digests := map[file.Coordinates][]file.Digest{
		{RealPath: "/somewhere/there/is/a-small-file"}: {
			file.Digest{Algorithm: "sha256", Value: "672c23470e4ce99cf270bb63ae66ad2b8a80aa19090c40e59fbb1229a4ab661a"},
		},
		{RealPath: "/somewhere/there/is/a/file"}: {
			file.Digest{Algorithm: "sha256", Value: "00dac26d6d94353ac0d92bb9640cba76f82f5ca8707bb845ecdc574bd002348e"},
		},
	}

	contents := map[file.Coordinates]string{
		{RealPath: "/somewhere/there/is/a-small-file"}: "c29tZSBjb250ZW50cyE=",
	}

	assertFileData(t, metadata, digests, contents, sbom)

}

func assertFileData(t testing.TB, metadata map[file.Coordinates]file.Metadata, digests map[file.Coordinates][]file.Digest, contents map[file.Coordinates]string, sbom sbom.SBOM) {
	metadataCompareOpts := cmp.Options{
		cmp.Comparer(func(x, y file.Metadata) bool {
			if x.Path != y.Path {
				t.Logf("path mismatch: %s != %s", x.Path, y.Path)
				return false
			}

			if x.Type != y.Type {
				t.Logf("type mismatch: %s != %s", x.Type, y.Type)
				return false
			}

			if x.LinkDestination != y.LinkDestination {
				t.Logf("link destination mismatch: %s != %s", x.LinkDestination, y.LinkDestination)
				return false
			}

			if x.MIMEType != y.MIMEType {
				t.Logf("mime type mismatch: %s != %s", x.MIMEType, y.MIMEType)
				return false
			}

			return true
		}),
	}

	if d := cmp.Diff(metadata, sbom.Artifacts.FileMetadata, metadataCompareOpts...); d != "" {
		t.Errorf("unexpected metadata (-want +got):\n%s", d)
	}

	assert.Equal(t, digests, sbom.Artifacts.FileDigests, "different digests detected")
	assert.Equal(t, contents, sbom.Artifacts.FileContents, "different contents detected")

}
