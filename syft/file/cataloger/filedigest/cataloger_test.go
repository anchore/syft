package filedigest

import (
	"context"
	"crypto"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	stereoscopeFile "github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/imagetest"
	intFile "github.com/anchore/syft/internal/file"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/source"
	"github.com/anchore/syft/syft/source/directorysource"
	"github.com/anchore/syft/syft/source/stereoscopesource"
)

func testDigests(t testing.TB, root string, files []string, hashes ...crypto.Hash) map[file.Coordinates][]file.Digest {
	digests := make(map[file.Coordinates][]file.Digest)

	for _, f := range files {
		fh, err := os.Open(filepath.Join(root, f))
		if err != nil {
			t.Fatalf("could not open %q : %+v", f, err)
		}
		b, err := io.ReadAll(fh)
		if err != nil {
			t.Fatalf("could not read %q : %+v", f, err)
		}

		if len(b) == 0 {
			// we don't keep digests for empty files
			digests[file.NewLocation(f).Coordinates] = []file.Digest{}
			continue
		}

		for _, hash := range hashes {
			h := hash.New()
			h.Write(b)
			digests[file.NewLocation(f).Coordinates] = append(digests[file.NewLocation(f).Coordinates], file.Digest{
				Algorithm: intFile.CleanDigestAlgorithmName(hash.String()),
				Value:     fmt.Sprintf("%x", h.Sum(nil)),
			})
		}
	}

	return digests
}

func TestDigestsCataloger(t *testing.T) {

	tests := []struct {
		name     string
		digests  []crypto.Hash
		files    []string
		expected map[file.Coordinates][]file.Digest
	}{
		{
			name:     "md5",
			digests:  []crypto.Hash{crypto.MD5},
			files:    []string{"test-fixtures/last/empty/empty", "test-fixtures/last/path.txt"},
			expected: testDigests(t, "test-fixtures/last", []string{"empty/empty", "path.txt"}, crypto.MD5),
		},
		{
			name:     "md5-sha1-sha256",
			digests:  []crypto.Hash{crypto.MD5, crypto.SHA1, crypto.SHA256},
			files:    []string{"test-fixtures/last/empty/empty", "test-fixtures/last/path.txt"},
			expected: testDigests(t, "test-fixtures/last", []string{"empty/empty", "path.txt"}, crypto.MD5, crypto.SHA1, crypto.SHA256),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c := NewCataloger(test.digests)

			src, err := directorysource.NewFromPath("test-fixtures/last/")
			require.NoError(t, err)

			resolver, err := src.FileResolver(source.SquashedScope)
			require.NoError(t, err)

			actual, err := c.Catalog(context.Background(), resolver)
			require.NoError(t, err)

			assert.Equal(t, test.expected, actual, "mismatched digests")
		})
	}
}

func TestDigestsCataloger_MixFileTypes(t *testing.T) {
	testImage := "image-file-type-mix"

	img := imagetest.GetFixtureImage(t, "docker-archive", testImage)

	src := stereoscopesource.New(img, stereoscopesource.ImageConfig{
		Reference: testImage,
	})

	resolver, err := src.FileResolver(source.SquashedScope)
	if err != nil {
		t.Fatalf("could not create resolver: %+v", err)
	}

	tests := []struct {
		path     string
		expected string
	}{
		{
			path:     "/file-1.txt",
			expected: "888c139e550867814eb7c33b84d76e4d",
		},
		// this is difficult to reproduce in a cross-platform way
		//{
		//	path: "/hardlink-1",
		//},
		{
			path: "/symlink-1",
		},
		{
			path: "/char-device-1",
		},
		{
			path: "/block-device-1",
		},
		{
			path: "/fifo-1",
		},
		{
			path: "/bin",
		},
	}

	for _, test := range tests {
		t.Run(test.path, func(t *testing.T) {
			c := NewCataloger([]crypto.Hash{crypto.MD5})

			actual, err := c.Catalog(context.Background(), resolver)
			if err != nil {
				t.Fatalf("could not catalog: %+v", err)
			}

			_, ref, err := img.SquashedTree().File(stereoscopeFile.Path(test.path))
			if err != nil {
				t.Fatalf("unable to get file=%q : %+v", test.path, err)
			}
			l := file.NewLocationFromImage(test.path, *ref.Reference, img)

			if len(actual[l.Coordinates]) == 0 {
				if test.expected != "" {
					t.Fatalf("no digest found, but expected one")
				}

			} else {
				assert.Equal(t, actual[l.Coordinates][0].Value, test.expected, "mismatched digests")
			}
		})
	}
}

func TestFileDigestCataloger_GivenCoordinates(t *testing.T) {
	testImage := "image-file-type-mix"

	img := imagetest.GetFixtureImage(t, "docker-archive", testImage)

	c := NewCataloger([]crypto.Hash{crypto.SHA256})

	src := stereoscopesource.New(img, stereoscopesource.ImageConfig{
		Reference: testImage,
	})

	resolver, err := src.FileResolver(source.SquashedScope)
	require.NoError(t, err)

	tests := []struct {
		path     string
		exists   bool
		expected string
	}{
		{
			path:     "/file-1.txt",
			exists:   true,
			expected: "b089629781f05ef805b4511e93717f2ffa4c9d991771d5cbfa4b7242b4ef5fff",
		},
	}

	for _, test := range tests {
		t.Run(test.path, func(t *testing.T) {
			_, ref, err := img.SquashedTree().File(stereoscopeFile.Path(test.path))
			require.NoError(t, err)

			l := file.NewLocationFromImage(test.path, *ref.Reference, img)

			// note: an important difference between this test and the previous is that this test is using a list
			// of specific coordinates to catalog
			actual, err := c.Catalog(context.Background(), resolver, l.Coordinates)
			require.NoError(t, err)
			require.Len(t, actual, 1)

			assert.Equal(t, test.expected, actual[l.Coordinates][0].Value, "mismatched digests")
		})
	}

}
