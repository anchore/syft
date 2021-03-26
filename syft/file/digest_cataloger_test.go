package file

import (
	"crypto"
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	"github.com/anchore/stereoscope/pkg/file"

	"github.com/anchore/stereoscope/pkg/imagetest"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/source"
)

func testDigests(t testing.TB, files []string, hashes ...crypto.Hash) map[source.Location][]Digest {
	digests := make(map[source.Location][]Digest)

	for _, f := range files {
		fh, err := os.Open(f)
		if err != nil {
			t.Fatalf("could not open %q : %+v", f, err)
		}
		b, err := ioutil.ReadAll(fh)
		if err != nil {
			t.Fatalf("could not read %q : %+v", f, err)
		}

		for _, hash := range hashes {
			h := hash.New()
			h.Write(b)
			digests[source.NewLocation(f)] = append(digests[source.NewLocation(f)], Digest{
				Algorithm: cleanAlgorithmName(hash.String()),
				Value:     fmt.Sprintf("%x", h.Sum(nil)),
			})
		}
	}

	return digests
}

func TestDigestsCataloger_SimpleContents(t *testing.T) {
	regularFiles := []string{"test-fixtures/last/path.txt", "test-fixtures/another-path.txt", "test-fixtures/a-path.txt"}

	tests := []struct {
		name           string
		algorithms     []string
		files          []string
		expected       map[source.Location][]Digest
		constructorErr bool
		catalogErr     bool
	}{
		{
			name:           "bad algorithm",
			algorithms:     []string{"sha-nothing"},
			files:          regularFiles,
			constructorErr: true,
		},
		{
			name:           "unsupported algorithm",
			algorithms:     []string{"sha512"},
			files:          regularFiles,
			constructorErr: true,
		},
		{
			name:       "md5",
			algorithms: []string{"md5"},
			files:      regularFiles,
			expected:   testDigests(t, regularFiles, crypto.MD5),
		},
		{
			name:       "md5-sha1-sha256",
			algorithms: []string{"md5", "sha1", "sha256"},
			files:      regularFiles,
			expected:   testDigests(t, regularFiles, crypto.MD5, crypto.SHA1, crypto.SHA256),
		},
		{
			name:       "directory returns error",
			algorithms: []string{"md5"},
			files:      []string{"test-fixtures/last"},
			catalogErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c, err := NewDigestsCataloger(test.algorithms)
			if err != nil && !test.constructorErr {
				t.Fatalf("could not create cataloger (but should have been able to): %+v", err)
			} else if err == nil && test.constructorErr {
				t.Fatalf("expected constructor error but did not get one")
			} else if test.constructorErr && err != nil {
				return
			}

			resolver := source.NewMockResolverForPaths(test.files...)
			actual, err := c.Catalog(resolver)
			if err != nil && !test.catalogErr {
				t.Fatalf("could not catalog (but should have been able to): %+v", err)
			} else if err == nil && test.catalogErr {
				t.Fatalf("expected catalog error but did not get one")
			} else if test.catalogErr && err != nil {
				return
			}

			assert.Equal(t, actual, test.expected, "mismatched digests")

		})
	}
}

func TestDigestsCataloger_MixFileTypes(t *testing.T) {
	testImage := "image-file-type-mix"

	if *updateImageGoldenFiles {
		imagetest.UpdateGoldenFixtureImage(t, testImage)
	}

	img := imagetest.GetGoldenFixtureImage(t, testImage)

	src, err := source.NewFromImage(img, "---")
	if err != nil {
		t.Fatalf("could not create source: %+v", err)
	}

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
		{
			path: "/hardlink-1",
		},
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
			c, err := NewDigestsCataloger([]string{"md5"})
			if err != nil {
				t.Fatalf("unable to get cataloger: %+v", err)
			}

			actual, err := c.Catalog(resolver)
			if err != nil {
				t.Fatalf("could not catalog: %+v", err)
			}

			_, ref, err := img.SquashedTree().File(file.Path(test.path))
			if err != nil {
				t.Fatalf("unable to get file=%q : %+v", test.path, err)
			}
			l := source.NewLocationFromImage(test.path, *ref, img)

			if len(actual[l]) == 0 {
				if test.expected != "" {
					t.Fatalf("no digest found, but expected one")
				}

			} else {
				assert.Equal(t, actual[l][0].Value, test.expected, "mismatched digests")
			}
		})
	}
}
