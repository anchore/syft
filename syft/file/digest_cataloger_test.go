package file

import (
	"crypto"
	"fmt"
	"io/ioutil"
	"os"
	"testing"

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

func TestDigestsCataloger(t *testing.T) {
	files := []string{"test-fixtures/last/path.txt", "test-fixtures/another-path.txt", "test-fixtures/a-path.txt"}

	tests := []struct {
		name           string
		algorithms     []string
		expected       map[source.Location][]Digest
		constructorErr bool
		catalogErr     bool
	}{
		{
			name:           "bad algorithm",
			algorithms:     []string{"sha-nothing"},
			constructorErr: true,
		},
		{
			name:           "unsupported algorithm",
			algorithms:     []string{"sha512"},
			constructorErr: true,
		},
		{
			name:       "md5-sha1-sha256",
			algorithms: []string{"md5"},
			expected:   testDigests(t, files, crypto.MD5),
		},
		{
			name:       "md5-sha1-sha256",
			algorithms: []string{"md5", "sha1", "sha256"},
			expected:   testDigests(t, files, crypto.MD5, crypto.SHA1, crypto.SHA256),
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

			resolver := source.NewMockResolverForPaths(files...)
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
