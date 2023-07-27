package java

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"io"
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/unionreader"
)

func TestParseNativeImage(t *testing.T) {
	tests := []struct {
		fixture string
		newFn   func(filename string, r io.ReaderAt) (nativeImage, error)
	}{
		{
			fixture: "example-java-app",
			newFn:   newElf,
		},
		{
			fixture: "gcc-amd64-darwin-exec-debug",
			newFn:   newMachO,
		},
	}
	for _, test := range tests {
		t.Run(test.fixture, func(t *testing.T) {
			f, err := os.Open("test-fixtures/java-builds/packages/" + test.fixture)
			assert.NoError(t, err)
			readerCloser := io.NopCloser(f)
			reader, err := unionreader.GetUnionReader(readerCloser)
			assert.NoError(t, err)
			parsed := false
			readers, err := unionreader.GetReaders(reader)
			for _, r := range readers {
				ni, err := test.newFn(test.fixture, r)
				assert.NoError(t, err)
				_, err = ni.fetchPkgs()
				if err == nil {
					t.Fatalf("should have failed to extract SBOM.")
				}
				// If we can enumerate the symbols in the binary, we can parse the binary.
				if err.Error() == nativeImageMissingSymbolsError {
					parsed = true
				}
			}
			if !parsed {
				t.Fatalf("Could not parse the Native Image executable: %v", test.fixture)
			}
		})
	}
}

func TestParseNativeImageSbom(t *testing.T) {
	tests := []struct {
		fixture  string
		expected []pkg.Package
	}{
		{
			fixture: "test-fixtures/graalvm-sbom/micronaut.json",
			expected: []pkg.Package{
				{
					Name:         "netty-codec-http2",
					Version:      "4.1.73.Final",
					Language:     pkg.Java,
					Type:         pkg.GraalVMNativeImagePkg,
					MetadataType: pkg.JavaMetadataType,
					FoundBy:      nativeImageCatalogerName,
					Metadata: pkg.JavaMetadata{
						PomProperties: &pkg.PomProperties{
							GroupID: "io.netty",
						},
					},
					CPEs: []cpe.CPE{
						{
							Part:    "a",
							Vendor:  "codec",
							Product: "codec",
							Version: "4.1.73.Final",
						},
						{
							Part:    "a",
							Vendor:  "codec",
							Product: "netty-codec-http2",
							Version: "4.1.73.Final",
						},
						{
							Part:    "a",
							Vendor:  "codec",
							Product: "netty_codec_http2",
							Version: "4.1.73.Final",
						},
					},
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(path.Base(test.fixture), func(t *testing.T) {
			// Create a buffer to resemble a compressed SBOM in a native image.
			sbom, err := os.ReadFile(test.fixture)
			assert.NoError(t, err)
			var b bytes.Buffer
			writebytes := bufio.NewWriter(&b)
			z := gzip.NewWriter(writebytes)
			_, err = z.Write(sbom)
			assert.NoError(t, err)
			_ = z.Close()
			_ = writebytes.Flush()
			compressedsbom := b.Bytes()
			sbomlength := uint64(len(compressedsbom))
			_ = binary.Write(writebytes, binary.LittleEndian, sbomlength)
			_ = writebytes.Flush()
			compressedsbom = b.Bytes()
			actual, err := decompressSbom(compressedsbom, 0, sbomlength)
			assert.NoError(t, err)
			assert.Equal(t, test.expected, actual)
		})
	}
}
