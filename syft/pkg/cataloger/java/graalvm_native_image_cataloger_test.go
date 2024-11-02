package java

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/internal/unionreader"
	"github.com/anchore/syft/syft/pkg"
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
			assert.NoError(t, err)
			for _, r := range readers {
				ni, err := test.newFn(test.fixture, r)
				assert.NoError(t, err)
				_, _, err = ni.fetchPkgs()
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
	const (
		nettyPurl     = "pkg:maven/io.netty/netty-codec-http2@4.1.104.Final"
		micronautPurl = "pkg:maven/io.micronaut/core@4.2.3"
		mainAppPurl   = "pkg:maven/com.oracle/main-test-app@1.0-SNAPSHOT"
	)

	mainAppPkg := makePackage("main-test-app", "1.0-SNAPSHOT", mainAppPurl, []cpe.CPE{
		{
			Attributes: cpe.Attributes{
				Part:    "a",
				Vendor:  "app",
				Product: "main-test-app",
				Version: "1.0-SNAPSHOT",
			},
			Source: "declared",
		},
	})

	nettyPkg := makePackage("netty-codec-http2", "4.1.73.Final", nettyPurl, []cpe.CPE{
		{
			Attributes: cpe.Attributes{
				Part:    "a",
				Vendor:  "codec",
				Product: "codec",
				Version: "4.1.73.Final",
			},
			Source: "declared",
		},
		{
			Attributes: cpe.Attributes{
				Part:    "a",
				Vendor:  "codec",
				Product: "netty-codec-http2",
				Version: "4.1.73.Final",
			},
			Source: "declared",
		},
		{
			Attributes: cpe.Attributes{
				Part:    "a",
				Vendor:  "codec",
				Product: "netty_codec_http2",
				Version: "4.1.73.Final",
			},
			Source: "declared",
		},
	})

	micronautPkg := makePackage("core", "4.2.3", micronautPurl, []cpe.CPE{
		{
			Attributes: cpe.Attributes{
				Part:    "a",
				Vendor:  "core",
				Product: "core",
				Version: "4.2.3",
			},
			Source: "declared",
		},
		{
			Attributes: cpe.Attributes{
				Part:    "a",
				Vendor:  "micronaut",
				Product: "core",
				Version: "4.2.3",
			},
			Source: "declared",
		},
	})

	basicPkg := makePackage("basic-lib", "1.0", "", nil)

	tests := []struct {
		fixture           string
		expectedPackages  []pkg.Package
		expectedRelations []artifact.Relationship
	}{
		{
			fixture:          "test-fixtures/graalvm-sbom/micronaut.json",
			expectedPackages: []pkg.Package{nettyPkg, micronautPkg, basicPkg, mainAppPkg},
			expectedRelations: []artifact.Relationship{
				{
					From: nettyPkg,
					To:   micronautPkg,
					Type: artifact.DependencyOfRelationship,
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(path.Base(test.fixture), func(t *testing.T) {
			compressed, length := createCompressedSbom(t, test.fixture)
			actualPkgs, actualRels, err := decompressSbom(compressed, 0, length)
			if err != nil {
				t.Fatal(err)
			}

			verifyPackages(t, test.expectedPackages, actualPkgs)
			verifyRelationships(t, test.expectedRelations, actualRels)
		})
	}
}

// makePackage makes a package using the data that we know must be in the parsed package
func makePackage(name, version, purl string, cpes []cpe.CPE) pkg.Package {
	p := pkg.Package{
		Name:    name,
		Version: version,
		CPEs:    cpes,
		PURL:    purl,
	}
	return p
}

// createCompressedSbom creates a compressed a buffer to resemble a compressed SBOM in a native image.
func createCompressedSbom(t *testing.T, filename string) ([]byte, uint64) {
	sbom, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}

	var b bytes.Buffer
	w := bufio.NewWriter(&b)
	z := gzip.NewWriter(w)

	if _, err := z.Write(sbom); err != nil {
		t.Fatal(err)
	}
	z.Close()
	w.Flush()

	compressedSbom := b.Bytes()
	sbomLength := uint64(len(compressedSbom))

	if err := binary.Write(w, binary.LittleEndian, sbomLength); err != nil {
		t.Fatal(err)
	}
	w.Flush()

	return b.Bytes(), sbomLength
}

func verifyPackages(t *testing.T, expected, actual []pkg.Package) {
	expectedPkgMap := buildPackageMap(expected)
	actualPkgMap := buildPackageMap(actual)

	for name, expectedPkg := range expectedPkgMap {
		actualPkg, exists := actualPkgMap[name]
		if !exists {
			t.Errorf("Expected package %s not found in actual packages", name)
			continue
		}
		verifyPackageFields(t, expectedPkg, actualPkg)
	}
}

func buildPackageMap(packages []pkg.Package) map[string]pkg.Package {
	pkgMap := make(map[string]pkg.Package)
	for _, p := range packages {
		pkgMap[p.Name] = p
	}
	return pkgMap
}

func verifyPackageFields(t *testing.T, expected, actual pkg.Package) {
	assert.Equal(t, expected.Name, actual.Name)
	assert.Equal(t, expected.Version, actual.Version)
	assert.Equal(t, expected.FoundBy, actual.FoundBy)
	assert.Equal(t, expected.PURL, actual.PURL)
	assert.ElementsMatch(t, expected.CPEs, actual.CPEs)
}

func verifyRelationships(t *testing.T, expected, actual []artifact.Relationship) {
	expectedRelMap := buildRelationshipMap(expected)
	actualRelMap := buildRelationshipMap(actual)

	for key, expectedRels := range expectedRelMap {
		actualRels, exists := actualRelMap[key]
		if !exists {
			t.Errorf("Expected relationship %s not found in actual relationships", key)
			continue
		}
		verifyRelationshipFields(t, expectedRels, actualRels)
	}
}

func buildRelationshipMap(relationships []artifact.Relationship) map[string][]artifact.Relationship {
	relMap := make(map[string][]artifact.Relationship)
	for _, rel := range relationships {
		// we cannot control the id, so use the names instead
		key := fmt.Sprintf("%s->%s", rel.From.(pkg.Package).Name, rel.To.(pkg.Package).Name)
		relMap[key] = append(relMap[key], rel)
	}
	return relMap
}

func verifyRelationshipFields(t *testing.T, expected, actual []artifact.Relationship) {
	assert.Equal(t, len(expected), len(actual))
	for i := range expected {
		assert.Equal(t, expected[i].Type, actual[i].Type)
	}
}
