package java

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"

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
			f, err := os.Open("testdata/java-builds/packages/" + test.fixture)
			require.NoError(t, err)
			readerCloser := io.NopCloser(f)
			reader, err := unionreader.GetUnionReader(readerCloser)
			require.NoError(t, err)
			parsed := false
			readers, err := unionreader.GetReaders(reader)
			require.NoError(t, err)
			for _, r := range readers {
				ni, err := test.newFn(test.fixture, r)
				require.NoError(t, err)
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
			fixture:          "testdata/graalvm-sbom/micronaut.json",
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
	require.Equal(t, expected.Name, actual.Name)
	require.Equal(t, expected.Version, actual.Version)
	require.Equal(t, expected.FoundBy, actual.FoundBy)
	require.Equal(t, expected.PURL, actual.PURL)
	require.ElementsMatch(t, expected.CPEs, actual.CPEs)
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
	require.Equal(t, len(expected), len(actual))
	for i := range expected {
		require.Equal(t, expected[i].Type, actual[i].Type)
	}
}

// buildMinimalPE64 assembles the smallest PE64 that debug/pe will parse, with DataDirectory[0] (the
// export directory) set to the given RVA and size. totalSize is how large the resulting file is; the
// point of the fixture is that size can claim far more than that.
//
// newPE uses the directory's VirtualAddress directly as a file offset rather than translating it, so the
// fixture needs no sections and exportRVA doubles as the offset the read starts from.
func buildMinimalPE64(exportRVA, exportSize uint32, totalSize int) []byte {
	const peHdrOff = 0x40
	buf := make([]byte, totalSize)
	copy(buf, []byte{'M', 'Z'})
	binary.LittleEndian.PutUint32(buf[0x3c:], peHdrOff)

	p := buf[peHdrOff:]
	copy(p, []byte{'P', 'E', 0, 0})
	// COFF file header
	binary.LittleEndian.PutUint16(p[4:], 0x8664) // Machine = AMD64
	binary.LittleEndian.PutUint16(p[20:], 240)   // SizeOfOptionalHeader
	binary.LittleEndian.PutUint16(p[22:], 0x22)  // Characteristics: executable image

	// optional header (PE32+)
	oh := p[24:]
	binary.LittleEndian.PutUint16(oh[0:], 0x20b) // Magic = PE32+
	binary.LittleEndian.PutUint32(oh[108:], 16)  // NumberOfRvaAndSizes
	// DataDirectory[0] = export table
	binary.LittleEndian.PutUint32(oh[112:], exportRVA)
	binary.LittleEndian.PutUint32(oh[116:], exportSize)

	return buf
}

func TestNewPE_ExportDirectorySizeIsNotAllocatedUpFront(t *testing.T) {
	// exportSymbolsDataDirectory.Size is a user-controlled uint32 from the PE optional header, and it used
	// to size a make([]byte, Size) before the read, so an 8KB file claiming 4GB reserved 4GB.
	data := buildMinimalPE64(0x1000, 0xFFFFFFFF, 8192)

	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, err := newPE("oversized-export-dir.exe", bytes.NewReader(data))
	runtime.ReadMemStats(&after)

	require.Error(t, err, "an export directory the file cannot satisfy must not read as successful")
	require.Contains(t, err.Error(), "truncated")

	allocated := after.TotalAlloc - before.TotalAlloc
	t.Logf("allocated %d bytes for a directory declaring %d", allocated, uint64(0xFFFFFFFF))
	require.Less(t, allocated, uint64(8*1024*1024),
		"the declared size must not be reserved before the read confirms the bytes exist")
}

func TestNewPE_ExportDirectoryWithinFileIsRead(t *testing.T) {
	// the bound must not reject an export directory that really is present
	data := buildMinimalPE64(0x1000, 64, 8192)

	ni, err := newPE("ok.exe", bytes.NewReader(data))
	require.NoError(t, err)
	require.NotNil(t, ni)
}

func TestDecompressSbom_RejectsOutOfRangeOffsets(t *testing.T) {
	// every offset and length below is read out of the binary, so each has to be rejected rather than
	// wrapped into a value that passes a bound and then panics on the slice that follows
	tests := []struct {
		name         string
		bufLen       int
		sbomStart    uint64
		lengthStart  uint64
		storedLength uint64
	}{
		{
			name:        "length offset wraps past the end of the buffer",
			bufLen:      64,
			lengthStart: ^uint64(0) - 3, // lengthStart+8 wraps to 4, which compares as in range
		},
		{
			name:        "length offset starts beyond the buffer",
			bufLen:      64,
			lengthStart: 100,
		},
		{
			name:         "stored length wraps past the end of the buffer",
			bufLen:       64,
			sbomStart:    16,
			lengthStart:  0,
			storedLength: ^uint64(0) - 3, // sbomStart+storedLength wraps to 12
		},
		{
			name:         "stored length runs past the end of the buffer",
			bufLen:       64,
			sbomStart:    16,
			lengthStart:  0,
			storedLength: 1000,
		},
		{
			name:        "sbom offset starts beyond the buffer",
			bufLen:      64,
			sbomStart:   ^uint64(0) - 3,
			lengthStart: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dataBuf := make([]byte, tt.bufLen)
			// subtract from the length rather than adding to the offset, for the same reason the code
			// under test has to: tt.lengthStart is deliberately large enough to wrap
			if tt.lengthStart <= uint64(tt.bufLen) && uint64(tt.bufLen)-tt.lengthStart >= 8 {
				binary.LittleEndian.PutUint64(dataBuf[tt.lengthStart:], tt.storedLength)
			}

			require.NotPanics(t, func() {
				_, _, err := decompressSbom(dataBuf, tt.sbomStart, tt.lengthStart)
				require.Error(t, err)
			})
		})
	}
}

func TestDecompressSbom_RejectsStreamExpandingPastTheLimit(t *testing.T) {
	// the compressed bytes are bounded by the file, but what they expand to is not, and the decoder
	// buffers the whole stream before it can tell whether the payload is even CycloneDX. Zeros stand in
	// for any uniform, highly compressible payload: they expand about 1000x, far past what real JSON does.
	// the bound is passed in rather than taken from nativeImageMaxDecompressedSbomSize, so that tripping
	// it costs a megabyte instead of the several hundred the real limit would demand
	const limit = 1024 * 1024
	const decompressedSize = limit + 1

	var compressed bytes.Buffer
	z := gzip.NewWriter(&compressed)
	_, err := z.Write(make([]byte, decompressedSize))
	require.NoError(t, err)
	require.NoError(t, z.Close())

	t.Logf("%d compressed bytes expand to %d (%dx)", compressed.Len(), decompressedSize,
		decompressedSize/compressed.Len())

	dataBuf := append(compressed.Bytes(), make([]byte, 8)...)
	lengthStart := uint64(compressed.Len())
	binary.LittleEndian.PutUint64(dataBuf[lengthStart:], lengthStart)

	_, _, err = decompressSbomWithLimit(dataBuf, 0, lengthStart, limit)
	require.Error(t, err)
	require.Contains(t, err.Error(), "decompresses past",
		"hitting the bound should say so, not report a parse failure")
}

func TestDecompressSbom_AcceptsLargeSbom(t *testing.T) {
	// guards the risk the size limit introduces: a genuinely large SBOM must still be cataloged.
	// Components carry distinct names, versions, purls and hashes, so this is shaped like a real
	// CycloneDX document rather than a uniform payload.
	const components = 20000

	var sb bytes.Buffer
	sb.WriteString(`{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":[`)
	for i := 0; i < components; i++ {
		if i > 0 {
			sb.WriteString(",")
		}
		// a sha256-shaped value keeps the entropy (and so the compression ratio) realistic
		hash := sha256.Sum256([]byte(fmt.Sprintf("component-%d", i)))
		fmt.Fprintf(&sb, `{"type":"library","name":"lib-%d","version":"%d.%d.%d",`+
			`"purl":"pkg:maven/com.example.group%d/lib-%d@%d.%d.%d",`+
			`"hashes":[{"alg":"SHA-256","content":"%x"}]}`,
			i, i%20, i%7, i%13, i%50, i, i%20, i%7, i%13, hash)
	}
	sb.WriteString(`]}`)

	raw := sb.Bytes()
	var compressed bytes.Buffer
	z := gzip.NewWriter(&compressed)
	_, err := z.Write(raw)
	require.NoError(t, err)
	require.NoError(t, z.Close())

	t.Logf("%d components: %d bytes of JSON, %d compressed (%dx), limit %d",
		components, len(raw), compressed.Len(), len(raw)/compressed.Len(), nativeImageMaxDecompressedSbomSize)
	require.Less(t, int64(len(raw)), int64(nativeImageMaxDecompressedSbomSize),
		"a real SBOM of this size must sit well inside the limit, otherwise the limit is too low")

	dataBuf := append(compressed.Bytes(), make([]byte, 8)...)
	lengthStart := uint64(compressed.Len())
	binary.LittleEndian.PutUint64(dataBuf[lengthStart:], lengthStart)

	pkgs, _, err := decompressSbom(dataBuf, 0, lengthStart)
	require.NoError(t, err, "a large SBOM at a realistic ratio must not be rejected")
	require.Len(t, pkgs, components)
}
