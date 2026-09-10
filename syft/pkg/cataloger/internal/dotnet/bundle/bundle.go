package bundle

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	intFile "github.com/anchore/syft/internal/file"
	"github.com/anchore/syft/internal/log"
)

const (
	// maxBundleSearchSize bounds the bytes findSignatureOffset will hold at once while looking for the
	// bundle marker.
	//
	// The marker sits inside the executable structure, so the search legitimately covers a whole
	// single-file bundle, which routinely runs past 100MB and can reach a few hundred for an app that
	// embeds sizable assets. Clamping to the file length alone is not enough: a mostly empty file costs
	// almost nothing inside a compressed layer, so a small artifact can still authorize a multi-gigabyte
	// allocation. The trade-off is that a bundle larger than this loses its deps.json rather than being
	// cataloged, which is the correct direction to fail when the alternative is OOM-killing the scan.
	// This mirrors maxDeclaredSectionSize in syft/internal/elfutil.
	maxBundleSearchSize = 512 * intFile.MB

	// maxDepsJSONSize bounds an embedded deps.json. These are dependency manifests, so real ones are
	// measured in KB even for large applications.
	maxDepsJSONSize = 3 * intFile.MB

	// minManifestEntrySize is the smallest a single manifest entry can be: an 8 byte offset, an 8 byte
	// size, a 1 byte file type, and at least 1 byte for the length-prefixed relative path.
	minManifestEntrySize = 18

	// minManifestEntrySizeV6 adds the 8 byte compressed size field that V6+ bundles carry.
	minManifestEntrySizeV6 = minManifestEntrySize + 8
)

// dotNetBundleSignature is the SHA-256 hash of ".net core bundle" used to identify single-file bundles.
var dotNetBundleSignature = []byte{
	0x8b, 0x12, 0x02, 0xb9, 0x6a, 0x61, 0x20, 0x38,
	0x72, 0x7b, 0x93, 0x02, 0x14, 0xd7, 0xa0, 0x32,
	0x13, 0xf5, 0xb9, 0xe6, 0xef, 0xae, 0x33, 0x18,
	0xee, 0x3b, 0x2d, 0xce, 0x24, 0xb3, 0x6a, 0xae,
}

// ExtractDepsJSON returns the deps.json embedded in the .NET single-file bundle in r, or "" if r carries no
// bundle marker.
//
// searchLimit is where the caller's format parsing says the executable structure ends, which is as far into
// the file as the marker can be. It is only ever an optimization: it comes from user-controlled header
// fields, so it may describe far more than the file holds or overflow negative. A limit that makes no sense
// falls back to searching the whole file rather than searching nothing, since treating it as authoritative
// would let one bogus header field hide a bundle from us entirely.
func ExtractDepsJSON(r io.ReadSeeker, searchLimit int64) (string, error) {
	headerOffset, err := findSignatureOffset(r, searchLimit)
	if err != nil || headerOffset == 0 {
		return "", err
	}

	return readDepsJSONFromBundleHeader(r, headerOffset)
}

// findSignatureOffset searches the start of r for the .NET single-file bundle signature and returns the
// bundle header offset stored in the 8 bytes immediately before it.
//
// Three outcomes are distinct on purpose, because collapsing any two of them loses information the caller
// needs: 0 means there is no bundle here, an error means we could not tell, and a positive offset is the
// answer. In particular the apphost ships the signature compiled in with a zero offset placeholder and only
// gets a real one written when it is published as a single file, so a zero offset is the ordinary
// framework-dependent executable rather than a malformed one.
func findSignatureOffset(r io.ReadSeeker, searchLimit int64) (int64, error) {
	end, err := r.Seek(0, io.SeekEnd)
	if err != nil {
		return 0, err
	}

	// a limit that overflowed negative or overshoots the file tells us nothing, so fall back to the file
	// itself rather than trusting it; either way the absolute cap is what bounds the allocation
	limit := end
	if searchLimit > 0 && searchLimit < end {
		limit = searchLimit
	}

	if limit > maxBundleSearchSize {
		log.Tracef("bundle marker search clamped from %d to %d bytes; a marker past that will not be found", limit, maxBundleSearchSize)
		limit = maxBundleSearchSize
	}

	if limit == 0 {
		return 0, nil
	}

	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return 0, err
	}

	// this scans a whole executable, routinely over 100MB for a single-file bundle, so the buffer is sized
	// exactly once. An append-growing read holds both arrays at its final growth and would cost well over
	// twice the file's own size for the same result.
	searchData := make([]byte, limit)

	// a short read is not fatal here: unionreader can hand back fewer bytes than the file reports (a
	// squashfs block that decompresses short does exactly that), and the marker may well be in what we
	// did get, so search the bytes we actually hold
	n, err := io.ReadFull(r, searchData)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return 0, err
	}

	idx := bytes.Index(searchData[:n], dotNetBundleSignature)
	if idx == -1 || idx < 8 {
		return 0, nil
	}

	headerOffset := int64(binary.LittleEndian.Uint64(searchData[idx-8 : idx]))

	if headerOffset == 0 {
		// the marker is compiled into every apphost; only publishing as a single file fills in the offset
		return 0, nil
	}

	// the offset comes straight out of the file, so it is the least trustworthy value here: everything
	// downstream seeks to it and reads structures from it
	if headerOffset < 0 || headerOffset >= end {
		return 0, fmt.Errorf("bundle header offset %d lies outside the file (%d bytes)", headerOffset, end)
	}

	return headerOffset, nil
}

// dotNetBundleHeader represents the fixed portion of the bundle header (version 1+)
type dotNetBundleHeader struct {
	MajorVersion     uint32
	MinorVersion     uint32
	NumEmbeddedFiles int32
}

// dotNetBundleHeaderV2 represents additional fields in V2+ bundles (.NET 5+)
type dotNetBundleHeaderV2 struct {
	DepsJSONOffset          int64
	DepsJSONSize            int64
	RuntimeConfigJSONOffset int64
	RuntimeConfigJSONSize   int64
	Flags                   uint64
}

// dotNetFileType represents the type of bundled file in the manifest, as of V2 bundles (.NET 5+).
// note: V1 bundles (.NET Core 3.x) predate the unknown member at the head of this enum, so every type there is
// one less than the values below (e.g. deps.json is 2, not 3). see depsJSONFileType().
type dotNetFileType uint8

const (
	dotNetFileTypeUnknown dotNetFileType = iota
	dotNetFileTypeAssembly
	dotNetFileTypeNativeBinary
	dotNetFileTypeDepsJSON
	dotNetFileTypeRuntimeConfigJSON
	dotNetFileTypeSymbols
)

// readDepsJSONFromBundleHeader parses the bundle header at the given offset and extracts deps.json content.
func readDepsJSONFromBundleHeader(r io.ReadSeeker, headerOffset int64) (string, error) {
	if _, err := r.Seek(headerOffset, io.SeekStart); err != nil {
		return "", err
	}

	var header dotNetBundleHeader
	if err := binary.Read(r, binary.LittleEndian, &header); err != nil {
		return "", err
	}

	// skip bundle ID (7-bit length-prefixed string)
	if err := skipDotNetString(r); err != nil {
		return "", err
	}

	// for V2+ bundles (.NET 5+), read deps.json location directly from header
	if header.MajorVersion >= 2 {
		var headerV2 dotNetBundleHeaderV2
		if err := binary.Read(r, binary.LittleEndian, &headerV2); err != nil {
			return "", err
		}

		if headerV2.DepsJSONSize > 0 && headerV2.DepsJSONOffset > 0 {
			return readDepsJSONAtOffset(r, headerV2.DepsJSONOffset, headerV2.DepsJSONSize)
		}
	}

	// for V1 bundles (.NET Core 3.x) or if V2 header doesn't have deps.json, parse manifest
	return findDepsJSONInManifest(r, header.NumEmbeddedFiles, header.MajorVersion)
}

// skipDotNetString skips a 7-bit length-prefixed string (.NET BinaryWriter format)
func skipDotNetString(r io.ReadSeeker) error {
	length, err := read7BitEncodedInt(r)
	if err != nil {
		return err
	}
	_, err = r.Seek(int64(length), io.SeekCurrent)
	return err
}

// read7BitEncodedInt reads a .NET 7-bit encoded integer (variable-length encoding used by BinaryWriter)
func read7BitEncodedInt(r io.Reader) (int, error) {
	result := 0
	shift := 0
	for {
		var b [1]byte
		if _, err := r.Read(b[:]); err != nil {
			return 0, err
		}
		result |= int(b[0]&0x7F) << shift
		if b[0]&0x80 == 0 {
			break
		}
		shift += 7
		if shift >= 35 { // prevent overflow
			return 0, errors.New("invalid 7-bit encoded int")
		}
	}

	// the shift above can carry past int32 where int is 32 bits, and a negative length would seek callers
	// backwards and let a manifest walk re-read the same bytes for every file it claims
	if result < 0 {
		return 0, errors.New("negative 7-bit encoded int")
	}

	return result, nil
}

// readDepsJSONAtOffset reads deps.json content at a specific offset using seeks (avoiding loading entire file)
func readDepsJSONAtOffset(r io.ReadSeeker, offset, size int64) (string, error) {
	if size <= 0 {
		return "", nil
	}

	if size > maxDepsJSONSize {
		// worth a line rather than a silent "", nil: a real bundle this far past the cap would lose its
		// whole dependency list here with nothing to explain why
		log.Tracef("skipping embedded deps.json of %d bytes, past the %d byte limit", size, maxDepsJSONSize)
		return "", nil
	}
	if _, err := r.Seek(offset, io.SeekStart); err != nil {
		return "", fmt.Errorf("failed to seek to deps.json at offset %d: %w", offset, err)
	}
	data := make([]byte, size)
	if _, err := io.ReadFull(r, data); err != nil {
		return "", fmt.Errorf("failed to read deps.json (%d bytes): %w", size, err)
	}
	return string(data), nil
}

// depsJSONFileType returns the manifest file type that marks deps.json for the given bundle version. V1 bundles
// (.NET Core 3.x) have no unknown member in the file type enum, so all of their types are shifted down by one --
// reading them with the V2+ values silently matches runtimeconfig.json instead.
func depsJSONFileType(majorVersion uint32) dotNetFileType {
	if majorVersion < 2 {
		return dotNetFileTypeDepsJSON - 1
	}
	return dotNetFileTypeDepsJSON
}

// checkManifestFits rejects a manifest whose declared entry count could not fit in the bytes left after
// the current position, which means the count came from a malformed header.
func checkManifestFits(r io.Seeker, numFiles, minEntrySize int64) error {
	pos, err := r.Seek(0, io.SeekCurrent)
	if err != nil {
		return err
	}

	end, err := r.Seek(0, io.SeekEnd)
	if err != nil {
		return err
	}

	if _, err := r.Seek(pos, io.SeekStart); err != nil {
		return err
	}

	if remaining := end - pos; numFiles > remaining/minEntrySize {
		return fmt.Errorf("manifest claims %d entries but only %d bytes remain", numFiles, remaining)
	}

	return nil
}

// findDepsJSONInManifest parses manifest entries to find deps.json (for V1 bundles or fallback)
func findDepsJSONInManifest(r io.ReadSeeker, numFiles int32, majorVersion uint32) (string, error) {
	depsJSONType := depsJSONFileType(majorVersion)

	if numFiles < 0 {
		return "", fmt.Errorf("negative embedded file count: %d", numFiles)
	}

	// numFiles is a header field, so it can claim up to 2^31-1 entries. The walk terminates either way,
	// since every iteration reads forward and eventually hits EOF, but a count the remaining bytes could
	// not possibly hold means the header is malformed rather than describing a manifest worth hundreds of
	// millions of reads.
	minEntrySize := int64(minManifestEntrySize)
	if majorVersion >= 6 {
		minEntrySize = minManifestEntrySizeV6
	}

	if err := checkManifestFits(r, int64(numFiles), minEntrySize); err != nil {
		return "", err
	}

	for i := int32(0); i < numFiles; i++ {
		var offset, size int64

		if err := binary.Read(r, binary.LittleEndian, &offset); err != nil {
			return "", err
		}
		if err := binary.Read(r, binary.LittleEndian, &size); err != nil {
			return "", err
		}

		// V6+ bundles (.NET 6+) have compressed size field
		if majorVersion >= 6 {
			var compressedSize int64
			if err := binary.Read(r, binary.LittleEndian, &compressedSize); err != nil {
				return "", err
			}
		}

		var fileType dotNetFileType
		if err := binary.Read(r, binary.LittleEndian, &fileType); err != nil {
			return "", err
		}

		// skip relativePath string
		if err := skipDotNetString(r); err != nil {
			return "", err
		}

		if fileType == depsJSONType && size > 0 {
			// save current position to resume manifest parsing if needed
			currentPos, err := r.Seek(0, io.SeekCurrent)
			if err != nil {
				return "", err
			}

			// read deps.json content
			content, err := readDepsJSONAtOffset(r, offset, size)
			if err != nil {
				return "", err
			}

			// restore position (in case caller needs to continue)
			if _, err := r.Seek(currentPos, io.SeekStart); err != nil {
				return "", err
			}

			return content, nil
		}
	}
	return "", nil
}
