package pe

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// dotNetBundleSignature is the SHA-256 hash of ".net core bundle" used to identify single-file bundles.
var dotNetBundleSignature = []byte{
	0x8b, 0x12, 0x02, 0xb9, 0x6a, 0x61, 0x20, 0x38,
	0x72, 0x7b, 0x93, 0x02, 0x14, 0xd7, 0xa0, 0x32,
	0x13, 0xf5, 0xb9, 0xe6, 0xef, 0xae, 0x33, 0x18,
	0xee, 0x3b, 0x2d, 0xce, 0x24, 0xb3, 0x6a, 0xae,
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

// dotNetFileType represents the type of bundled file in the manifest
type dotNetFileType uint8

const (
	dotNetFileTypeUnknown dotNetFileType = iota
	dotNetFileTypeAssembly
	dotNetFileTypeNativeBinary
	dotNetFileTypeDepsJSON
	dotNetFileTypeRuntimeConfigJSON
	dotNetFileTypeSymbols
)

// extractDepsJSONFromBundle searches for an embedded deps.json file in a .NET single-file bundle.
// When built with PublishSingleFile=true, .NET embeds the application and all dependencies into
// the AppHost executable. The bundle marker (8-byte header offset + 32-byte signature) is placed
// in a placeholder location within the PE structure, pointing to the bundle header which contains
// file entry metadata. For V2+ bundles (.NET 5+), the header includes direct offsets to deps.json;
// for V1 bundles (.NET Core 3.x), we parse the manifest to locate it.
//
//	┌──────────────────────────────────┐
//	│ PE AppHost Binary                │  Standard PE structure
//	│   ...                            │
//	│   [8B offset][32B signature]     │  Bundle marker (in placeholder within PE)
//	│   ...                            │
//	├──────────────────────────────────┤
//	│ Bundled Files                    │  Raw file contents (assemblies, deps.json, etc.)
//	├──────────────────────────────────┤
//	│ Bundle Header                    │  Version info, file count, deps.json offset (V2+)
//	│ File Manifest                    │  Per-file: offset, size, type, path
//	└──────────────────────────────────┘
//
// Parsing strategy:
//  1. Search only the PE portion (using section headers) for the bundle signature
//  2. Read 8 bytes before signature to get header offset
//  3. Parse header to get deps.json location (V2+) or scan manifest entries (V1)
//
// See related documentation for more information:
// - https://github.com/dotnet/designs/blob/main/accepted/2020/single-file/design.md
// - https://github.com/dotnet/designs/blob/main/accepted/2020/single-file/bundler.md
// - https://github.com/dotnet/runtime/blob/main/src/installer/managed/Microsoft.NET.HostModel/Bundle/Manifest.cs
// - https://github.com/dotnet/runtime/blob/main/src/installer/managed/Microsoft.NET.HostModel/Bundle/Bundler.cs
// - https://github.com/dotnet/runtime/blob/main/src/native/corehost/bundle/header.h
// - https://github.com/dotnet/runtime/blob/main/src/native/corehost/bundle/file_entry.h
// - https://github.com/dotnet/runtime/blob/main/src/native/corehost/bundle/file_type.h
func extractDepsJSONFromBundle(r io.ReadSeeker, sections []pe.SectionHeader32) (string, error) {
	headerOffset, err := findBundleHeaderOffset(r, sections)
	if err != nil {
		return "", err
	}
	if headerOffset == 0 {
		return "", nil // not a .NET single-file bundle
	}

	return readDepsJSONFromBundleHeader(r, headerOffset)
}

// findBundleHeaderOffset locates the bundle marker within the PE structure and returns the header offset.
// Returns 0 if no bundle marker is found (not a single-file bundle).
func findBundleHeaderOffset(r io.ReadSeeker, sections []pe.SectionHeader32) (int64, error) {
	peEndOffset := calculatePEEndOffset(sections)

	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return 0, err
	}

	peData := make([]byte, peEndOffset)
	n, err := io.ReadFull(r, peData)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
		return 0, err
	}
	peData = peData[:n]

	idx := bytes.Index(peData, dotNetBundleSignature)
	if idx == -1 || idx < 8 {
		return 0, nil
	}

	// the header offset is stored in the 8 bytes immediately before the signature
	headerOffset := int64(binary.LittleEndian.Uint64(peData[idx-8 : idx]))
	return headerOffset, nil
}

// calculatePEEndOffset determines where the PE structure ends based on section headers,
// adding padding for alignment. This bounds our search for the bundle marker.
func calculatePEEndOffset(sections []pe.SectionHeader32) int64 {
	var peEndOffset int64
	for _, sec := range sections {
		endOfSection := int64(sec.PointerToRawData) + int64(sec.SizeOfRawData)
		if endOfSection > peEndOffset {
			peEndOffset = endOfSection
		}
	}
	// add buffer for alignment padding after sections
	return peEndOffset + 4096
}

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
	return result, nil
}

// readDepsJSONAtOffset reads deps.json content at a specific offset using seeks (avoiding loading entire file)
func readDepsJSONAtOffset(r io.ReadSeeker, offset, size int64) (string, error) {
	if _, err := r.Seek(offset, io.SeekStart); err != nil {
		return "", fmt.Errorf("failed to seek to deps.json at offset %d: %w", offset, err)
	}
	data := make([]byte, size)
	if _, err := io.ReadFull(r, data); err != nil {
		return "", fmt.Errorf("failed to read deps.json (%d bytes): %w", size, err)
	}
	return string(data), nil
}

// findDepsJSONInManifest parses manifest entries to find deps.json (for V1 bundles or fallback)
func findDepsJSONInManifest(r io.ReadSeeker, numFiles int32, majorVersion uint32) (string, error) {
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

		if fileType == dotNetFileTypeDepsJSON && size > 0 {
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
