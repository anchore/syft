package pe

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"errors"
	"io"

	"github.com/anchore/syft/syft/pkg/cataloger/internal/dotnet/bundle"
)

// dotNetBundleSignature is the SHA-256 hash of ".net core bundle" used to identify single-file bundles.
var dotNetBundleSignature = []byte{
	0x8b, 0x12, 0x02, 0xb9, 0x6a, 0x61, 0x20, 0x38,
	0x72, 0x7b, 0x93, 0x02, 0x14, 0xd7, 0xa0, 0x32,
	0x13, 0xf5, 0xb9, 0xe6, 0xef, 0xae, 0x33, 0x18,
	0xee, 0x3b, 0x2d, 0xce, 0x24, 0xb3, 0x6a, 0xae,
}

// ExtractDepsJSONFromBundle searches for an embedded deps.json file in a .NET single-file bundle.
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

	return bundle.ReadDepsJSONFromBundleHeader(r, headerOffset)
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
