package pe

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// dotNetBundleSignature is the SHA-256 hash of ".net core bundle" used to identify single-file bundles.
// this marker is located at the last 32 bytes of a .NET single-file bundle.
var dotNetBundleSignature = []byte{
	0x8b, 0x12, 0x02, 0xb9, 0x6a, 0x61, 0x20, 0x38,
	0x72, 0x7b, 0x93, 0x02, 0x14, 0xd7, 0xa0, 0x32,
	0x13, 0xf5, 0xb9, 0xe6, 0xef, 0xae, 0x33, 0x18,
	0xee, 0x3b, 0x2d, 0xce, 0x24, 0xb3, 0x6a, 0xae,
}

const (
	// bundleMarkerSize is the size of the bundle marker at the end of a .NET single-file bundle (8 byte offset + 32 byte signature)
	bundleMarkerSize = 40
)

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

// extractDepsJSONFromBundle searches the provided reader for an embedded deps.json file in a .NET single-file bundle.
// when using the SingleFilePublish option, .NET applications embed the deps.json file within the binary like so:
//
//	┌──────────────────────────────────┐
//	│ PE Host Binary                   │  <-- Standard PE structure
//	├──────────────────────────────────┤
//	│ Bundled Files (binary blob)      │  <-- deps.json lives here
//	├──────────────────────────────────┤
//	│ Bundle Header + Manifest         │  <-- Metadata
//	├──────────────────────────────────┤
//	│ Bundle Marker (last 40 bytes)    │  <-- Entry point for parsing
//	│   [8B header offset][32B sig]    │
//	└──────────────────────────────────┘
//
// See related documentation for more information:
// - https://github.com/dotnet/designs/blob/main/accepted/2020/single-file/design.md
// - https://github.com/dotnet/designs/blob/main/accepted/2020/single-file/bundler.md
// - https://github.com/dotnet/runtime/blob/main/src/installer/managed/Microsoft.NET.HostModel/Bundle/Manifest.cs
// - https://github.com/dotnet/runtime/blob/main/src/installer/managed/Microsoft.NET.HostModel/Bundle/Bundler.cs
// - https://github.com/dotnet/runtime/blob/main/src/native/corehost/bundle/header.h
// - https://github.com/dotnet/runtime/blob/main/src/native/corehost/bundle/file_entry.h
// - https://github.com/dotnet/runtime/blob/main/src/native/corehost/bundle/file_type.h
func extractDepsJSONFromBundle(r io.ReadSeeker) (string, error) {
	// the bundle marker (signature + header offset) is embedded within the PE file, not at the end.
	// we need to search for the signature pattern to find the bundle header offset location.

	// read the entire file to search for the signature
	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return "", err
	}

	data, err := io.ReadAll(r)
	if err != nil {
		return "", err
	}

	// search for the bundle signature in the file
	idx := bytes.Index(data, dotNetBundleSignature)
	if idx == -1 {
		return "", nil // not a .NET single-file bundle
	}

	// the header offset is stored in the 8 bytes immediately before the signature
	if idx < 8 {
		return "", nil // invalid bundle format
	}

	headerOffset := int64(binary.LittleEndian.Uint64(data[idx-8 : idx]))
	if headerOffset == 0 || headerOffset >= int64(len(data)) {
		return "", nil // invalid offset or not a bundle
	}

	// create a reader starting at the header offset
	headerReader := bytes.NewReader(data[headerOffset:])

	var header dotNetBundleHeader
	if err := binary.Read(headerReader, binary.LittleEndian, &header); err != nil {
		return "", err
	}

	// skip bundle ID (7-bit length-prefixed string)
	if err := skipDotNetStringFromReader(headerReader); err != nil {
		return "", err
	}

	// for V2+ bundles (.NET 5+), read deps.json location directly from header
	if header.MajorVersion >= 2 {
		var headerV2 dotNetBundleHeaderV2
		if err := binary.Read(headerReader, binary.LittleEndian, &headerV2); err != nil {
			return "", err
		}

		if headerV2.DepsJSONSize > 0 && headerV2.DepsJSONOffset > 0 {
			return readBundleContentFromData(data, headerV2.DepsJSONOffset, headerV2.DepsJSONSize)
		}
	}

	// for V1 bundles (.NET Core 3.x) or if V2 header doesn't have deps.json, parse manifest
	return findDepsJSONInManifestFromReader(headerReader, data, header.NumEmbeddedFiles, header.MajorVersion)
}

// skipDotNetStringFromReader skips a 7-bit length-prefixed string (.NET BinaryWriter format) using a bytes.Reader
func skipDotNetStringFromReader(r *bytes.Reader) error {
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

// readBundleContentFromData reads content from a specific offset in the data buffer
func readBundleContentFromData(data []byte, offset, size int64) (string, error) {
	if offset < 0 || offset+size > int64(len(data)) {
		return "", fmt.Errorf("invalid offset/size for bundle content: offset=%d, size=%d, dataLen=%d", offset, size, len(data))
	}
	return string(data[offset : offset+size]), nil
}

// findDepsJSONInManifestFromReader parses manifest entries to find deps.json (for V1 bundles or fallback)
func findDepsJSONInManifestFromReader(r *bytes.Reader, data []byte, numFiles int32, majorVersion uint32) (string, error) {
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
		if err := skipDotNetStringFromReader(r); err != nil {
			return "", err
		}

		if fileType == dotNetFileTypeDepsJSON && size > 0 {
			// read deps.json content directly from the data buffer
			return readBundleContentFromData(data, offset, size)
		}
	}
	return "", nil
}
