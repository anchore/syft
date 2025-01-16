package dotnet

import (
	"bytes"
	"context"
	"debug/pe"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/internal/unionreader"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
	"io"
)

const peMaxAllowedDirectoryEntries = 0x1000

var _ generic.Parser = parseDotnetPortableExecutable

type peDosHeader struct {
	Magic                 [2]byte // "MZ"
	Unused                [58]byte
	AddressOfNewEXEHeader uint32 // offset to PE header
}

// peImageResourceDirectory represents the resource directory structure.
type peImageResourceDirectory struct {
	Characteristics      uint32
	TimeDateStamp        uint32
	MajorVersion         uint16
	MinorVersion         uint16
	NumberOfNamedEntries uint16
	NumberOfIDEntries    uint16
}

// peImageResourceDirectoryEntry represents an entry in the resource directory entries.
type peImageResourceDirectoryEntry struct {
	Name         uint32
	OffsetToData uint32
}

// peImageResourceDataEntry is the unit of raw data in the Resource Data area.
type peImageResourceDataEntry struct {
	OffsetToData uint32
	Size         uint32
	CodePage     uint32
	Reserved     uint32
}

// peResourceDirectory represents resource directory information.
type peResourceDirectory struct {
	Struct  peImageResourceDirectory
	Entries []peResourceDirectoryEntry
}

// peResourceDirectoryEntry represents a resource directory entry.
type peResourceDirectoryEntry struct {
	Struct        peImageResourceDirectoryEntry
	Name          string
	ID            uint32
	IsResourceDir bool
	Directory     peResourceDirectory
	Data          peResourceDataEntry
}

// peResourceDataEntry represents a resource data entry.
type peResourceDataEntry struct {
	Struct  peImageResourceDataEntry
	Lang    uint32
	SubLang uint32
}

// peVsFixedFileInfo represents the fixed file information structure.
type peVsFixedFileInfo struct {
	Signature        uint32
	StructVersion    uint32
	FileVersionMS    uint32
	FileVersionLS    uint32
	ProductVersionMS uint32
	ProductVersionLS uint32
	FileFlagsMask    uint32
	FileFlags        uint32
	FileOS           uint32
	FileType         uint32
	FileSubtype      uint32
	FileDateMS       uint32
	FileDateLS       uint32
}

type peVsVersionInfo peLenValLenType

type peStringFileInfo peLenValLenType

type peStringTable peLenValLenType

type peString peLenValLenType

type peLenValLenType struct {
	Length      uint16
	ValueLength uint16
	Type        uint16
}

func parseDotnetPortableExecutable(_ context.Context, _ file.Resolver, _ *generic.Environment, f file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	r, err := unionreader.GetUnionReader(f)
	if err != nil {
		return nil, nil, err
	}

	vAddress, vSize, rsrcSection, err := findResourceSection(r)
	if rsrcSection == nil {
		return nil, nil, errors.New("resource section not found")
	}

	var dirs []uint32
	versionResources := make(map[string]string)
	err = parseResourceDirectory(rsrcSection, vAddress, vSize, vAddress, dirs, versionResources)
	if err != nil {
		log.WithFields("error", err).Error("unable to parse version resources in PE file")
		return nil, nil, err
	}

	dotNetPkg, err := newDotnetBinaryPackage(versionResources, f)
	if err != nil {
		log.Tracef("unable to build dotnet package for: %v %v", f.RealPath, err)
		return nil, nil, err
	}

	return []pkg.Package{dotNetPkg}, nil, nil
}

// findResourceSection locates and reads the .rsrc section using debug/pe types.
func findResourceSection(file unionreader.UnionReader) (uint32, uint32, *bytes.Reader, error) {
	var dosHeader peDosHeader
	if err := binary.Read(file, binary.LittleEndian, &dosHeader); err != nil {
		return 0, 0, nil, fmt.Errorf("error reading DOS header: %w", err)
	}
	if string(dosHeader.Magic[:]) != "MZ" {
		return 0, 0, nil, fmt.Errorf("invalid DOS header magic")
	}

	peOffset := int64(dosHeader.AddressOfNewEXEHeader)
	if _, err := file.Seek(peOffset, io.SeekStart); err != nil {
		return 0, 0, nil, fmt.Errorf("error seeking to PE header: %w", err)
	}

	var signature [4]byte
	if err := binary.Read(file, binary.LittleEndian, &signature); err != nil {
		return 0, 0, nil, fmt.Errorf("error reading PE signature: %w", err)
	}
	if !bytes.Equal(signature[:], []byte("PE\x00\x00")) {
		return 0, 0, nil, fmt.Errorf("invalid PE signature")
	}

	var fileHeader pe.FileHeader
	if err := binary.Read(file, binary.LittleEndian, &fileHeader); err != nil {
		return 0, 0, nil, fmt.Errorf("error reading file header: %w", err)
	}

	var magic uint16
	if err := binary.Read(file, binary.LittleEndian, &magic); err != nil {
		return 0, 0, nil, fmt.Errorf("error reading optional header magic: %w", err)
	}

	// seek back to before reading magic (since that value is in the header)
	if _, err := file.Seek(-2, io.SeekCurrent); err != nil {
		return 0, 0, nil, fmt.Errorf("error seeking back to before reading magic: %w", err)
	}

	var optVirtualAddress uint32
	var optSize uint32
	if magic == 0x10B { // PE32
		var optHeader pe.OptionalHeader32
		if err := binary.Read(file, binary.LittleEndian, &optHeader); err != nil {
			return 0, 0, nil, fmt.Errorf("error reading optional header (PE32): %w", err)
		}

		if optHeader.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_RESOURCE].Size != 0 {
			sectionHeader := optHeader.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_RESOURCE]
			optVirtualAddress = sectionHeader.VirtualAddress
			optSize = sectionHeader.Size
		}
	} else if magic == 0x20B { // PE32+
		var optHeader pe.OptionalHeader64
		if err := binary.Read(file, binary.LittleEndian, &optHeader); err != nil {
			return 0, 0, nil, fmt.Errorf("error reading optional header (PE32+): %w", err)
		}

		if optHeader.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_RESOURCE].Size != 0 {
			sectionHeader := optHeader.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_RESOURCE]
			optVirtualAddress = sectionHeader.VirtualAddress
			optSize = sectionHeader.Size
		}
	} else {
		return 0, 0, nil, fmt.Errorf("unknown optional header magic: 0x%x", magic)
	}

	var otherSections []pe.SectionHeader32
	for i := 0; i < int(fileHeader.NumberOfSections); i++ {
		var sectionHeader pe.SectionHeader32
		if err := binary.Read(file, binary.LittleEndian, &sectionHeader); err != nil {
			return 0, 0, nil, fmt.Errorf("error reading section header: %w", err)
		}

		sectionName := string(bytes.Trim(sectionHeader.Name[:], "\x00"))
		if sectionName == ".rsrc" {
			// seek to the raw data of the section
			if _, err := file.Seek(int64(sectionHeader.PointerToRawData), io.SeekStart); err != nil {
				return 0, 0, nil, fmt.Errorf("error seeking to .rsrc data: %w", err)
			}

			// read the raw data
			data := make([]byte, sectionHeader.SizeOfRawData)
			if _, err := file.Read(data); err != nil {
				return 0, 0, nil, fmt.Errorf("error reading .rsrc section data: %w", err)
			}

			return sectionHeader.VirtualAddress, sectionHeader.SizeOfRawData, bytes.NewReader(data), nil
		} else {
			otherSections = append(otherSections, sectionHeader)
		}
	}

	if optVirtualAddress != 0 && optSize != 0 {
		for _, section := range otherSections {
			if optVirtualAddress >= section.VirtualAddress && optVirtualAddress < section.VirtualAddress+section.VirtualSize {
				// seek to the raw data of the section
				if _, err := file.Seek(int64(section.PointerToRawData), io.SeekStart); err != nil {
					return 0, 0, nil, fmt.Errorf("error seeking to .rsrc data: %w", err)
				}

				// read the raw data
				data := make([]byte, section.SizeOfRawData)
				if _, err := file.Read(data); err != nil {
					return 0, 0, nil, fmt.Errorf("error reading .rsrc section data: %w", err)
				}

				return optVirtualAddress, optSize, bytes.NewReader(data), nil
			}
		}
	}

	return 0, 0, nil, fmt.Errorf(".rsrc section not found")
}

// parseResourceDirectory recursively parses a PE resource directory. This takes a relative virtual address (offset of
// a piece of data or code relative to the base address), the size of the resource directory, the set of RVAs already
// parsed, and the map to populate discovered version resource values.
//
// .rsrc Section
// +------------------------------+
// | Resource Directory Table     |
// +------------------------------+
// | Resource Directory Entries   |
// |  +------------------------+  |
// |  | Subdirectory or Data   |  |
// |  +------------------------+  |
// +------------------------------+
// | Resource Data Entries        |
// |  +------------------------+  |
// |  | Resource Data          |  |
// |  +------------------------+  |
// +------------------------------+
// | Actual Resource Data         |
// +------------------------------+
//
// sources:
// - https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-rsrc-section
// - https://learn.microsoft.com/en-us/previous-versions/ms809762(v=msdn.10)#pe-file-resources
func parseResourceDirectory(reader *bytes.Reader, rva, size, baseRVA uint32, dirs []uint32, fields map[string]string) error {
	if size <= 0 {
		return nil
	}

	var directoryHeader peImageResourceDirectory

	offset := int64(rva - baseRVA)
	if _, err := reader.Seek(offset, io.SeekStart); err != nil {
		return fmt.Errorf("error seeking to directory offset: %w", err)
	}

	if err := readIntoStruct(reader, &directoryHeader); err != nil {
		return fmt.Errorf("error reading directory header: %w", err)
	}

	numEntries := int(directoryHeader.NumberOfNamedEntries + directoryHeader.NumberOfIDEntries)
	switch {
	case numEntries > peMaxAllowedDirectoryEntries:
		return fmt.Errorf("too many entries in resource directory: %d", numEntries)
	case numEntries == 0:
		return fmt.Errorf("no entries in resource directory")
	case numEntries < 0:
		return fmt.Errorf("invalid number of entries in resource directory: %d", numEntries)
	}

	for i := 0; i < numEntries; i++ {
		var entry peImageResourceDirectoryEntry

		entryOffset := offset + int64(binary.Size(directoryHeader)) + int64(i*binary.Size(entry))
		if _, err := reader.Seek(entryOffset, io.SeekStart); err != nil {
			log.Tracef("error seeking to PE entry offset: %v", err)
			continue
		}

		if err := readIntoStruct(reader, &entry); err != nil {
			continue
		}

		// if the high bit is set, this is a directory entry, otherwise it is a data entry
		isDirectory := entry.OffsetToData&0x80000000 != 0

		// note: the offset is relative to the beginning of the resource section, not an RVA
		entryOffsetToData := entry.OffsetToData & 0x7FFFFFFF

		if isDirectory {
			subRVA := baseRVA + entryOffsetToData
			if intInSlice(subRVA, dirs) {
				// some malware uses recursive PE references to evade analysis
				log.Tracef("recursive PE reference detected; skipping directory at rva=0x%x", subRVA)
				continue
			}

			dirs = append(dirs, subRVA)
			err := parseResourceDirectory(reader, subRVA, size-(rva-baseRVA), baseRVA, dirs, fields)
			if err != nil {
				return err
			}
		} else {
			err := parseResourceDataEntry(reader, baseRVA, baseRVA+entryOffsetToData, size, fields)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// intInSlice checks weather a uint32 exists in a slice of uint32.
func intInSlice(a uint32, list []uint32) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

func parseResourceDataEntry(reader *bytes.Reader, baseRVA, rva, remainingSize uint32, fields map[string]string) error {
	var dataEntry peImageResourceDataEntry
	offset := int64(rva - baseRVA)

	if _, err := reader.Seek(offset, io.SeekStart); err != nil {
		return fmt.Errorf("error seeking to data entry offset: %w", err)
	}

	if err := readIntoStruct(reader, &dataEntry); err != nil {
		return fmt.Errorf("error reading resource data entry: %w", err)
	}

	if remainingSize < dataEntry.Size {
		return fmt.Errorf("resource data entry size exceeds remaining size")
	}

	data := make([]byte, dataEntry.Size)
	if _, err := reader.Seek(int64(dataEntry.OffsetToData-baseRVA), io.SeekStart); err != nil {
		return fmt.Errorf("error seeking to resource data: %w", err)
	}

	if _, err := reader.Read(data); err != nil {
		return fmt.Errorf("error reading resource data: %w", err)
	}

	return parseVersionResourceSection(bytes.NewReader(data), fields)
}

// parseVersionResourceSection parses a PE version resource section from within a resource directory.
//
//	"The main structure in a version resource is the VS_FIXEDFILEINFO structure. Additional structures include the
//	VarFileInfo structure to store language information data, and StringFileInfo for user-defined string information.
//	All strings in a version resource are in Unicode format. Each block of information is aligned on a DWORD boundary."
//
//	"VS_VERSIONINFO" (utf16)
//	+---------------------------------------------------+
//	| wLength (2 bytes)                                 |
//	| wValueLength (2 bytes)                            |
//	| wType (2 bytes)                                   |
//	| szKey ("VS_VERSION_INFO") (utf16)                 |
//	| Padding (to DWORD)                                |
//	+---------------------------------------------------+
//	| VS_FIXEDFILEINFO (52 bytes)                       |
//	+---------------------------------------------------+
//	| "StringFileInfo" (utf16)                          |
//	+---------------------------------------------------+
//	| wLength (2 bytes)                                 |
//	| wValueLength (2 bytes)                            |
//	| wType (2 bytes)                                   |
//	| szKey ("StringFileInfo") (utf16)                  |
//	| Padding (to DWORD)                                |
//	| StringTable                                       |
//	|   +--------------------------------------------+  |
//	|   | wLength (2 bytes)                          |  |
//	|   | wValueLength (2 bytes)                     |  |
//	|   | wType (2 bytes)                            |  |
//	|   | szKey ("040904b0")                         |  |
//	|   | Padding (to DWORD)                         |  |
//	|   | String                                     |  |
//	|   | +--------------------------------------+   |  |
//	|   | | wLength (2 bytes)                    |   |  |
//	|   | | wValueLength (2 bytes)               |   |  |
//	|   | | wType (2 bytes)                      |   |  |
//	|   | | szKey ("FileVersion")                |   |  |
//	|   | | Padding (to DWORD)                   |   |  |
//	|   | | szValue ("15.00.0913.015")           |   |  |
//	|   | | Padding (to DWORD)                   |   |  |
//	|   +--------------------------------------------+  |
//	+---------------------------------------------------+
//	| VarFileInfo  (utf16)                              |
//	+---------------------------------------------------+
//	| (skip!)                                           |
//	+---------------------------------------------------+
//
// sources:
//   - https://learn.microsoft.com/en-us/windows/win32/menurc/resource-file-formats
//   - https://learn.microsoft.com/en-us/windows/win32/menurc/vs-versioninfo
//   - https://learn.microsoft.com/en-us/windows/win32/api/verrsrc/ns-verrsrc-vs_fixedfileinfo
//   - https://learn.microsoft.com/en-us/windows/win32/menurc/varfileinfo
//   - https://learn.microsoft.com/en-us/windows/win32/menurc/stringfileinfo
//   - https://learn.microsoft.com/en-us/windows/win32/menurc/stringtable
func parseVersionResourceSection(reader *bytes.Reader, fields map[string]string) error {
	offset := 0

	var info peVsVersionInfo
	if szKey, err := readIntoStructAndSzKey(reader, &info, &offset); err != nil {
		return fmt.Errorf("error reading PE version info: %v", err)
	} else if szKey != "VS_VERSION_INFO" {
		// this is a resource section, but not the version resources
		return nil
	}

	if err := alignAndSeek(reader, &offset); err != nil {
		return fmt.Errorf("error aligning past PE version info: %w", err)
	}

	var fixedFileInfo peVsFixedFileInfo
	if err := readIntoStruct(reader, &fixedFileInfo, &offset); err != nil {
		return fmt.Errorf("error reading PE FixedFileInfo: %v", err)
	}

	for reader.Len() > 0 {
		if err := alignAndSeek(reader, &offset); err != nil {
			return fmt.Errorf("error seeking to PE StringFileInfo: %w", err)
		}

		var sfiHeader peStringFileInfo
		if szKey, err := readIntoStructAndSzKey(reader, &sfiHeader, &offset); err != nil {
			return fmt.Errorf("error reading PE string file info header: %v", err)
		} else if szKey != "StringFileInfo" {
			// we only care about extracting strings from any string tables, skip this
			offset += int(sfiHeader.ValueLength)
			continue
		}

		var stOffset int

		// note: the szKey for the prStringTable is the language
		var stHeader peStringTable
		if _, err := readIntoStructAndSzKey(reader, &stHeader, &offset, &stOffset); err != nil {
			return fmt.Errorf("error reading PE string table header: %v", err)
		}

		for stOffset < int(stHeader.Length) {
			var stringHeader peString
			if err := readIntoStruct(reader, &stringHeader, &offset, &stOffset); err != nil {
				break
			}

			key := readUTF16(reader, &offset, &stOffset)

			if err := alignAndSeek(reader, &offset, &stOffset); err != nil {
				return fmt.Errorf("error aligning to next PE string table value: %w", err)
			}

			var value string
			if stringHeader.ValueLength > 0 {
				value = readUTF16(reader, &offset, &stOffset)
			}

			fields[key] = value
			// TODO: change to trace log?
			// log.WithFields("key", key, "value", value).Warn("found PE string table entry")

			if err := alignAndSeek(reader, &offset, &stOffset); err != nil {
				return fmt.Errorf("error aligning to next PE string table key: %w", err)
			}
		}
	}

	if fields["FileVersion"] == "" {
		// we can derive the file version from the fixed file info if it is not already specified as a string entry
		fields["FileVersion"] = fmt.Sprintf("%d.%d.%d.%d",
			fixedFileInfo.FileVersionMS>>16, fixedFileInfo.FileVersionMS&0xFFFF,
			fixedFileInfo.FileVersionLS>>16, fixedFileInfo.FileVersionLS&0xFFFF)
	}

	return nil
}

func readIntoStructAndSzKey[T any](reader *bytes.Reader, data *T, offsets ...*int) (string, error) {
	if err := readIntoStruct(reader, data, offsets...); err != nil {
		return "", err
	}
	return readUTF16(reader, offsets...), nil
}

func readIntoStruct[T any](reader io.Reader, data *T, offsets ...*int) error {
	if err := binary.Read(reader, binary.LittleEndian, data); err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		return err
	}

	for i := range offsets {
		*offsets[i] += binary.Size(*data)
	}
	return nil
}

func alignAndSeek(reader io.Seeker, offset *int, trackOffsets ...*int) error {
	ogOffset := *offset
	*offset = alignToDWORD(*offset)
	diff := *offset - ogOffset
	for i := range trackOffsets {
		*trackOffsets[i] += diff
	}
	_, err := reader.Seek(int64(*offset), io.SeekStart)
	return err
}

func alignToDWORD(offset int) int {
	return (offset + 3) & ^3
}

func readUTF16(reader *bytes.Reader, offsets ...*int) string {
	var result []rune
	for {
		var char uint16
		if err := binary.Read(reader, binary.LittleEndian, &char); err != nil || char == 0 {
			break
		}
		result = append(result, rune(char))
	}
	if len(result) == 0 {
		return ""
	}

	for i := range offsets {
		*offsets[i] += len(result)*2 + 2 // utf-16 characters + null terminator
	}
	return string(result)
}

func mergeDotnetPEs(pkgs []pkg.Package, rels []artifact.Relationship, givenErr error) ([]pkg.Package, []artifact.Relationship, error) {
	// merge packages by package.ID, if they are the same ID then merge the package
	pkgsByID := make(map[artifact.ID]*pkg.Package)
	var extra []pkg.Package
	for i := range pkgs {
		p := &pkgs[i]
		mId, err := artifact.IDByHash(p.Metadata)
		if err != nil {
			log.WithFields("error", err).Trace("unable to hash dotnet package metadata")
			extra = append(extra, *p)
			continue
		}
		if existingPkg, ok := pkgsByID[mId]; ok {
			merge(existingPkg, p)
			continue
		}
		pkgsByID[mId] = p
	}
	var finalPkgs []pkg.Package
	for _, p := range pkgsByID {
		finalPkgs = append(finalPkgs, *p)
	}
	finalPkgs = append(finalPkgs, extra...)

	pkg.Sort(finalPkgs)

	// TODO: once relationships are supported, then merge those as well
	return finalPkgs, rels, givenErr
}

func merge(p, other *pkg.Package) {
	p.Locations.Add(other.Locations.ToSlice()...)
	p.Licenses.Add(other.Licenses.ToSlice()...)

	p.CPEs = cpe.Merge(p.CPEs, other.CPEs)

	if p.PURL == "" {
		p.PURL = other.PURL
	}
}
