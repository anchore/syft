package dotnet

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"unicode/utf16"

	"github.com/scylladb/go-set/strset"
	"github.com/scylladb/go-set/u32set"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/internal/unionreader"
)

const peMaxAllowedDirectoryEntries = 0x1000

var imageDirectoryEntryIndexes = []int{
	pe.IMAGE_DIRECTORY_ENTRY_RESOURCE,       // where version resources are stored
	pe.IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR, // where info about the CLR is stored
}

// logicalPE does not directly represent a binary shape to be parsed, instead it represents the
// information of interest extracted from a PE file.
type logicalPE struct {
	// Location is where the PE file was found
	Location file.Location

	// TargetPath is the path is the deps.json target entry. This is not present in the PE file
	// but instead is used in downstream processing to track associations between the PE file and the deps.json file.
	TargetPath string

	// CLR is the information about the CLR (common language runtime) version found in the PE file which helps
	// understand if this executable is even a .NET application.
	CLR *clrEvidence

	// VersionResources is a map of version resource keys to their values found in the VERSIONINFO resource directory.
	VersionResources map[string]string
}

// clrEvidence is basic info about the CLR (common language runtime) version from the COM descriptor.
// This is not a complete representation of the CLR version, but rather a subset of the information that is
// useful to us.
type clrEvidence struct {
	// HasClrResourceNames is true if there are CLR resource names found in the PE file (e.g. "CLRDEBUGINFO").
	HasClrResourceNames bool

	// MajorVersion is the minimum supported major version of the CLR.
	MajorVersion uint16

	// MinorVersion is the minimum supported minor version of the CLR.
	MinorVersion uint16
}

// hasEvidenceOfCLR returns true if the PE file has evidence of a CLR (common language runtime) version.
func (c *clrEvidence) hasEvidenceOfCLR() bool {
	return c != nil && (c.MajorVersion != 0 && c.MinorVersion != 0 || c.HasClrResourceNames)
}

type peDosHeader struct {
	Magic                 [2]byte // "MZ"
	Unused                [58]byte
	AddressOfNewEXEHeader uint32 // offset to PE header
}

// peImageCore20 represents the .NET Core 2.0 header structure.
// Source: https://github.com/dotnet/msbuild/blob/9fa9d800dabce3bfcf8365f651f3a713e01f8a85/src/Tasks/NativeMethods.cs#L761-L775
type peImageCore20 struct {
	Cb                  uint32
	MajorRuntimeVersion uint16
	MinorRuntimeVersion uint16
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

type extractedSection struct {
	RVA     uint32
	BaseRVA uint32
	Size    uint32
	Reader  *bytes.Reader
}

func (s extractedSection) exists() bool {
	return s.RVA != 0 && s.Size != 0
}

func directoryName(i int) string {
	switch i {
	case pe.IMAGE_DIRECTORY_ENTRY_RESOURCE:
		return "Resource"
	case pe.IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR:
		return "COM Descriptor"
	}
	return fmt.Sprintf("Unknown (%d)", i)
}

func getLogicalDotnetPE(f file.LocationReadCloser) (*logicalPE, error) {
	r, err := unionreader.GetUnionReader(f)
	if err != nil {
		return nil, err
	}

	sections, _, err := parsePEFile(r)
	if err != nil {
		return nil, fmt.Errorf("unable to parse PE sections: %w", err)
	}

	dirs := u32set.New()                        // keep track of the RVAs we have already parsed (prevent infinite recursion edge cases)
	versionResources := make(map[string]string) // map of version resource keys to their values
	resourceNames := strset.New()               // set of resource names found in the PE file
	err = parseResourceDirectory(sections[pe.IMAGE_DIRECTORY_ENTRY_RESOURCE], dirs, versionResources, resourceNames)
	if err != nil {
		return nil, err
	}

	c, err := parseCLR(sections[pe.IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR], resourceNames)
	if err != nil {
		return nil, fmt.Errorf("unable to parse PE CLR directory: %w", err)
	}

	return &logicalPE{
		Location:         f.Location,
		CLR:              c,
		VersionResources: versionResources,
	}, nil
}

// parsePEFile creates readers for targeted sections of the binary used by downstream processing.
func parsePEFile(file unionreader.UnionReader) (map[int]*extractedSection, []pe.SectionHeader32, error) {
	fileHeader, magic, err := parsePEHeader(file)
	if err != nil {
		return nil, nil, fmt.Errorf("error parsing PE header: %w", err)
	}

	soi, headers, err := parseSectionHeaders(file, magic, fileHeader.NumberOfSections)
	if err != nil {
		return nil, nil, fmt.Errorf("error parsing section headers: %w", err)
	}

	for i, sec := range soi {
		if !sec.exists() {
			continue
		}
		data, err := readDataFromRVA(file, sec.RVA, sec.Size, headers)
		if err != nil {
			return nil, nil, fmt.Errorf("error reading %q section data: %w", directoryName(i), err)
		}
		sec.Reader = data
	}

	return soi, headers, nil
}

// parsePEHeader reads the beginning of a PE formatted file, returning the file header and "magic" indicator
// for downstream logic to determine 32/64 bit parsing.
func parsePEHeader(file unionreader.UnionReader) (*pe.FileHeader, uint16, error) {
	var dosHeader peDosHeader
	if err := binary.Read(file, binary.LittleEndian, &dosHeader); err != nil {
		return nil, 0, fmt.Errorf("error reading DOS header: %w", err)
	}
	if string(dosHeader.Magic[:]) != "MZ" {
		return nil, 0, fmt.Errorf("invalid DOS header magic")
	}

	peOffset := int64(dosHeader.AddressOfNewEXEHeader)
	if _, err := file.Seek(peOffset, io.SeekStart); err != nil {
		return nil, 0, fmt.Errorf("error seeking to PE header: %w", err)
	}

	var signature [4]byte
	if err := binary.Read(file, binary.LittleEndian, &signature); err != nil {
		return nil, 0, fmt.Errorf("error reading PE signature: %w", err)
	}
	if !bytes.Equal(signature[:], []byte("PE\x00\x00")) {
		return nil, 0, fmt.Errorf("invalid PE signature")
	}

	var fileHeader pe.FileHeader
	if err := binary.Read(file, binary.LittleEndian, &fileHeader); err != nil {
		return nil, 0, fmt.Errorf("error reading file header: %w", err)
	}

	var magic uint16
	if err := binary.Read(file, binary.LittleEndian, &magic); err != nil {
		return nil, 0, fmt.Errorf("error reading optional header magic: %w", err)
	}

	// seek back to before reading magic (since that value is in the header)
	if _, err := file.Seek(-2, io.SeekCurrent); err != nil {
		return nil, 0, fmt.Errorf("error seeking back to before reading magic: %w", err)
	}

	return &fileHeader, magic, nil
}

// parseSectionHeaders reads the section headers from the PE file and extracts the virtual addresses + section size
// information for the sections of interest. Additionally, all section headers are returned to aid in downstream processing.
func parseSectionHeaders(file unionreader.UnionReader, magic uint16, numberOfSections uint16) (map[int]*extractedSection, []pe.SectionHeader32, error) {
	soi := make(map[int]*extractedSection)
	switch magic {
	case 0x10B: // PE32
		var optHeader pe.OptionalHeader32
		if err := binary.Read(file, binary.LittleEndian, &optHeader); err != nil {
			return nil, nil, fmt.Errorf("error reading optional header (PE32): %w", err)
		}

		for _, i := range imageDirectoryEntryIndexes {
			sectionHeader := optHeader.DataDirectory[i]
			if sectionHeader.Size == 0 {
				continue
			}
			soi[i] = &extractedSection{
				RVA:  sectionHeader.VirtualAddress,
				Size: sectionHeader.Size,
			}
		}
	case 0x20B: // PE32+ (64 bit)
		var optHeader pe.OptionalHeader64
		if err := binary.Read(file, binary.LittleEndian, &optHeader); err != nil {
			return nil, nil, fmt.Errorf("error reading optional header (PE32+): %w", err)
		}

		for _, i := range imageDirectoryEntryIndexes {
			sectionHeader := optHeader.DataDirectory[i]
			if sectionHeader.Size == 0 {
				continue
			}
			soi[i] = &extractedSection{
				RVA:  sectionHeader.VirtualAddress,
				Size: sectionHeader.Size,
			}
		}
	default:
		return nil, nil, fmt.Errorf("unknown optional header magic: 0x%x", magic)
	}

	// read section headers
	headers := make([]pe.SectionHeader32, numberOfSections)
	for i := 0; i < int(numberOfSections); i++ {
		if err := binary.Read(file, binary.LittleEndian, &headers[i]); err != nil {
			return nil, nil, fmt.Errorf("error reading section header: %w", err)
		}
	}

	return soi, headers, nil
}

// parseCLR extracts the CLR (common language runtime) version information from the COM descriptor and makes
// present/not-present determination based on the presence of CLR resource names.
func parseCLR(sec *extractedSection, resourceNames *strset.Set) (*clrEvidence, error) {
	hasCLRDebugResourceNames := resourceNames.HasAny("CLRDEBUGINFO")
	if sec == nil || sec.Reader == nil {
		return &clrEvidence{
			HasClrResourceNames: hasCLRDebugResourceNames,
		}, nil
	}

	reader := sec.Reader
	var c peImageCore20
	if err := binary.Read(reader, binary.LittleEndian, &c); err != nil {
		return nil, fmt.Errorf("error reading CLR header: %w", err)
	}

	return &clrEvidence{
		HasClrResourceNames: hasCLRDebugResourceNames,
		MajorVersion:        c.MajorRuntimeVersion,
		MinorVersion:        c.MinorRuntimeVersion,
	}, nil
}

// rvaToFileOffset is a helper function to convert RVA to file offset using section headers
func rvaToFileOffset(rva uint32, sections []pe.SectionHeader32) (uint32, error) {
	for _, section := range sections {
		if rva >= section.VirtualAddress && rva < section.VirtualAddress+section.VirtualSize {
			return section.PointerToRawData + (rva - section.VirtualAddress), nil
		}
	}
	return 0, fmt.Errorf("RVA 0x%x not found in any section", rva)
}

// readDataFromRVA will read data from a specific RVA in the PE file
func readDataFromRVA(file io.ReadSeeker, rva, size uint32, sections []pe.SectionHeader32) (*bytes.Reader, error) {
	if size == 0 {
		return nil, fmt.Errorf("zero size specified")
	}

	offset, err := rvaToFileOffset(rva, sections)
	if err != nil {
		return nil, err
	}

	if _, err := file.Seek(int64(offset), io.SeekStart); err != nil {
		return nil, fmt.Errorf("error seeking to data: %w", err)
	}

	data := make([]byte, size)
	if _, err := io.ReadFull(file, data); err != nil {
		return nil, fmt.Errorf("error reading data: %w", err)
	}

	return bytes.NewReader(data), nil
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
func parseResourceDirectory(sec *extractedSection, dirs *u32set.Set, fields map[string]string, names *strset.Set) error {
	if sec == nil || sec.Size <= 0 {
		return nil
	}

	if sec.Reader == nil {
		return errors.New("resource section not found")
	}

	baseRVA := sec.BaseRVA
	if baseRVA == 0 {
		baseRVA = sec.RVA
	}

	offset := int64(sec.RVA - baseRVA)
	if _, err := sec.Reader.Seek(offset, io.SeekStart); err != nil {
		return fmt.Errorf("error seeking to directory offset: %w", err)
	}

	var directoryHeader peImageResourceDirectory
	if err := readIntoStruct(sec.Reader, &directoryHeader); err != nil {
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
		if _, err := sec.Reader.Seek(entryOffset, io.SeekStart); err != nil {
			log.Tracef("error seeking to PE entry offset: %v", err)
			continue
		}

		if err := readIntoStruct(sec.Reader, &entry); err != nil {
			continue
		}

		if err := processResourceEntry(entry, baseRVA, sec, dirs, fields, names); err != nil {
			log.Tracef("error processing resource entry: %v", err)
			continue
		}
	}

	return nil
}

func processResourceEntry(entry peImageResourceDirectoryEntry, baseRVA uint32, sec *extractedSection, dirs *u32set.Set, fields map[string]string, names *strset.Set) error {
	// if the high bit is set, this is a directory entry, otherwise it is a data entry
	isDirectory := entry.OffsetToData&0x80000000 != 0

	// note: the offset is relative to the beginning of the resource section, not an RVA
	entryOffsetToData := entry.OffsetToData & 0x7FFFFFFF

	nameIsString := entry.Name&0x80000000 != 0
	nameOffset := entry.Name & 0x7FFFFFFF

	// read the string name of the resource directory
	if nameIsString {
		currentPos, err := sec.Reader.Seek(0, io.SeekCurrent)
		if err != nil {
			return fmt.Errorf("error getting current reader position: %w", err)
		}

		if _, err := sec.Reader.Seek(int64(nameOffset), io.SeekStart); err != nil {
			return fmt.Errorf("error restoring reader position: %w", err)
		}

		name, err := readUTF16WithLength(sec.Reader)
		if err == nil {
			names.Add(name)
		}

		if _, err := sec.Reader.Seek(currentPos, io.SeekStart); err != nil {
			return fmt.Errorf("error restoring reader position: %w", err)
		}
	}

	if isDirectory {
		subRVA := baseRVA + entryOffsetToData
		if dirs.Has(subRVA) {
			// some malware uses recursive PE references to evade analysis
			return fmt.Errorf("recursive PE reference detected; skipping directory at baseRVA=0x%x subRVA=0x%x", baseRVA, subRVA)
		}

		dirs.Add(subRVA)
		err := parseResourceDirectory(
			&extractedSection{
				RVA:     subRVA,
				BaseRVA: baseRVA,
				Size:    sec.Size - (sec.RVA - baseRVA),
				Reader:  sec.Reader,
			},
			dirs, fields, names)
		if err != nil {
			return err
		}
		return nil
	}
	return parseResourceDataEntry(sec.Reader, baseRVA, baseRVA+entryOffsetToData, sec.Size, fields)
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

			if err := alignAndSeek(reader, &offset, &stOffset); err != nil {
				return fmt.Errorf("error aligning to next PE string table key: %w", err)
			}
		}
	}

	if fields["FileVersion"] == "" {
		// we can derive the file version from the fixed file info if it is not already specified as a string entry... neat!
		fields["FileVersion"] = fmt.Sprintf("%d.%d.%d.%d",
			fixedFileInfo.FileVersionMS>>16, fixedFileInfo.FileVersionMS&0xFFFF,
			fixedFileInfo.FileVersionLS>>16, fixedFileInfo.FileVersionLS&0xFFFF)
	}

	return nil
}

// readIntoStructAndSzKey reads a struct from the reader and updates the offsets if provided, returning the szKey value.
// This is only useful in the context of the resource directory parsing in narrow cases (this is invalid to use outside of that context).
func readIntoStructAndSzKey[T any](reader *bytes.Reader, data *T, offsets ...*int) (string, error) {
	if err := readIntoStruct(reader, data, offsets...); err != nil {
		return "", err
	}
	return readUTF16(reader, offsets...), nil
}

// readIntoStruct reads a struct from the reader and updates the offsets if provided.
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

// alignAndSeek aligns the reader to the next DWORD boundary and seeks to the new offset (updating any provided trackOffsets).
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

// alignToDWORD aligns the offset to the next DWORD boundary (4 byte boundary)
func alignToDWORD(offset int) int {
	return (offset + 3) & ^3
}

// readUTF16 is a helper function to read a null-terminated UTF16 string
func readUTF16(reader *bytes.Reader, offsets ...*int) string {
	startPos, err := reader.Seek(0, io.SeekCurrent)
	if err != nil {
		return ""
	}

	var result []rune
	for {
		var char uint16
		err := binary.Read(reader, binary.LittleEndian, &char)
		if err != nil || char == 0 {
			break
		}
		result = append(result, rune(char))
	}

	// calculate how many bytes we've actually read (including null terminator)
	endPos, _ := reader.Seek(0, io.SeekCurrent)
	bytesRead := int(endPos - startPos)

	for i := range offsets {
		*offsets[i] += bytesRead
	}

	return string(result)
}

// readUTF16WithLength reads a length-prefixed UTF-16 string from reader.
// The first 2 bytes represent the number of UTF-16 code units.
func readUTF16WithLength(reader *bytes.Reader) (string, error) {
	var length uint16
	if err := binary.Read(reader, binary.LittleEndian, &length); err != nil {
		return "", err
	}
	if length == 0 {
		return "", nil
	}

	// read length UTF-16 code units.
	codes := make([]uint16, length)
	if err := binary.Read(reader, binary.LittleEndian, &codes); err != nil {
		return "", err
	}
	return string(utf16.Decode(codes)), nil
}
