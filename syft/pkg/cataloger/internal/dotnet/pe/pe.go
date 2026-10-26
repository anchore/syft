package pe

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"unicode/utf16"

	"github.com/scylladb/go-set/u32set"

	intFile "github.com/anchore/syft/internal/file"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/internal/unionreader"
)

const (
	peMaxAllowedDirectoryEntries = 0x1000

	// peResourceBudgetFactor bounds the total bytes a walk will read out of a resource section, as a
	// multiple of that section's own size. The per-directory cap above only bounds the fan-out of one
	// node, and nothing in the format stops entries from aliasing: thousands of them may name the same
	// blob, so a tree whose every individual offset is in bounds can still drive work quadratic in the
	// section size. A well-formed section's entries partition it rather than overlapping, so real binaries
	// come in right around 1x and the slack here only absorbs padding and shared string tables.
	peResourceBudgetFactor = 4

	// peMaxResourceDirectoryDepth bounds how deep the resource tree walk will recurse.
	//
	// The format uses exactly three levels (type, then name, then language), so anything past a handful
	// is malformed. The bound matters because Go grows a goroutine stack until it hits the process limit
	// and then dies with a fatal error rather than a recoverable panic: a chain of directories at
	// distinct RVAs, each naming the next, would take the whole scan down with it. Distinct RVAs are why
	// the dirs set below cannot stand in for this, and a byte budget cannot either, since the budget
	// scales with the section while the stack does not.
	peMaxResourceDirectoryDepth = 32

	// maxDirectorySectionSize bounds the bytes any single PE data directory may declare.
	//
	// Only the resource and COM descriptor directories are read, and both are metadata: real ones run
	// from a few KB to a few MB even for applications that embed sizable assets. Clamping to the bytes
	// remaining in the file (which the caller does as well) is not on its own enough, because a mostly
	// empty file compresses to almost nothing in a layer, so an attacker can hand us a small artifact
	// that still authorizes a multi-gigabyte allocation. The trade-off is that a binary declaring a
	// larger directory loses its version resources rather than being cataloged; that is the correct
	// direction to fail, since the alternative is OOM-killing the whole scan. This mirrors
	// maxDeclaredSectionSize in syft/internal/elfutil.
	maxDirectorySectionSize = 128 * intFile.MB

	// clrDebugInfoResourceName is the only resource name any downstream logic asks about.
	clrDebugInfoResourceName = "CLRDEBUGINFO"
)

// resourceWalk is the state shared across a single resource directory traversal.
//
// reader and baseRVA are fixed for the whole walk: every RVA a nested entry names resolves against the
// same origin and the same bytes, so reader.Size() is the one authoritative bound on every offset derived
// from them. Holding them here rather than on a per-node value is what keeps that invariant structural.
type resourceWalk struct {
	reader  *bytes.Reader
	baseRVA uint32

	// dirs tracks the RVAs already parsed (prevents infinite recursion edge cases)
	dirs *u32set.Set

	// fields collects version resource keys and their values
	fields map[string]string

	// hasCLRDebugInfo records whether a CLRDEBUGINFO resource name was seen
	hasCLRDebugInfo bool

	// budget is the number of bytes left that we are willing to read out of the section. Charging every
	// read against one counter bounds the blobs, the names, and the total tree walk together.
	//
	// note: this bounds total work, not recursion depth. The budget scales with the section size, so a
	// large section still affords a very deep chain of directory headers; depth is bounded separately by
	// peMaxResourceDirectoryDepth.
	budget int64

	// depth is how many directory levels the current recursion is into the tree.
	depth int
}

// newResourceWalk starts a walk over one resource section's bytes, fixing the origin every RVA is
// measured against. Taking both up front is what keeps reader.Size() the one authoritative bound on
// every offset the walk derives, since there is no window in which a walk exists without them.
func newResourceWalk(reader *bytes.Reader, baseRVA uint32) *resourceWalk {
	return &resourceWalk{
		reader:  reader,
		baseRVA: baseRVA,
		dirs:    u32set.New(),
		fields:  make(map[string]string),
		budget:  reader.Size() * peResourceBudgetFactor,
	}
}

// offsetOf turns an RVA into an offset into the walk's bytes, rejecting any RVA the section does not
// actually hold. RVAs are user-controlled uint32s, so this is what keeps the subtraction from underflowing
// and keeps every offset derived from one inside the buffer.
func (w *resourceWalk) offsetOf(rva uint32) (int64, error) {
	if rva < w.baseRVA {
		return 0, fmt.Errorf("RVA=0x%x precedes its section base 0x%x", rva, w.baseRVA)
	}

	offset := int64(rva - w.baseRVA)
	if offset >= w.reader.Size() {
		return 0, fmt.Errorf("RVA=0x%x lies past its section end (baseRVA=0x%x size=0x%x)", rva, w.baseRVA, w.reader.Size())
	}

	return offset, nil
}

// offsetWithin validates a section-relative offset the file supplied directly (rather than as an RVA)
// before it is used to seek. bytes.Reader happily seeks past its end and only fails on the later read, so
// checking here is what turns a bogus offset into a legible error instead of a downstream EOF.
func (w *resourceWalk) offsetWithin(offset uint32) (int64, error) {
	if int64(offset) >= w.reader.Size() {
		return 0, fmt.Errorf("offset 0x%x lies past its section end 0x%x", offset, w.reader.Size())
	}
	return int64(offset), nil
}

// errResourceBudget stops the walk rather than one entry: once the budget is gone every remaining sibling
// would hit it too, so callers that normally log-and-continue have to propagate this one.
var errResourceBudget = errors.New("resource walk read more of its section than a well-formed one could justify")

// errResourceDepth stops the walk for the same reason as errResourceBudget: the format nests three levels,
// so a tree past the cap is crafted rather than unusual, and its siblings are the same structure.
var errResourceDepth = errors.New("resource directory nested deeper than a well-formed one could justify")

// stopsWalk reports whether an error is about the walk as a whole rather than the one entry that raised it,
// which is what tells the log-and-continue loops to propagate instead.
func stopsWalk(err error) bool {
	return errors.Is(err, errResourceBudget) || errors.Is(err, errResourceDepth)
}

// spend charges n bytes about to be read out of the section against the walk's budget.
func (w *resourceWalk) spend(n int64) error {
	w.budget -= n
	if w.budget < 0 {
		return errResourceBudget
	}
	return nil
}

var imageDirectoryEntryIndexes = []int{
	pe.IMAGE_DIRECTORY_ENTRY_RESOURCE,       // where version resources are stored
	pe.IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR, // where info about the CLR is stored
}

// File does not directly represent a binary shape to be parsed, instead it represents the
// information of interest extracted from a PE file.
type File struct {
	// Location is where the PE file was found
	Location file.Location

	// CLR is the information about the CLR (common language runtime) version found in the PE file which helps
	// understand if this executable is even a .NET application.
	CLR *CLREvidence

	// EmbeddedDepsJSON is the contents of an embedded deps.json file found within the PE file, if any.
	// This is typical when using the PublishSingleFile build option.
	EmbeddedDepsJSON string

	// VersionResources is a map of version resource keys to their values found in the VERSIONINFO resource directory.
	VersionResources map[string]string

	// ParseErr records the structures that could not be parsed out of an otherwise usable PE file.
	//
	// A malformed resource directory, an unreadable data directory, or a bundle marker pointing nowhere
	// each cost us one piece of evidence, not the whole file, so Read reports them here and still returns
	// what it did find. Callers that track partial results should join this into their unknowns rather
	// than discarding the package.
	ParseErr error
}

// CLREvidence is basic info about the CLR (common language runtime) version from the COM descriptor.
// This is not a complete representation of the CLR version, but rather a subset of the information that is
// useful to us.
type CLREvidence struct {
	// HasClrResourceNames is true if there are CLR resource names found in the PE file (e.g. "CLRDEBUGINFO").
	HasClrResourceNames bool

	// MajorVersion is the minimum supported major version of the CLR.
	MajorVersion uint16

	// MinorVersion is the minimum supported minor version of the CLR.
	MinorVersion uint16
}

// HasEvidenceOfCLR returns true if the PE file has evidence of a CLR (common language runtime) version.
func (c *CLREvidence) HasEvidenceOfCLR() bool {
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

	// Err records why this section's bytes could not be read, leaving Reader nil. Recording it rather
	// than failing the file keeps one malformed directory from dropping the package entirely; the
	// downstream parsers all treat a nil Reader as "nothing to say about this".
	Err error
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

func Read(f file.LocationReadCloser) (*File, error) {
	r, err := unionreader.GetUnionReader(f)
	if err != nil {
		return nil, err
	}

	sections, sectionHeaders, err := parsePEFile(r)
	if err != nil {
		return nil, fmt.Errorf("unable to parse PE sections: %w", err)
	}

	// every structure below is optional evidence: losing one costs us a field, not the package. They are
	// collected rather than returned so a single malformed directory cannot drop the file from the SBOM,
	// and so callers can still see what went wrong instead of it only reaching a trace log.
	var parseErrs []error
	for _, i := range imageDirectoryEntryIndexes {
		if sec := sections[i]; sec != nil && sec.Err != nil {
			parseErrs = append(parseErrs, sec.Err)
		}
	}

	walk, err := parseResourceDirectory(sections[pe.IMAGE_DIRECTORY_ENTRY_RESOURCE])
	if err != nil {
		parseErrs = append(parseErrs, fmt.Errorf("unable to fully parse PE resource directory: %w", err))
	}

	c, err := parseCLR(sections[pe.IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR], walk.hasCLRDebugInfo)
	if err != nil {
		parseErrs = append(parseErrs, fmt.Errorf("unable to parse PE CLR directory: %w", err))
		c = &CLREvidence{HasClrResourceNames: walk.hasCLRDebugInfo}
	}

	embeddedDepsJSON, err := extractDepsJSONFromBundle(r, sectionHeaders)
	if err != nil {
		parseErrs = append(parseErrs, fmt.Errorf("unable to extract embedded deps.json: %w", err))
	}

	parseErr := errors.Join(parseErrs...)
	if parseErr != nil {
		log.Tracef("partially parsed PE file %s: %v", f.RealPath, parseErr)
	}

	return &File{
		Location:         f.Location,
		CLR:              c,
		EmbeddedDepsJSON: embeddedDepsJSON,
		VersionResources: walk.fields,
		ParseErr:         parseErr,
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
			// one unreadable directory says nothing about the others or about the rest of the file, so
			// record it and carry on rather than dropping the package over it
			sec.Err = fmt.Errorf("error reading %q section data: %w", directoryName(i), err)
			continue
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

	// read section headers. numberOfSections is a uint16 straight out of the file header, so the slice
	// grows to the headers that are actually there rather than reserving for all 65535 up front.
	var headers []pe.SectionHeader32
	for range numberOfSections {
		var header pe.SectionHeader32
		if err := binary.Read(file, binary.LittleEndian, &header); err != nil {
			return nil, nil, fmt.Errorf("error reading section header: %w", err)
		}
		headers = append(headers, header)
	}

	return soi, headers, nil
}

// parseCLR extracts the CLR (common language runtime) version information from the COM descriptor and makes
// present/not-present determination based on the presence of CLR resource names.
func parseCLR(sec *extractedSection, hasCLRDebugResourceNames bool) (*CLREvidence, error) {
	if sec == nil || sec.Reader == nil {
		return &CLREvidence{
			HasClrResourceNames: hasCLRDebugResourceNames,
		}, nil
	}

	reader := sec.Reader
	var c peImageCore20
	if err := binary.Read(reader, binary.LittleEndian, &c); err != nil {
		return nil, fmt.Errorf("error reading CLR header: %w", err)
	}

	return &CLREvidence{
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
func readDataFromRVA(file io.ReaderAt, rva, size uint32, sections []pe.SectionHeader32) (*bytes.Reader, error) {
	if size == 0 {
		return nil, fmt.Errorf("zero size specified")
	}

	offset, err := rvaToFileOffset(rva, sections)
	if err != nil {
		return nil, err
	}

	// size is a user-controlled uint32, so sizing the buffer from it alone lets a small file reserve up to
	// 4GB. Two bounds apply before it sizes anything: the bytes that actually remain in the file, and the
	// absolute cap, which is what keeps a sparse multi-gigabyte file (cheap to ship inside a compressed
	// layer) from authorizing a multi-gigabyte allocation. Both checks precede the allocation, and the
	// allocation is exact in one shot, which an append-growing read cannot do: it holds both arrays at its
	// final growth, so a legitimate 150MB bundle would cost well over twice its own size to scan.
	if size > maxDirectorySectionSize {
		return nil, fmt.Errorf("error reading data: %d bytes declared at offset %d exceeds the %d byte limit", size, offset, maxDirectorySectionSize)
	}

	// the length has to come from something the reader can back up rather than from what it claims, since
	// the whole point here is weighing a declared size against the bytes that are really present
	end, ok := intFile.ReaderSize(file)
	if !ok {
		return nil, errors.New("error measuring file")
	}

	if remaining := end - int64(offset); remaining < int64(size) {
		return nil, fmt.Errorf("error reading data: %d bytes declared at offset %d but only %d remain", size, offset, max(remaining, 0))
	}

	data := make([]byte, size)
	// ReadAt may report a full read as io.EOF when it lands on the end of the file, so the count is what
	// says whether the whole section was there
	if n, err := file.ReadAt(data, int64(offset)); err != nil && n < len(data) {
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
// parseResourceDirectory walks a resource section and returns the walk that collected from it. The walk is
// always non-nil, even on error: a tree that stops partway still tells us about the fields it did yield.
func parseResourceDirectory(sec *extractedSection) (*resourceWalk, error) {
	if sec == nil || sec.Size <= 0 {
		return newResourceWalk(bytes.NewReader(nil), 0), nil
	}

	if sec.Reader == nil {
		return newResourceWalk(bytes.NewReader(nil), 0), errors.New("resource section not found")
	}

	baseRVA := sec.BaseRVA
	if baseRVA == 0 {
		baseRVA = sec.RVA
	}

	w := newResourceWalk(sec.Reader, baseRVA)

	return w, parseResourceDirectoryAt(sec.RVA, w)
}

func parseResourceDirectoryAt(rva uint32, w *resourceWalk) error {
	// a resource tree is three levels deep by spec, so anything past the cap is malformed. This has to be
	// its own bound: the dirs set only catches a directory naming an RVA already seen, and a chain of
	// distinct RVAs each naming the next would otherwise recurse until the goroutine stack gives out,
	// which is a fatal error no caller can recover from.
	w.depth++
	defer func() { w.depth-- }()

	if w.depth > peMaxResourceDirectoryDepth {
		return fmt.Errorf("%w: %d levels", errResourceDepth, peMaxResourceDirectoryDepth)
	}

	offset, err := w.offsetOf(rva)
	if err != nil {
		return fmt.Errorf("resource directory: %w", err)
	}

	if _, err := w.reader.Seek(offset, io.SeekStart); err != nil {
		return fmt.Errorf("error seeking to directory offset: %w", err)
	}

	var directoryHeader peImageResourceDirectory
	if err := w.spend(int64(binary.Size(directoryHeader))); err != nil {
		return err
	}

	if err := readIntoStruct(w.reader, &directoryHeader); err != nil {
		return fmt.Errorf("error reading directory header: %w", err)
	}

	// widen before adding: the two counts are uint16s that a crafted file can make sum past 0xFFFF,
	// which would wrap and hide entries a real loader would still walk
	numEntries := int(directoryHeader.NumberOfNamedEntries) + int(directoryHeader.NumberOfIDEntries)
	switch {
	case numEntries > peMaxAllowedDirectoryEntries:
		return fmt.Errorf("too many entries in resource directory: %d", numEntries)
	case numEntries == 0:
		return fmt.Errorf("no entries in resource directory")
	}

	for i := range numEntries {
		var entry peImageResourceDirectoryEntry

		if err := w.spend(int64(binary.Size(entry))); err != nil {
			return err
		}

		entryOffset := offset + int64(binary.Size(directoryHeader)) + int64(i*binary.Size(entry))
		if _, err := w.reader.Seek(entryOffset, io.SeekStart); err != nil {
			log.Tracef("error seeking to PE entry offset: %v", err)
			continue
		}

		if err := readIntoStruct(w.reader, &entry); err != nil {
			continue
		}

		if err := processResourceEntry(entry, w); err != nil {
			// a budget or depth limit hit partway down the tree is not a property of this one entry, so
			// stop the walk rather than letting every sibling re-discover it
			if stopsWalk(err) {
				return err
			}
			log.Tracef("error processing resource entry: %v", err)
			continue
		}
	}

	return nil
}

func processResourceEntry(entry peImageResourceDirectoryEntry, w *resourceWalk) error {
	// if the high bit is set, this is a directory entry, otherwise it is a data entry
	isDirectory := entry.OffsetToData&0x80000000 != 0

	// note: the offset is relative to the beginning of the resource section, not an RVA
	entryOffsetToData := entry.OffsetToData & 0x7FFFFFFF

	nameIsString := entry.Name&0x80000000 != 0
	nameOffset := entry.Name & 0x7FFFFFFF

	// read the string name of the resource directory
	if nameIsString {
		currentPos, err := w.reader.Seek(0, io.SeekCurrent)
		if err != nil {
			return fmt.Errorf("error getting current reader position: %w", err)
		}

		nameAt, err := w.offsetWithin(nameOffset)
		if err != nil {
			return fmt.Errorf("resource name: %w", err)
		}

		if _, err := w.reader.Seek(nameAt, io.SeekStart); err != nil {
			return fmt.Errorf("error seeking to resource name: %w", err)
		}

		// only one name matters downstream, so compare in place rather than retaining every name a
		// crafted file cares to declare
		name, err := w.readUTF16WithLength()
		switch {
		case stopsWalk(err):
			return err
		case err == nil && name == clrDebugInfoResourceName:
			w.hasCLRDebugInfo = true
		}

		if _, err := w.reader.Seek(currentPos, io.SeekStart); err != nil {
			return fmt.Errorf("error restoring reader position: %w", err)
		}
	}

	targetRVA := w.baseRVA + entryOffsetToData

	if isDirectory {
		if w.dirs.Has(targetRVA) {
			// some malware uses recursive PE references to evade analysis
			return fmt.Errorf("recursive PE reference detected; skipping directory at baseRVA=0x%x subRVA=0x%x", w.baseRVA, targetRVA)
		}

		w.dirs.Add(targetRVA)

		return parseResourceDirectoryAt(targetRVA, w)
	}

	return parseResourceDataEntry(targetRVA, w)
}

func parseResourceDataEntry(rva uint32, w *resourceWalk) error {
	offset, err := w.offsetOf(rva)
	if err != nil {
		return fmt.Errorf("resource data entry: %w", err)
	}

	if _, err := w.reader.Seek(offset, io.SeekStart); err != nil {
		return fmt.Errorf("error seeking to data entry offset: %w", err)
	}

	var dataEntry peImageResourceDataEntry
	if err := w.spend(int64(binary.Size(dataEntry))); err != nil {
		return err
	}

	if err := readIntoStruct(w.reader, &dataEntry); err != nil {
		return fmt.Errorf("error reading resource data entry: %w", err)
	}

	// OffsetToData and Size are both user-controlled uint32s, so the region they describe has to be bounded
	// against the bytes the section actually holds before it sizes the allocation below.
	dataOffset, err := w.offsetOf(dataEntry.OffsetToData)
	if err != nil {
		return fmt.Errorf("resource data: %w", err)
	}

	if int64(dataEntry.Size) > w.reader.Size()-dataOffset {
		return fmt.Errorf("resource data (offset=0x%x size=0x%x) extends past its section end 0x%x", dataOffset, dataEntry.Size, w.reader.Size())
	}

	if err := w.spend(int64(dataEntry.Size)); err != nil {
		return err
	}

	data := make([]byte, dataEntry.Size)
	if _, err := w.reader.Seek(dataOffset, io.SeekStart); err != nil {
		return fmt.Errorf("error seeking to resource data: %w", err)
	}

	if _, err := io.ReadFull(w.reader, data); err != nil {
		return fmt.Errorf("error reading resource data: %w", err)
	}

	return parseVersionResourceSection(bytes.NewReader(data), w.fields)
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
			if isTruncated(err) {
				// a well-formed version resource whose last child is VarFileInfo ends right here, so stop
				// and let the FileVersion fallback below still run
				break
			}
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
			if isTruncated(err) {
				break
			}
			return fmt.Errorf("error reading PE string table header: %v", err)
		}

		if err := parseStringTable(reader, int(stHeader.Length), &offset, &stOffset, fields); err != nil {
			return err
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

// parseStringTable reads the key/value pairs of a single string table into fields. length is what the
// string table header claims it holds, and stOffset tracks how much of that has actually been consumed.
func parseStringTable(reader *bytes.Reader, length int, offset, stOffset *int, fields map[string]string) error {
	for *stOffset < length {
		var stringHeader peString
		if err := readIntoStruct(reader, &stringHeader, offset, stOffset); err != nil {
			if isTruncated(err) {
				// the table claims more content than the resource carries; stop rather than re-reading a
				// reader that is not advancing
				break
			}
			return fmt.Errorf("error reading PE string table entry: %w", err)
		}

		key := readUTF16(reader, offset, stOffset)

		if err := alignAndSeek(reader, offset, stOffset); err != nil {
			return fmt.Errorf("error aligning to next PE string table value: %w", err)
		}

		var value string
		if stringHeader.ValueLength > 0 {
			value = readUTF16(reader, offset, stOffset)
		}

		fields[key] = value

		if err := alignAndSeek(reader, offset, stOffset); err != nil {
			return fmt.Errorf("error aligning to next PE string table key: %w", err)
		}
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

// isTruncated reports whether err means the resource simply ran out of bytes. binary.Read gives io.EOF when
// nothing was left and io.ErrUnexpectedEOF when a struct was cut in half; both say the same thing about a
// version resource, and neither should cost us the fields already collected.
func isTruncated(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
}

// readIntoStruct reads a struct from the reader and updates the offsets if provided.
//
// note: EOF must stay an error. Callers advance their loop counters by the offsets updated below, so
// reporting a zeroed struct as a successful read leaves length-driven loops spinning forever.
func readIntoStruct[T any](reader io.Reader, data *T, offsets ...*int) error {
	if err := binary.Read(reader, binary.LittleEndian, data); err != nil {
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

// readUTF16WithLength reads a length-prefixed UTF-16 string from the walk's current position.
// The first 2 bytes represent the number of UTF-16 code units.
func (w *resourceWalk) readUTF16WithLength() (string, error) {
	var length uint16
	if err := binary.Read(w.reader, binary.LittleEndian, &length); err != nil {
		return "", err
	}
	if length == 0 {
		return "", nil
	}

	// length is a user-controlled uint16 and binary.Read allocates a second buffer of its own, so a name
	// the reader cannot satisfy must be rejected before either one is sized from it
	size := int64(length) * 2
	if size > int64(w.reader.Len()) {
		return "", fmt.Errorf("declared name length %d exceeds the %d bytes remaining", length, w.reader.Len())
	}

	if err := w.spend(size); err != nil {
		return "", err
	}

	// read length UTF-16 code units.
	codes := make([]uint16, length)
	if err := binary.Read(w.reader, binary.LittleEndian, &codes); err != nil {
		return "", err
	}
	return string(utf16.Decode(codes)), nil
}
