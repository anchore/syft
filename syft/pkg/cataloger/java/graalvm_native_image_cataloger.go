package java

import (
	"bytes"
	"compress/gzip"
	"context"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"unsafe"

	"github.com/anchore/syft/internal"
	intFile "github.com/anchore/syft/internal/file"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/mimetype"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/format/cyclonedxjson"
	"github.com/anchore/syft/syft/internal/elfutil"
	"github.com/anchore/syft/syft/internal/unionreader"
	"github.com/anchore/syft/syft/pkg"
)

type nativeImage interface {
	fetchPkgs() ([]pkg.Package, []artifact.Relationship, error)
}

type nativeImageElf struct {
	file *elf.File
}

type nativeImageMachO struct {
	file *macho.File
}

type exportTypesPE struct {
	functionPointer uint32
	namePointer     uint32
	headerAttribute uint32
}

type exportPrefixPE struct {
	characteristics uint32
	timeDateStamp   uint32
	majorVersion    uint16
	minorVersion    uint16
	name            uint32
	base            uint32
}

type exportContentPE struct {
	// Directory Entry Contents for finding SBOM symbols
	numberOfFunctions  uint32
	numberOfNames      uint32
	addressOfFunctions uint32
	addressOfNames     uint32
	// Locations of SBOM symbols in the .data section
	addressOfSbom       uint32
	addressOfSbomLength uint32
	addressOfSvmVersion uint32
}

// nativeImagePE carries the raw export directory, which debug/pe does not expose.
type nativeImagePE struct {
	file          *pe.File
	exportSymbols pe.DataDirectory
	exports       []byte
	t             exportTypesPE
	header        exportPrefixPE
}

type nativeImageCataloger struct{}

const nativeImageCatalogerName = "graalvm-native-image-cataloger"
const nativeImageSbomSymbol = "sbom"
const nativeImageSbomLengthSymbol = "sbom_length"
const nativeImageSbomVersionSymbol = "__svm_version_info"
const nativeImageMissingSymbolsError = "one or more symbols are missing from the native image executable"
const nativeImageInvalidIndexError = "parsing the executable file generated an invalid index"
const nativeImageMissingExportedDataDirectoryError = "exported data directory is missing"

// nativeImageMaxDecompressedSbomSize bounds the decompressed SBOM rather than the compressed bytes,
// since gzip turns a few kilobytes into gigabytes. Real SBOMs run to single-digit MB even at 20k
// components, and decoding costs several times that again in graph allocation.
const nativeImageMaxDecompressedSbomSize = 16 * intFile.MB

// nativeImageMaxExportDirectorySize bounds the export directory, which is symbol metadata and runs to a
// few KB. Bounding by the bytes remaining is not enough on its own: a mostly empty multi-gigabyte file
// is cheap to ship in a layer and would still authorize reading all of it.
const nativeImageMaxExportDirectorySize = 16 * intFile.MB

// NewNativeImageCataloger returns a new Native Image cataloger object.
func NewNativeImageCataloger() pkg.Cataloger {
	return &nativeImageCataloger{}
}

// Name returns a string that uniquely describes a native image cataloger
func (c *nativeImageCataloger) Name() string {
	return nativeImageCatalogerName
}

// decompressSbom returns the packages given within a native image executable's SBOM.
//
// Offsets and the stored length all come from the binary, so the bounds below subtract from the buffer
// length rather than adding to a file-controlled value, which wraps and then panics on the slice.
func decompressSbom(dataBuf []byte, sbomStart, lengthStart uint64) ([]pkg.Package, []artifact.Relationship, error) {
	bufLen := uint64(len(dataBuf))
	if lengthStart > bufLen || bufLen-lengthStart < 8 {
		return nil, nil, errors.New("the 'sbom_length' symbol overflows the binary")
	}

	storedLength := binary.LittleEndian.Uint64(dataBuf[lengthStart : lengthStart+8])

	log.WithFields("len", storedLength).Trace("found java native-image SBOM")
	if sbomStart > bufLen || storedLength > bufLen-sbomStart {
		return nil, nil, errors.New("the sbom symbol overflows the binary")
	}

	sbomCompressed := dataBuf[sbomStart : sbomStart+storedLength]
	gzreader, err := gzip.NewReader(bytes.NewBuffer(sbomCompressed))
	if err != nil {
		return nil, nil, fmt.Errorf("could not decompress the java native-image SBOM: %w", err)
	}
	defer gzreader.Close()

	// the compressed bytes are bounded by the file, the decompressed stream is not. one byte past the
	// ceiling, so a stream sitting exactly on it is still legal
	raw, err := io.ReadAll(io.LimitReader(gzreader, nativeImageMaxDecompressedSbomSize+1))
	if err != nil {
		return nil, nil, fmt.Errorf("could not decompress the java native-image SBOM: %w", err)
	}
	if len(raw) > nativeImageMaxDecompressedSbomSize {
		return nil, nil, fmt.Errorf("the java native-image SBOM decompresses past %d bytes", nativeImageMaxDecompressedSbomSize)
	}

	sbom, _, _, err := cyclonedxjson.NewFormatDecoder().Decode(bytes.NewReader(raw))
	if err != nil {
		return nil, nil, fmt.Errorf("could not unmarshal the java native-image SBOM: %w", err)
	}
	var pkgs []pkg.Package
	for p := range sbom.Artifacts.Packages.Enumerate() {
		pkgs = append(pkgs, p)
	}
	return pkgs, sbom.Relationships, nil
}

// symbolOffset converts an SBOM symbol address into an offset within the section that should hold it.
// The subtraction is unsigned, so an address below the section base underflows into a huge offset.
func symbolOffset(addr, sectionBase uint64) (uint64, error) {
	if addr < sectionBase {
		return 0, errors.New("an SBOM symbol precedes the section that should contain it")
	}
	return addr - sectionBase, nil
}

// fileError logs an error message when an executable cannot be read.
func fileError(filename string, err error) (nativeImage, error) {
	// We could not read the file as a binary for the desired platform, but it may still be a native-image executable.
	return nil, fmt.Errorf("unable to read executable (file=%q): %w", filename, err)
}

// newElf reads a Native Image from an ELF executable.
func newElf(filename string, r io.ReaderAt) (nativeImage, error) {
	// First attempt to read an ELF file.
	bi, err := elfutil.NewFile(r)

	if err != nil {
		var fmtErr *elf.FormatError
		// note: a size rejection from elfutil is not an *elf.FormatError, so it takes the branch below
		if errors.As(err, &fmtErr) {
			// this is not an elf file
			log.WithFields("filename", filename, "error", err).Trace("not an ELF binary")
			return nil, nil
		}
		return fileError(filename, err)
	}
	if bi == nil {
		return nil, nil
	}
	return nativeImageElf{
		file: bi,
	}, nil
}

// newMachO reads a Native Image from a Mach O executable.
func newMachO(filename string, r io.ReaderAt) (nativeImage, error) {
	// First attempt to read an ELF file.
	bi, err := macho.NewFile(r)

	if err != nil {
		var fmtErr *macho.FormatError
		if errors.As(err, &fmtErr) {
			// this is not a MachO file
			log.WithFields("filename", filename, "error", err).Trace("not a MachO binary")
			return nil, nil
		}
		// a real read failure, not a format mismatch; returning nil here would drop the file silently
		return fileError(filename, err)
	}
	if bi == nil {
		return nil, nil
	}
	return nativeImageMachO{
		file: bi,
	}, nil
}

// readExportDirectory weighs the size the file declares against both an absolute cap and the bytes
// really present before allocating.
//
// note: dir.VirtualAddress is an RVA used directly as a file offset, with no section-table translation.
// Long-standing behavior this preserves rather than fixes; see rvaToFileOffset in dotnet/pe.
func readExportDirectory(r io.ReaderAt, dir pe.DataDirectory) ([]byte, error) {
	if dir.Size > nativeImageMaxExportDirectorySize {
		return nil, fmt.Errorf("export directory declares %d bytes, over the %d byte limit", dir.Size, nativeImageMaxExportDirectorySize)
	}

	// the size has to come from the reader, not from what the file claims
	end, ok := intFile.ReaderSize(r)
	if !ok {
		return nil, errors.New("unable to measure the binary")
	}
	if remaining := end - int64(dir.VirtualAddress); remaining < int64(dir.Size) {
		return nil, fmt.Errorf("export directory declares %d bytes at RVA %d but only %d remain",
			dir.Size, dir.VirtualAddress, max(remaining, 0))
	}

	// the count decides, not the error: a ReadAt may report a full read as io.EOF, or a short one with no
	// error at all. io.ReadFull covers both but spins forever on a reader that keeps answering (0, nil)
	exports := make([]byte, dir.Size)
	if n, err := r.ReadAt(exports, int64(dir.VirtualAddress)); n < len(exports) {
		return nil, fmt.Errorf("could not read the exported symbols data directory: read %d of %d bytes (%v)", n, len(exports), err)
	}
	return exports, nil
}

// newPE reads a Native Image from a Portable Executable file.
func newPE(filename string, r io.ReaderAt) (nativeImage, error) {
	// First attempt to read an PE file.
	bi, err := pe.NewFile(r)

	// The reader does not refer to a PE file.
	if err != nil {
		// note: there isn't a good way to distinguish between a format error and other kinds of errors
		log.WithFields("filename", filename, "error", err).Trace("not a PE binary")
		return nil, nil
	}
	if bi == nil {
		return nil, nil
	}

	var exportSymbolsDataDirectory pe.DataDirectory
	switch h := bi.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		exportSymbolsDataDirectory = h.DataDirectory[0]
	case *pe.OptionalHeader64:
		exportSymbolsDataDirectory = h.DataDirectory[0]
	default:
		return nil, fmt.Errorf("unable to get 'exportSymbolsDataDirectory' from binary: %s", filename)
	}
	// If we have no exported symbols it is not a Native Image
	if exportSymbolsDataDirectory.Size == 0 {
		return fileError(filename, errors.New(nativeImageMissingExportedDataDirectoryError))
	}
	exports, err := readExportDirectory(r, exportSymbolsDataDirectory)
	if err != nil {
		return fileError(filename, err)
	}
	return nativeImagePE{
		file:          bi,
		exportSymbols: exportSymbolsDataDirectory,
		exports:       exports,
		t: exportTypesPE{
			functionPointer: 0,
			namePointer:     0,
			headerAttribute: 0,
		},
		header: exportPrefixPE{
			characteristics: 0,
			timeDateStamp:   0,
			majorVersion:    0,
			minorVersion:    0,
			name:            0,
			base:            0,
		},
	}, nil
}

// fetchPkgs obtains the packages given in the binary.
func (ni nativeImageElf) fetchPkgs() (pkgs []pkg.Package, relationships []artifact.Relationship, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			// this can happen in cases where a malformed binary is passed in can be initially parsed, but not
			// used without error later down the line.
			retErr = fmt.Errorf("recovered from panic: %v", r)
		}
	}()

	bi := ni.file
	var sbom elf.Symbol
	var sbomLength elf.Symbol
	var svmVersion elf.Symbol

	si, err := ni.getSymbols()
	if err != nil {
		return nil, nil, err
	}
	if len(si) == 0 {
		return nil, nil, errors.New(nativeImageMissingSymbolsError)
	}
	for _, s := range si {
		switch s.Name {
		case nativeImageSbomSymbol:
			sbom = s
		case nativeImageSbomLengthSymbol:
			sbomLength = s
		case nativeImageSbomVersionSymbol:
			svmVersion = s
		}
	}
	if sbom.Value == 0 || sbomLength.Value == 0 || svmVersion.Value == 0 {
		return nil, nil, errors.New(nativeImageMissingSymbolsError)
	}
	dataSection := bi.Section(".data")
	if dataSection == nil {
		return nil, nil, errors.New("no .data section found in binary")
	}
	data, err := dataSection.Data()
	if err != nil {
		return nil, nil, fmt.Errorf("cannot read the .data section: %w", err)
	}
	sbomLocation, err := symbolOffset(sbom.Value, dataSection.Addr)
	if err != nil {
		return nil, nil, err
	}
	lengthLocation, err := symbolOffset(sbomLength.Value, dataSection.Addr)
	if err != nil {
		return nil, nil, err
	}

	return decompressSbom(data, sbomLocation, lengthLocation)
}

// getSymbols obtains the union of the symbols in the .symtab and .dynsym sections of the ELF file
func (ni nativeImageElf) getSymbols() ([]elf.Symbol, error) {
	var symbols []elf.Symbol
	symsErr := error(nil)
	dynErr := error(nil)

	if syms, err := ni.file.Symbols(); err == nil {
		symbols = append(symbols, syms...)
	} else {
		symsErr = err
	}

	if dynSyms, err := ni.file.DynamicSymbols(); err == nil {
		symbols = append(symbols, dynSyms...)
	} else {
		dynErr = err
	}

	if symsErr != nil && dynErr != nil {
		return nil, fmt.Errorf("could not retrieve symbols from binary: SHT_SYMTAB error: %v, SHT_DYNSYM error: %v", symsErr, dynErr)
	}

	return symbols, nil
}

// fetchPkgs obtains the packages from a Native Image given as a Mach O file.
func (ni nativeImageMachO) fetchPkgs() (pkgs []pkg.Package, relationships []artifact.Relationship, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			// this can happen in cases where a malformed binary is passed in can be initially parsed, but not
			// used without error later down the line.
			retErr = fmt.Errorf("recovered from panic: %v", r)
		}
	}()

	var sbom macho.Symbol
	var sbomLength macho.Symbol
	var svmVersion macho.Symbol

	bi := ni.file
	if bi.Symtab == nil {
		return nil, nil, errors.New(nativeImageMissingSymbolsError)
	}
	for _, s := range bi.Symtab.Syms {
		switch s.Name {
		case "_" + nativeImageSbomSymbol:
			sbom = s
		case "_" + nativeImageSbomLengthSymbol:
			sbomLength = s
		case "_" + nativeImageSbomVersionSymbol:
			svmVersion = s
		}
	}
	if sbom.Value == 0 || sbomLength.Value == 0 || svmVersion.Value == 0 {
		return nil, nil, errors.New(nativeImageMissingSymbolsError)
	}

	dataSegment := bi.Segment("__DATA")
	if dataSegment == nil {
		return nil, nil, nil
	}
	dataBuf, err := dataSegment.Data()
	if err != nil {
		log.Tracef("cannot obtain buffer from data segment")
		return nil, nil, nil
	}
	sbomLocation, err := symbolOffset(sbom.Value, dataSegment.Addr)
	if err != nil {
		return nil, nil, err
	}
	lengthLocation, err := symbolOffset(sbomLength.Value, dataSegment.Addr)
	if err != nil {
		return nil, nil, err
	}

	return decompressSbom(dataBuf, sbomLocation, lengthLocation)
}

// fetchExportAttribute obtains an attribute from the exported symbols directory entry.
func (ni nativeImagePE) fetchExportAttribute(i int) (uint32, error) {
	n := len(ni.exports)
	sz := int(unsafe.Sizeof(ni.t.headerAttribute))
	// i is only ever 0-3, so this cannot overflow; > not >= because an attribute ending flush with the
	// directory is still entirely present
	j := int(unsafe.Sizeof(ni.header)) + i*sz
	if j+sz > n {
		log.Tracef("invalid index to export directory entry attribute: %v", j)
		return uint32(0), errors.New(nativeImageInvalidIndexError)
	}
	return binary.LittleEndian.Uint32(ni.exports[j : j+sz]), nil
}

// fetchExportFunctionPointer obtains a function pointer from the exported symbols directory entry.
func (ni nativeImagePE) fetchExportFunctionPointer(functionsBase uint32, i uint32) (uint32, error) {
	// functionsBase is a file-controlled RVA: in uint32 the sum wraps under the bound, then panics
	n := uint64(len(ni.exports))
	sz := uint64(unsafe.Sizeof(ni.t.functionPointer))
	j := uint64(functionsBase) + uint64(i)*sz
	if j > n || n-j < sz {
		log.Tracef("invalid index to exported function: %v", j)
		return uint32(0), errors.New(nativeImageInvalidIndexError)
	}
	return binary.LittleEndian.Uint32(ni.exports[j : j+sz]), nil
}

// fetchExportContent obtains the content of the export directory entry relevant to the SBOM.
func (ni nativeImagePE) fetchExportContent() (*exportContentPE, error) {
	content := new(exportContentPE)
	var err error
	content.numberOfFunctions, err = ni.fetchExportAttribute(0)
	if err != nil {
		return nil, fmt.Errorf("could not find the number of exported 'number of functions' attribute: %w", err)
	}
	content.numberOfNames, err = ni.fetchExportAttribute(1)
	if err != nil {
		return nil, fmt.Errorf("could not find the number of exported 'number of names' attribute: %w", err)
	}
	content.addressOfFunctions, err = ni.fetchExportAttribute(2)
	if err != nil {
		return nil, fmt.Errorf("could not find the exported 'address of functions' attribute: %w", err)
	}
	content.addressOfNames, err = ni.fetchExportAttribute(3)
	if err != nil {
		return nil, fmt.Errorf("could not find the exported 'address of names' attribute: %w", err)
	}
	return content, nil
}

// fetchSbomSymbols enumerates the symbols exported by a binary to detect Native Image's SBOM symbols.
func (ni nativeImagePE) fetchSbomSymbols(content *exportContentPE) {
	// Appending NULL bytes to symbol names simplifies finding them in the export data directory
	sbomBytes := []byte(nativeImageSbomSymbol + "\x00")
	sbomLengthBytes := []byte(nativeImageSbomLengthSymbol + "\x00")
	svmVersionInfoBytes := []byte(nativeImageSbomVersionSymbol + "\x00")
	n := uint64(len(ni.exports))
	sz := uint64(unsafe.Sizeof(ni.t.namePointer))

	// an RVA below the directory would underflow into a huge offset that wraps back into range below
	if content.addressOfNames < ni.exportSymbols.VirtualAddress {
		log.Tracef("exported name array precedes the export directory: %v", content.addressOfNames)
		return
	}
	addressBase := uint64(content.addressOfNames - ni.exportSymbols.VirtualAddress)

	// Find SBOM, SBOM Length, and SVM Version Symbol
	for i := uint32(0); i < content.numberOfNames; i++ {
		k := addressBase + uint64(i)*sz
		if k > n || n-k < sz {
			log.Tracef("invalid index to exported function: %v", k)
			// If we are at the end of exports, stop looking
			return
		}
		symbolAddress := binary.LittleEndian.Uint32(ni.exports[k : k+sz])
		if symbolAddress < ni.exportSymbols.VirtualAddress {
			log.Tracef("exported symbol precedes the export directory: %v", symbolAddress)
			return
		}
		symbolBase := uint64(symbolAddress - ni.exportSymbols.VirtualAddress)
		if symbolBase >= n {
			log.Tracef("invalid index to exported symbol: %v", symbolBase)
			return
		}
		switch {
		case bytes.HasPrefix(ni.exports[symbolBase:], sbomBytes):
			content.addressOfSbom = i
		case bytes.HasPrefix(ni.exports[symbolBase:], sbomLengthBytes):
			content.addressOfSbomLength = i
		case bytes.HasPrefix(ni.exports[symbolBase:], svmVersionInfoBytes):
			content.addressOfSvmVersion = i
		}
	}
}

// fetchPkgs obtains the packages from a Native Image given as a PE file.
func (ni nativeImagePE) fetchPkgs() (pkgs []pkg.Package, relationships []artifact.Relationship, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			// this can happen in cases where a malformed binary is passed in can be initially parsed, but not
			// used without error later down the line.
			retErr = fmt.Errorf("recovered from panic: %v", r)
		}
	}()

	content, err := ni.fetchExportContent()
	if err != nil {
		log.Debugf("could not fetch the content of the export directory entry: %v", err)
		return nil, nil, err
	}
	ni.fetchSbomSymbols(content)
	if content.addressOfSbom == uint32(0) || content.addressOfSbomLength == uint32(0) || content.addressOfSvmVersion == uint32(0) {
		return nil, nil, errors.New(nativeImageMissingSymbolsError)
	}
	if content.addressOfFunctions < ni.exportSymbols.VirtualAddress {
		return nil, nil, errors.New("exported function array precedes the export directory")
	}
	functionsBase := content.addressOfFunctions - ni.exportSymbols.VirtualAddress
	sbomOffset := content.addressOfSbom
	sbomAddress, err := ni.fetchExportFunctionPointer(functionsBase, sbomOffset)
	if err != nil {
		return nil, nil, fmt.Errorf("could not fetch SBOM pointer from exported functions: %w", err)
	}
	sbomLengthOffset := content.addressOfSbomLength
	sbomLengthAddress, err := ni.fetchExportFunctionPointer(functionsBase, sbomLengthOffset)
	if err != nil {
		return nil, nil, fmt.Errorf("could not fetch SBOM length pointer from exported functions: %w", err)
	}
	bi := ni.file
	dataSection := bi.Section(".data")
	if dataSection == nil {
		return nil, nil, nil
	}
	dataBuf, err := dataSection.Data()
	if err != nil {
		log.Tracef("cannot obtain buffer from the java native-image .data section")
		return nil, nil, nil
	}
	sbomLocation, err := symbolOffset(uint64(sbomAddress), uint64(dataSection.VirtualAddress))
	if err != nil {
		return nil, nil, err
	}
	lengthLocation, err := symbolOffset(uint64(sbomLengthAddress), uint64(dataSection.VirtualAddress))
	if err != nil {
		return nil, nil, err
	}

	return decompressSbom(dataBuf, sbomLocation, lengthLocation)
}

// fetchPkgs provides the packages available in a UnionReader.
func fetchPkgs(reader unionreader.UnionReader, location file.Location) ([]pkg.Package, []artifact.Relationship) {
	var pkgs []pkg.Package
	var relationships []artifact.Relationship
	imageFormats := []func(string, io.ReaderAt) (nativeImage, error){newElf, newMachO, newPE}

	// NOTE: multiple readers are returned to cover universal binaries, which are files
	// with more than one binary
	readers, err := unionreader.GetReaders(reader)
	if err != nil {
		log.Debugf("failed to open the java native-image binary: %v", err)
		return nil, nil
	}
	filename := location.RealPath
	for _, r := range readers {
		for _, makeNativeImage := range imageFormats {
			ni, err := makeNativeImage(filename, r)
			if err != nil {
				// both "not this format" and a real rejection of a file that is one, which drops every
				// package the binary carries and is only visible at trace level
				log.WithFields("file", filename, "error", err).Trace("unable to read possible java native-image")
				continue
			}
			if ni == nil {
				continue
			}
			newPkgs, newRelationships, err := ni.fetchPkgs()
			if err != nil {
				log.Tracef("unable to extract SBOM from possible java native-image %s: %v", filename, err)
			} else {
				// Associate extracted packages with the native image location
				for i := range newPkgs {
					newPkgs[i].Locations.Add(location)
				}
				pkgs = append(pkgs, newPkgs...)
				relationships = append(relationships, newRelationships...)
			}
			// nothing parses as two of these today; stopping makes that explicit rather than relying on it.
			// note a format that parses but whose fetchPkgs fails is not retried as another format
			break
		}
	}
	return pkgs, relationships
}

// Catalog attempts to find any native image executables reachable from a resolver.
func (c *nativeImageCataloger) Catalog(_ context.Context, resolver file.Resolver) ([]pkg.Package, []artifact.Relationship, error) {
	var pkgs []pkg.Package
	var relationships []artifact.Relationship
	fileMatches, err := resolver.FilesByMIMEType(mimetype.ExecutableMIMETypeSet.List()...)
	if err != nil {
		return pkgs, nil, fmt.Errorf("failed to find binaries by mime types: %w", err)
	}

	for _, location := range fileMatches {
		newPkgs, newRelationships, err := processLocation(location, resolver)
		if err != nil {
			return nil, nil, err
		}
		pkgs = append(pkgs, newPkgs...)
		relationships = append(relationships, newRelationships...)
	}

	return pkgs, relationships, nil
}

func processLocation(location file.Location, resolver file.Resolver) ([]pkg.Package, []artifact.Relationship, error) {
	readerCloser, err := resolver.FileContentsByLocation(location)
	if err != nil {
		log.Debugf("error opening file: %v", err)
		return nil, nil, nil
	}
	defer internal.CloseAndLogError(readerCloser, location.RealPath)

	reader, err := unionreader.GetUnionReader(readerCloser)
	if err != nil {
		return nil, nil, err
	}
	pkgs, relationships := fetchPkgs(reader, location)
	return pkgs, relationships, nil
}
