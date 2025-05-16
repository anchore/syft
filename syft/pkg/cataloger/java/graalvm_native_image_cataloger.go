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
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/mimetype"
	"github.com/anchore/syft/internal/unknown"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/format/cyclonedxjson"
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

// A nativeImagePE must maintain the underlying reader to fetch information unavailable in the Golang API.
type nativeImagePE struct {
	file          *pe.File
	reader        io.ReaderAt
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

// NewNativeImageCataloger returns a new Native Image cataloger object.
func NewNativeImageCataloger() pkg.Cataloger {
	return &nativeImageCataloger{}
}

// Name returns a string that uniquely describes a native image cataloger
func (c *nativeImageCataloger) Name() string {
	return nativeImageCatalogerName
}

// decompressSbom returns the packages given within a native image executable's SBOM.
func decompressSbom(dataBuf []byte, sbomStart uint64, lengthStart uint64) ([]pkg.Package, []artifact.Relationship, error) {
	lengthEnd := lengthStart + 8
	bufLen := len(dataBuf)
	if lengthEnd > uint64(bufLen) {
		return nil, nil, errors.New("the 'sbom_length' symbol overflows the binary")
	}

	length := dataBuf[lengthStart:lengthEnd]
	p := bytes.NewBuffer(length)
	var storedLength uint64
	err := binary.Read(p, binary.LittleEndian, &storedLength)
	if err != nil {
		return nil, nil, fmt.Errorf("could not read from binary file: %w", err)
	}

	log.WithFields("len", storedLength).Trace("found java native-image SBOM")
	sbomEnd := sbomStart + storedLength
	if sbomEnd > uint64(bufLen) {
		return nil, nil, errors.New("the sbom symbol overflows the binary")
	}

	sbomCompressed := dataBuf[sbomStart:sbomEnd]
	p = bytes.NewBuffer(sbomCompressed)
	gzreader, err := gzip.NewReader(p)
	if err != nil {
		return nil, nil, fmt.Errorf("could not decompress the java native-image SBOM: %w", err)
	}

	sbom, _, _, err := cyclonedxjson.NewFormatDecoder().Decode(gzreader)
	if err != nil {
		return nil, nil, fmt.Errorf("could not unmarshal the java native-image SBOM: %w", err)
	}
	var pkgs []pkg.Package
	for p := range sbom.Artifacts.Packages.Enumerate() {
		pkgs = append(pkgs, p)
	}
	return pkgs, sbom.Relationships, nil
}

// fileError logs an error message when an executable cannot be read.
func fileError(filename string, err error) (nativeImage, error) {
	// We could not read the file as a binary for the desired platform, but it may still be a native-image executable.
	return nil, fmt.Errorf("unable to read executable (file=%q): %w", filename, err)
}

// newElf reads a Native Image from an ELF executable.
func newElf(filename string, r io.ReaderAt) (nativeImage, error) {
	// First attempt to read an ELF file.
	bi, err := elf.NewFile(r)

	if err != nil {
		var fmtErr *elf.FormatError
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
	}
	if bi == nil {
		return nil, nil
	}
	return nativeImageMachO{
		file: bi,
	}, nil
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
	exportSymbolsOffset := uint64(exportSymbolsDataDirectory.VirtualAddress)
	exports := make([]byte, exportSymbolsDataDirectory.Size)
	_, err = r.ReadAt(exports, int64(exportSymbolsOffset))
	if err != nil {
		return fileError(filename, fmt.Errorf("could not read the exported symbols data directory: %w", err))
	}
	return nativeImagePE{
		file:          bi,
		reader:        r,
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
		return nil, nil, fmt.Errorf("no .data section found in binary: %w", err)
	}
	dataSectionBase := dataSection.Addr
	data, err := dataSection.Data()
	if err != nil {
		return nil, nil, fmt.Errorf("cannot read the .data section: %w", err)
	}
	sbomLocation := sbom.Value - dataSectionBase
	lengthLocation := sbomLength.Value - dataSectionBase

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
	sbomLocation := sbom.Value - dataSegment.Addr
	lengthLocation := sbomLength.Value - dataSegment.Addr

	return decompressSbom(dataBuf, sbomLocation, lengthLocation)
}

// fetchExportAttribute obtains an attribute from the exported symbols directory entry.
func (ni nativeImagePE) fetchExportAttribute(i int) (uint32, error) {
	var attribute uint32
	n := len(ni.exports)
	j := int(unsafe.Sizeof(ni.header)) + i*int(unsafe.Sizeof(ni.t.headerAttribute))
	if j+4 >= n {
		log.Tracef("invalid index to export directory entry attribute: %v", j)
		return uint32(0), errors.New(nativeImageInvalidIndexError)
	}
	p := bytes.NewBuffer(ni.exports[j : j+4])
	err := binary.Read(p, binary.LittleEndian, &attribute)
	if err != nil {
		log.Tracef("error fetching export directory entry attribute: %v", err)
		return uint32(0), err
	}
	return attribute, nil
}

// fetchExportFunctionPointer obtains a function pointer from the exported symbols directory entry.
func (ni nativeImagePE) fetchExportFunctionPointer(functionsBase uint32, i uint32) (uint32, error) {
	var pointer uint32

	n := uint32(len(ni.exports))
	sz := uint32(unsafe.Sizeof(ni.t.functionPointer))
	j := functionsBase + i*sz
	if j+sz >= n {
		log.Tracef("invalid index to exported function: %v", j)
		return uint32(0), errors.New(nativeImageInvalidIndexError)
	}
	p := bytes.NewBuffer(ni.exports[j : j+sz])
	err := binary.Read(p, binary.LittleEndian, &pointer)
	if err != nil {
		log.Tracef("error fetching exported function: %v", err)
		return uint32(0), err
	}
	return pointer, nil
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
	n := uint32(len(ni.exports))

	// Find SBOM, SBOM Length, and SVM Version Symbol
	for i := uint32(0); i < content.numberOfNames; i++ {
		j := i * uint32(unsafe.Sizeof(ni.t.namePointer))
		addressBase := content.addressOfNames - ni.exportSymbols.VirtualAddress
		k := addressBase + j
		sz := uint32(unsafe.Sizeof(ni.t.namePointer))
		if k+sz >= n {
			log.Tracef("invalid index to exported function: %v", k)
			// If we are at the end of exports, stop looking
			return
		}
		var symbolAddress uint32
		p := bytes.NewBuffer(ni.exports[k : k+sz])
		err := binary.Read(p, binary.LittleEndian, &symbolAddress)
		if err != nil {
			log.Tracef("error fetching address of symbol %v", err)
			return
		}
		symbolBase := symbolAddress - ni.exportSymbols.VirtualAddress
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
	sbomLocation := sbomAddress - dataSection.VirtualAddress
	lengthLocation := sbomLengthAddress - dataSection.VirtualAddress

	return decompressSbom(dataBuf, uint64(sbomLocation), uint64(lengthLocation))
}

// fetchPkgs provides the packages available in a UnionReader.
func fetchPkgs(reader unionreader.UnionReader, filename string) ([]pkg.Package, []artifact.Relationship, error) {
	var pkgs []pkg.Package
	var relationships []artifact.Relationship
	imageFormats := []func(string, io.ReaderAt) (nativeImage, error){newElf, newMachO, newPE}

	// NOTE: multiple readers are returned to cover universal binaries, which are files
	// with more than one binary
	readers, err := unionreader.GetReaders(reader)
	if err != nil {
		log.Debugf("failed to open the java native-image binary: %v", err)
		return nil, nil, nil
	}
	var unknowns error
	for _, r := range readers {
		for _, makeNativeImage := range imageFormats {
			ni, err := makeNativeImage(filename, r)
			if err != nil {
				continue
			}
			if ni == nil {
				continue
			}
			newPkgs, newRelationships, err := ni.fetchPkgs()
			if err != nil {
				log.Tracef("unable to extract SBOM from possible java native-image %s: %v", filename, err)
				unknowns = unknown.Join(unknowns, fmt.Errorf("unable to extract SBOM from possible java native-image %s: %w", filename, err))
				continue
			}
			pkgs = append(pkgs, newPkgs...)
			relationships = append(relationships, newRelationships...)
		}
	}
	return pkgs, relationships, unknowns
}

// Catalog attempts to find any native image executables reachable from a resolver.
func (c *nativeImageCataloger) Catalog(_ context.Context, resolver file.Resolver) ([]pkg.Package, []artifact.Relationship, error) {
	var pkgs []pkg.Package
	var relationships []artifact.Relationship
	fileMatches, err := resolver.FilesByMIMEType(mimetype.ExecutableMIMETypeSet.List()...)
	if err != nil {
		return pkgs, nil, fmt.Errorf("failed to find binaries by mime types: %w", err)
	}
	var errs error
	for _, location := range fileMatches {
		newPkgs, newRelationships, err := processLocation(location, resolver)
		if err != nil {
			errs = unknown.Append(errs, location, err)
			continue
		}
		pkgs = append(pkgs, newPkgs...)
		relationships = append(relationships, newRelationships...)
	}

	return pkgs, relationships, errs
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
	pkgs, relationships, err := fetchPkgs(reader, location.RealPath)
	return pkgs, relationships, err
}
