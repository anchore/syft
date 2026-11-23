package executable

import (
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"io"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/scylladb/go-set/strset"

	intFile "github.com/anchore/syft/internal/file"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/unknown"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/internal/elfutil"
	"github.com/anchore/syft/syft/internal/unionreader"
)

func findELFFeatures(data *file.Executable, reader unionreader.UnionReader) error {
	f, err := elfutil.NewFile(reader)
	if err != nil {
		return err
	}

	libs, err := f.ImportedLibraries()
	if err != nil {
		log.WithFields("error", err).Trace("unable to read imported libraries from elf file")
		err = unknown.Joinf(err, "unable to read imported libraries from elf file: %w", err)
		libs = nil
	}

	if libs == nil {
		libs = []string{}
	}

	data.ImportedLibraries = libs
	data.ELFSecurityFeatures = findELFSecurityFeatures(f)
	data.HasEntrypoint = elfHasEntrypoint(f)
	data.HasExports = elfHasExports(f)
	data.Identifiers = findELFIdentifiers(f)

	return err
}

const (
	// NT_GNU_BUILD_ID is not defined by debug/elf.
	ntGNUBuildID = 3
	// ELF_NOTE_GOBUILDID_TAG from cmd/link, the note type the go linker uses for the go build ID.
	ntGoBuildID = 4

	elfNoteOwnerGNU = "GNU"
	elfNoteOwnerGo  = "Go"

	// bound decoded bytes read from any one identifier note section.
	maxELFNoteBytes = 64 * intFile.KB

	elfNoteHeaderSize = 12
)

type elfNote struct {
	owner string
	typ   uint32
	desc  []byte
}

// elfIdentifierNote describes where one kind of identifier lives and how its descriptor becomes a value.
type elfIdentifierNote struct {
	section string
	owner   string
	typ     uint32
	kind    file.ExecutableIdentifierKind
	// encode returns the value for a descriptor, or "" to skip it.
	encode func([]byte) string
}

var elfIdentifierNotes = []elfIdentifierNote{
	{section: ".note.gnu.build-id", owner: elfNoteOwnerGNU, typ: ntGNUBuildID, kind: file.ELFGNUBuildID, encode: hex.EncodeToString},
	// the go linker always writes this note, while it only writes a GNU build ID when asked (-B) or when linking externally
	{section: ".note.go.buildid", owner: elfNoteOwnerGo, typ: ntGoBuildID, kind: file.GoBuildID, encode: goBuildIDValue},
}

func findELFIdentifiers(f *elf.File) []file.ExecutableIdentifier {
	var ids []file.ExecutableIdentifier
	for _, in := range elfIdentifierNotes {
		ids = append(ids, findELFNoteIdentifiers(f, in)...)
	}
	return ids
}

func findELFNoteIdentifiers(f *elf.File, in elfIdentifierNote) []file.ExecutableIdentifier {
	s := f.Section(in.section)
	// real identifier notes are SHF_ALLOC, which the gABI forbids compressing, so a compressed one is
	// hostile or broken and is never decompressed
	if s == nil || s.Type != elf.SHT_NOTE || s.Flags&elf.SHF_COMPRESSED != 0 {
		return nil
	}
	data, err := io.ReadAll(io.LimitReader(s.Open(), maxELFNoteBytes))
	if err != nil {
		log.WithFields("error", err, "section", in.section).Trace("unable to read ELF identifier note")
		return nil
	}

	var ids []file.ExecutableIdentifier
	seen := strset.New()
	for _, n := range parseELFNotes(data, s.Addralign, f.ByteOrder) {
		if n.owner != in.owner || n.typ != in.typ || len(n.desc) == 0 {
			continue
		}
		value := in.encode(n.desc)
		if value == "" || seen.Has(value) {
			continue
		}
		seen.Add(value)
		ids = append(ids, file.ExecutableIdentifier{Kind: in.kind, Value: value})
	}
	return ids
}

// goBuildIDValue keeps the go build ID as the text the go toolchain prints for it (e.g. "go tool buildid").
func goBuildIDValue(desc []byte) string {
	if !utf8.Valid(desc) {
		return ""
	}
	return string(desc)
}

// parseELFNotes decodes the Elf_Nhdr records in a note region, stopping at the first truncated record.
func parseELFNotes(data []byte, align uint64, order binary.ByteOrder) []elfNote {
	// Some GNU property note regions use 8-byte alignment instead of 4.
	if align != 8 {
		align = 4
	}

	var notes []elfNote
	for len(data) >= elfNoteHeaderSize {
		nameSize := uint64(order.Uint32(data[0:4]))
		descSize := uint64(order.Uint32(data[4:8]))
		typ := order.Uint32(data[8:12])

		nameEnd := elfNoteHeaderSize + nameSize
		descStart := alignUp(nameEnd, align)
		descEnd := descStart + descSize
		if descEnd > uint64(len(data)) {
			break
		}

		notes = append(notes, elfNote{
			owner: strings.TrimRight(string(data[elfNoteHeaderSize:nameEnd]), "\x00"),
			typ:   typ,
			desc:  data[descStart:descEnd],
		})

		next := alignUp(descEnd, align)
		if next >= uint64(len(data)) {
			break
		}
		data = data[next:]
	}
	return notes
}

func alignUp(n, align uint64) uint64 {
	return (n + align - 1) &^ (align - 1)
}

func findELFSecurityFeatures(f *elf.File) *file.ELFSecurityFeatures {
	return &file.ELFSecurityFeatures{
		SymbolTableStripped:           isElfSymbolTableStripped(f),
		StackCanary:                   checkElfStackCanary(f),
		NoExecutable:                  checkElfNXProtection(f),
		RelocationReadOnly:            checkElfRelROProtection(f),
		PositionIndependentExecutable: isELFPIE(f),
		DynamicSharedObject:           isELFDSO(f),
		LlvmSafeStack:                 checkLLVMSafeStack(f),
		LlvmControlFlowIntegrity:      checkLLVMControlFlowIntegrity(f),
		ClangFortifySource:            checkClangFortifySource(f),
	}
}

func isElfSymbolTableStripped(file *elf.File) bool {
	return file.Section(".symtab") == nil
}

func checkElfStackCanary(file *elf.File) *bool {
	return hasAnyDynamicSymbols(file, "__stack_chk_fail", "__stack_chk_guard")
}

func hasAnyDynamicSymbols(file *elf.File, symbolNames ...string) *bool {
	dynSyms, err := file.DynamicSymbols()
	if err != nil {
		log.WithFields("error", err).Trace("unable to read dynamic symbols from elf file")
		return nil
	}

	nameSet := strset.New(symbolNames...)

	for _, sym := range dynSyms {
		if nameSet.Has(sym.Name) {
			return boolRef(true)
		}
	}
	return boolRef(false)
}

func boolRef(b bool) *bool {
	return &b
}

func checkElfNXProtection(file *elf.File) bool {
	// find the program headers until you find the GNU_STACK segment
	for _, prog := range file.Progs {
		if prog.Type == elf.PT_GNU_STACK {
			// check if the GNU_STACK segment is executable
			return prog.Flags&elf.PF_X == 0
		}
	}

	return false
}

func checkElfRelROProtection(f *elf.File) file.RelocationReadOnly {
	// background on relro https://www.redhat.com/en/blog/hardening-elf-binaries-using-relocation-read-only-relro
	hasRelro := false
	hasBindNow := hasBindNowDynTagOrFlag(f)

	for _, prog := range f.Progs {
		if prog.Type == elf.PT_GNU_RELRO {
			hasRelro = true
			break
		}
	}

	switch {
	case hasRelro && hasBindNow:
		return file.RelocationReadOnlyFull
	case hasRelro:
		return file.RelocationReadOnlyPartial
	default:
		return file.RelocationReadOnlyNone
	}
}

func hasBindNowDynTagOrFlag(f *elf.File) bool {
	if hasElfDynTag(f, elf.DT_BIND_NOW) {
		// support older binaries...
		return true
	}

	// "DT_BIND_NOW ... use has been superseded by the DF_BIND_NOW flag"
	// source: https://refspecs.linuxbase.org/elf/gabi4+/ch5.dynamic.html
	return hasElfDynFlag(f, elf.DF_BIND_NOW)
}

func hasElfDynFlag(f *elf.File, flag elf.DynFlag) bool {
	vals, err := f.DynValue(elf.DT_FLAGS)
	if err != nil {
		log.WithFields("error", err).Trace("unable to read DT_FLAGS from elf file")
		return false
	}
	for _, val := range vals {
		if val&uint64(flag) != 0 {
			return true
		}
	}
	return false
}

func hasElfDynFlag1(f *elf.File, flag elf.DynFlag1) bool {
	vals, err := f.DynValue(elf.DT_FLAGS_1)
	if err != nil {
		log.WithFields("error", err).Trace("unable to read DT_FLAGS_1 from elf file")
		return false
	}
	for _, val := range vals {
		if val&uint64(flag) != 0 {
			return true
		}
	}
	return false
}

func hasElfDynTag(f *elf.File, tag elf.DynTag) bool {
	vals, err := f.DynValue(tag)
	if err != nil {
		log.WithFields("error", err).Trace("unable to read dynamic section from elf file")
		return false
	}
	return len(vals) > 0
}

func isELFPIE(f *elf.File) bool {
	// being a shared object is not sufficient to be a PIE, the explicit flag must be set also
	return isELFDSO(f) && hasElfDynFlag1(f, elf.DF_1_PIE)
}

func isELFDSO(f *elf.File) bool {
	return f.Type == elf.ET_DYN
}

func checkLLVMSafeStack(file *elf.File) *bool {
	// looking for the presence of https://github.com/microsoft/compiler-rt/blob/30b3b8cb5c9a0854f2f40f187c6f6773561a35f2/lib/safestack/safestack.cc#L207
	return hasAnyDynamicSymbols(file, "__safestack_init")
}

func checkLLVMControlFlowIntegrity(file *elf.File) *bool {
	// look for any symbols that are functions and end with ".cfi"
	dynSyms, err := file.Symbols()
	if err != nil {
		log.WithFields("error", err).Trace("unable to read symbols from elf file")
		return nil
	}

	for _, sym := range dynSyms {
		if isFunction(sym) && strings.HasSuffix(sym.Name, ".cfi") {
			return boolRef(true)
		}
	}
	return boolRef(false)
}

func isFunction(sym elf.Symbol) bool {
	return elf.ST_TYPE(sym.Info) == elf.STT_FUNC
}

var fortifyPattern = regexp.MustCompile(`__\w+_chk@.+`)

func checkClangFortifySource(file *elf.File) *bool {
	dynSyms, err := file.Symbols()
	if err != nil {
		log.WithFields("error", err).Trace("unable to read symbols from elf file")
		return nil
	}

	for _, sym := range dynSyms {
		if isFunction(sym) && fortifyPattern.MatchString(sym.Name) {
			return boolRef(true)
		}
	}
	return boolRef(false)
}

func elfHasEntrypoint(f *elf.File) bool {
	// this is akin to
	//    readelf -h ./path/to/bin | grep "Entry point address"
	return f.Entry > 0
}

func elfHasExports(f *elf.File) bool {
	// this is akin to:
	//    nm -D --defined-only ./path/to/bin | grep ' T \| W \| B '
	// where:
	//   T - symbol in the text section
	//   W - weak symbol that might be overwritten
	//   B - variable located in the uninitialized data section
	// really anything that is not marked with 'U' (undefined) is considered an export.
	symbols, err := f.DynamicSymbols()
	if err != nil {
		log.WithFields("error", err).Trace("unable to get ELF dynamic symbols")
		return false
	}

	for _, s := range symbols {
		// check if the section is SHN_UNDEF, which is the "U" output type from "nm -D" meaning that the symbol
		// is undefined, meaning it is not an export. Any entry that is not undefined is considered an export.
		if s.Section != elf.SHN_UNDEF {
			return true
		}
	}

	return false
}
