package executable

import (
	"debug/pe"
	"strings"

	"github.com/scylladb/go-set/strset"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/internal/unionreader"
)

// PE symbol storage class constants
const (
	peSymClassExternal = 2 // IMAGE_SYM_CLASS_EXTERNAL - external symbol
	peSymClassStatic   = 3 // IMAGE_SYM_CLASS_STATIC - static symbol
)

// PE section characteristic flags
const (
	peSectionCntCode              = 0x00000020 // IMAGE_SCN_CNT_CODE
	peSectionCntInitializedData   = 0x00000040 // IMAGE_SCN_CNT_INITIALIZED_DATA
	peSectionCntUninitializedData = 0x00000080 // IMAGE_SCN_CNT_UNINITIALIZED_DATA
	peSectionMemExecute           = 0x20000000 // IMAGE_SCN_MEM_EXECUTE
	peSectionMemRead              = 0x40000000 // IMAGE_SCN_MEM_READ
	peSectionMemWrite             = 0x80000000 // IMAGE_SCN_MEM_WRITE
)

func findPEFeatures(data *file.Executable, reader unionreader.UnionReader, cfg SymbolConfig) error {
	// TODO: support security features

	f, err := pe.NewFile(reader)
	if err != nil {
		return err
	}

	libs, err := f.ImportedLibraries()
	if err != nil {
		return err
	}

	data.ImportedLibraries = libs
	data.HasEntrypoint = peHasEntrypoint(f)
	data.HasExports = peHasExports(f)
	data.Toolchains = peToolchains(reader)
	if shouldCaptureSymbols(data, cfg) {
		data.SymbolNames = peNMSymbols(f, cfg, data.Toolchains)
	}

	return nil
}

var (
	windowsExeEntrypoints = strset.New("main", "WinMain", "wWinMain")
	windowsDllEntrypoints = strset.New("DllMain", "_DllMainCRTStartup@12", "CRT_INIT")
)

func peHasEntrypoint(f *pe.File) bool {
	// DLLs can have entrypoints, but they are not "executables" in the traditional sense,
	// but instead point to an initialization function (DLLMain).
	// The PE format does not require an entrypoint, so it is possible to not have one, however,
	// the microsoft C runtime does: https://learn.microsoft.com/en-US/troubleshoot/developer/visualstudio/cpp/libraries/use-c-run-time
	//
	// > When building a DLL which uses any of the C Run-time libraries, in order to ensure that the CRT is properly initialized, either
	// > 1. the initialization function must be named DllMain() and the entry point must be specified with the linker option -entry:_DllMainCRTStartup@12 - or -
	// > 2. the DLL's entry point must explicitly call CRT_INIT() on process attach and process detach
	//
	// This isn't really helpful from a user perspective when it comes to indicating if there is an entrypoint or not
	// since it will always effectively be true for DLLs! All DLLs and Executables (aka "modules") have a single
	// entrypoint, _GetPEImageBase, but we're more interested in the logical idea of an entrypoint.
	// See https://learn.microsoft.com/en-us/windows/win32/psapi/module-information for more details.

	var hasLibEntrypoint, hasExeEntrypoint bool
	for _, s := range f.Symbols {
		if windowsExeEntrypoints.Has(s.Name) {
			hasExeEntrypoint = true
		}
		if windowsDllEntrypoints.Has(s.Name) {
			hasLibEntrypoint = true
		}
	}

	switch v := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		return v.AddressOfEntryPoint > 0 && !hasLibEntrypoint && hasExeEntrypoint
	case *pe.OptionalHeader64:
		return v.AddressOfEntryPoint > 0 && !hasLibEntrypoint && hasExeEntrypoint
	}
	return false
}

func peHasExports(f *pe.File) bool {
	if f.OptionalHeader == nil {
		return false
	}

	switch v := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		return v.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_EXPORT].Size > 0
	case *pe.OptionalHeader64:
		return v.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_EXPORT].Size > 0
	}

	return false
}

func peToolchains(reader unionreader.UnionReader) []file.Toolchain {
	return includeNoneNil(
		golangToolchainEvidence(reader),
	)
}

func peNMSymbols(f *pe.File, cfg SymbolConfig, toolchains []file.Toolchain) []string {
	if isGoToolchainPresent(toolchains) {
		return capturePeGoSymbols(f, cfg)
	}

	// include all symbols for non-Go binaries
	if f.Symbols == nil {
		return nil
	}
	var symbols []string
	for _, sym := range f.Symbols {
		symbols = append(symbols, sym.Name)
	}
	return symbols
}

func capturePeGoSymbols(f *pe.File, cfg SymbolConfig) []string {
	if f.Symbols == nil {
		return nil
	}

	var symbols []string
	filter := createGoSymbolFilter(cfg)
	for _, sym := range f.Symbols {
		name, include := filter(sym.Name, peSymbolType(sym, f.Sections))
		if include {
			symbols = append(symbols, name)
		}
	}
	return symbols
}

// peSymbolType returns the nm-style single character representing the symbol type.
// This mimics the output of `nm` for PE/COFF binaries.
func peSymbolType(sym *pe.Symbol, sections []*pe.Section) string {
	// handle special section numbers first
	switch sym.SectionNumber {
	case 0:
		// IMAGE_SYM_UNDEFINED - undefined symbol
		return "U"
	case -1:
		// IMAGE_SYM_ABSOLUTE - absolute symbol
		if sym.StorageClass == peSymClassExternal {
			return "A"
		}
		return "a"
	case -2:
		// IMAGE_SYM_DEBUG - debugging symbol
		return "-"
	}

	// for defined symbols, determine type based on section characteristics
	typeChar := peSectionTypeChar(sym.SectionNumber, sections)

	// lowercase for static (local) symbols, uppercase for external (global)
	if sym.StorageClass != peSymClassExternal && typeChar != '-' && typeChar != '?' {
		return strings.ToLower(string(typeChar))
	}
	return string(typeChar)
}

// peSectionTypeChar returns the nm-style character based on section characteristics.
// Section numbers are 1-based.
func peSectionTypeChar(sectNum int16, sections []*pe.Section) byte {
	idx := int(sectNum) - 1 // convert to 0-based index
	if idx < 0 || idx >= len(sections) {
		return '?'
	}

	section := sections[idx]
	chars := section.Characteristics

	// determine symbol type based on section characteristics
	switch {
	case chars&peSectionMemExecute != 0 || chars&peSectionCntCode != 0:
		// executable section -> text
		return 'T'

	case chars&peSectionCntUninitializedData != 0:
		// uninitialized data section -> BSS
		return 'B'

	case chars&peSectionMemWrite == 0 && chars&peSectionCntInitializedData != 0:
		// read-only initialized data -> rodata
		return 'R'

	case chars&peSectionCntInitializedData != 0:
		// writable initialized data -> data
		return 'D'

	default:
		return 'D'
	}
}
