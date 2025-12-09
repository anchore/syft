package executable

import (
	"debug/macho"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/internal/unionreader"
)

// source http://www.cilinder.be/docs/next/NeXTStep/3.3/nd/DevTools/14_MachO/MachO.htmld/index.html
const (
	machoNStab uint8 = 0xe0 // N_STAB mask for debugging symbols
	machoNPExt uint8 = 0x10 // N_PEXT: private external symbol bit
	machoNType uint8 = 0x0e // N_TYPE mask for symbol type
	machoNExt  uint8 = 0x01 // N_EXT: external symbol bit

	// N_TYPE values (after masking with 0x0e)
	machoNUndf uint8 = 0x00 // undefined symbol
	machoNAbs  uint8 = 0x02 // absolute symbol
	machoNSect uint8 = 0x0e // defined in section
	machoNPbud uint8 = 0x0c // prebound undefined
	machoNIndr uint8 = 0x0a // indirect symbol

	// > #define LC_REQ_DYLD 0x80000000
	// > #define LC_MAIN (0x28|LC_REQ_DYLD) /* replacement for LC_UNIXTHREAD */
	lcMain = 0x28 | 0x80000000
)

func findMachoFeatures(data *file.Executable, reader unionreader.UnionReader, cfg SymbolConfig) error {
	// TODO: support security features

	// a universal binary may have multiple architectures, so we need to check each one
	readers, err := unionreader.GetReaders(reader)
	if err != nil {
		return err
	}

	var libs, symbols []string
	for _, r := range readers {
		f, err := macho.NewFile(r)
		if err != nil {
			return err
		}

		rLibs, err := f.ImportedLibraries()
		if err != nil {
			return err
		}
		libs = append(libs, rLibs...)

		// TODO handle only some having entrypoints/exports? If that is even practical
		// only check for entrypoint if we don't already have one
		if !data.HasEntrypoint {
			data.HasEntrypoint = machoHasEntrypoint(f)
		}
		// only check for exports if we don't already have them
		if !data.HasExports {
			data.HasExports = machoHasExports(f)
		}

		data.Toolchains = machoToolchains(reader, f)
		if shouldCaptureSymbols(data, cfg) {
			symbols = machoNMSymbols(f, cfg, data.Toolchains)
		}
	}

	// de-duplicate libraries andn symbols
	data.ImportedLibraries = internal.NewSet(libs...).ToSlice()
	data.SymbolNames = internal.NewSet(symbols...).ToSlice()

	return nil
}

func machoToolchains(reader unionreader.UnionReader, f *macho.File) []file.Toolchain {
	return includeNoneNil(
		golangToolchainEvidence(reader),
	)
}

func machoNMSymbols(f *macho.File, cfg SymbolConfig, toolchains []file.Toolchain) []string {
	if isGoToolchainPresent(toolchains) {
		return captureMachoGoSymbols(f, cfg)
	}

	// TODO: capture other symbol types (non-go) based on the scope selection (lib, app, etc)
	return nil
}

func captureMachoGoSymbols(f *macho.File, cfg SymbolConfig) []string {
	var symbols []string
	filter := createGoSymbolFilter(cfg.Go)
	for _, sym := range f.Symtab.Syms {
		name, include := filter(sym.Name, machoSymbolType(sym, f.Sections))
		if include {
			symbols = append(symbols, name)
		}
	}
	return symbols
}

func isGoToolchainPresent(toolchains []file.Toolchain) bool {
	for _, tc := range toolchains {
		if tc.Name == "go" {
			return true
		}
	}
	return false
}

func machoSymbolType(s macho.Symbol, sections []*macho.Section) string {
	// stab (debugging) symbols get '-'
	if s.Type&machoNStab != 0 {
		return "-"
	}

	isExternal := s.Type&machoNExt != 0
	symType := s.Type & machoNType

	var typeChar byte
	switch symType {
	case machoNUndf, machoNPbud:
		typeChar = 'U'
	case machoNAbs:
		typeChar = 'A'
	case machoNSect:
		typeChar = machoSectionTypeChar(s.Sect, sections)
	case machoNIndr:
		typeChar = 'I'
	default:
		typeChar = '?'
	}

	// lowercase for local symbols, uppercase for external
	if !isExternal && typeChar != '-' && typeChar != '?' {
		typeChar = typeChar + 32 // convert to lowercase
	}

	return string(typeChar)
}

// machoSectionTypeChar returns the nm-style character for a section-defined symbol.
// Section numbers are 1-based; 0 means NO_SECT.
func machoSectionTypeChar(sect uint8, sections []*macho.Section) byte {
	if sect == 0 || int(sect) > len(sections) {
		return 'S'
	}

	section := sections[sect-1]
	seg := section.Seg

	// match nm behavior based on segment and section names
	switch seg {
	case "__TEXT":
		return 'T'
	case "__DATA", "__DATA_CONST":
		switch section.Name {
		case "__bss", "__common":
			return 'B'
		default:
			return 'D'
		}
	default:
		return 'S'
	}
}

func machoHasEntrypoint(f *macho.File) bool {
	// derived from struct entry_point_command found from which explicitly calls out LC_MAIN:
	// https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h
	// we need to look for both LC_MAIN and LC_UNIXTHREAD commands to determine if the file is an executable
	//
	// this is akin to:
	//    otool -l ./path/to/bin | grep -A4 LC_MAIN
	//    otool -l ./path/to/bin | grep -A4 LC_UNIXTHREAD
	for _, l := range f.Loads {
		data := l.Raw()
		cmd := f.ByteOrder.Uint32(data)

		if macho.LoadCmd(cmd) == macho.LoadCmdUnixThread || macho.LoadCmd(cmd) == lcMain {
			return true
		}
	}
	return false
}

func machoHasExports(f *macho.File) bool {
	if f == nil || f.Symtab == nil {
		return false
	}
	for _, sym := range f.Symtab.Syms {
		// look for symbols that are:
		//  - not private and are external
		//  - do not have an N_TYPE value of N_UNDF (undefined symbol)
		//
		// here's the bit layout for the n_type field:
		// 0000 0000
		// ─┬─│ ─┬─│
		//  │ │  │ └─ N_EXT (external symbol)
		//  │ │  └─ N_TYPE (N_UNDF, N_ABS, N_SECT, N_PBUD, N_INDR)
		//  │ └─ N_PEXT (private external symbol)
		//  └─ N_STAB (debugging symbol)
		//
		isExternal := sym.Type&machoNExt == machoNExt
		isPrivate := sym.Type&machoNPExt == machoNPExt
		nTypeIsUndefined := sym.Type&0x0e == 0

		if isExternal && !isPrivate {
			if sym.Name == "_main" || sym.Name == "__mh_execute_header" {
				// ...however there are some symbols that are not exported but are still important
				// for debugging or as an entrypoint, so we need to explicitly check for them
				continue
			}
			if nTypeIsUndefined {
				continue
			}
			// we have a symbol that is not private and is external
			// and is not undefined, so it is an export
			return true
		}
	}
	return false
}
