package executable

import (
	"debug/macho"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/internal/unionreader"
)

// source http://www.cilinder.be/docs/next/NeXTStep/3.3/nd/DevTools/14_MachO/MachO.htmld/index.html
const (
	machoNPExt uint8 = 0x10 /* N_PEXT: private external symbol bit */
	machoNExt  uint8 = 0x01 /* N_EXT: external symbol bit, set for external symbols */
	// > #define LC_REQ_DYLD 0x80000000
	// > #define LC_MAIN (0x28|LC_REQ_DYLD) /* replacement for LC_UNIXTHREAD */
	lcMain = 0x28 | 0x80000000
)

func findMachoFeatures(data *file.Executable, reader unionreader.UnionReader) error {
	// TODO: support security features

	// TODO: support multi-architecture binaries
	f, err := macho.NewFile(reader)
	if err != nil {
		return err
	}

	libs, err := f.ImportedLibraries()
	if err != nil {
		return err
	}

	data.ImportedLibraries = libs
	data.HasEntrypoint = machoHasEntrypoint(f)
	data.HasExports = machoHasExports(f)

	return nil
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
