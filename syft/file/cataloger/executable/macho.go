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
	// we need to look for both LC_MAIN and LC_UNIXTHREAD commands to determine if the file is an executable:
	// > #define LC_MAIN (0x28|LC_REQ_DYLD) /* replacement for LC_UNIXTHREAD */
	for _, l := range f.Loads {
		data := l.Raw()
		cmd := f.ByteOrder.Uint32(data)

		if macho.LoadCmd(cmd) == macho.LoadCmdUnixThread || macho.LoadCmd(cmd) == macho.LoadCmdThread {
			return true
		}
	}
	return false
}

func machoHasExports(f *macho.File) bool {
	for _, sym := range f.Symtab.Syms {
		if sym.Type&machoNExt == machoNExt && sym.Type&machoNPExt == 0 {
			return true
		}
	}
	return false
}
