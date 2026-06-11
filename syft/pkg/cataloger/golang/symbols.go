package golang

import (
	"debug/elf"
	"debug/gosym"
	"debug/macho"
	"fmt"
	"io"
	"runtime/debug"
	"slices"
	"strings"
)

// binarySymbol represents a single function symbol extracted from a go binary's pclntab.
type binarySymbol struct {
	// packagePath is the import path of the package that owns the symbol (e.g. "github.com/foo/bar/internal/baz")
	packagePath string

	// name is the fully qualified symbol name (e.g. "github.com/foo/bar/internal/baz.(*Type).Method")
	name string
}

// getSymbols extracts all function symbols from the pclntab of a go binary. The pclntab is required by the
// go runtime (for panic tracebacks and GC), so it is present even in binaries built with -ldflags="-s -w".
func getSymbols(r io.ReaderAt) (syms []binarySymbol, err error) {
	defer func() {
		if r := recover(); r != nil {
			// the gosym package can panic on malformed pclntab data
			err = fmt.Errorf("recovered from panic while reading pclntab: %v", r)
		}
	}()

	pclntab, textStart, err := readPclntab(r)
	if err != nil {
		return nil, err
	}

	table, err := gosym.NewTable(nil, gosym.NewLineTable(pclntab, textStart))
	if err != nil {
		return nil, fmt.Errorf("unable to parse pclntab: %w", err)
	}

	for _, fn := range table.Funcs {
		if fn.Sym == nil {
			continue
		}
		syms = append(syms, binarySymbol{
			packagePath: fn.PackageName(),
			name:        fn.Name,
		})
	}

	return syms, nil
}

// readPclntab locates the pclntab and the start address of the text segment within the binary.
func readPclntab(r io.ReaderAt) (pclntab []byte, textStart uint64, err error) {
	ident := make([]byte, 16)
	if n, err := r.ReadAt(ident, 0); n < len(ident) || err != nil {
		return nil, 0, errUnrecognizedFormat
	}

	switch {
	case strings.HasPrefix(string(ident), "\x7FELF"):
		f, err := elf.NewFile(r)
		if err != nil {
			return nil, 0, fmt.Errorf("unable to parse ELF binary: %w", err)
		}
		sect := f.Section(".gopclntab")
		if sect == nil {
			return nil, 0, fmt.Errorf("no .gopclntab section found")
		}
		pclntab, err := sect.Data()
		if err != nil {
			return nil, 0, fmt.Errorf("unable to read .gopclntab section: %w", err)
		}
		text := f.Section(".text")
		if text == nil {
			return nil, 0, fmt.Errorf("no .text section found")
		}
		return pclntab, text.Addr, nil
	case strings.HasPrefix(string(ident), "\xFE\xED\xFA") || strings.HasPrefix(string(ident[1:]), "\xFA\xED\xFE"):
		f, err := macho.NewFile(r)
		if err != nil {
			return nil, 0, fmt.Errorf("unable to parse Mach-O binary: %w", err)
		}
		sect := f.Section("__gopclntab")
		if sect == nil {
			return nil, 0, fmt.Errorf("no __gopclntab section found")
		}
		pclntab, err := sect.Data()
		if err != nil {
			return nil, 0, fmt.Errorf("unable to read __gopclntab section: %w", err)
		}
		text := f.Section("__text")
		if text == nil {
			return nil, 0, fmt.Errorf("no __text section found")
		}
		return pclntab, text.Addr, nil
	}

	// note: PE and XCOFF binaries do not place the pclntab in a dedicated section; locating it requires
	// walking the symbol table for runtime.pclntab markers, which is not yet supported here
	return nil, 0, errUnrecognizedFormat
}

// moduleSymbols attributes each extracted symbol to the module that owns it (by longest module path prefix
// of the symbol's package path) and returns a sorted, deduplicated list of symbol names per module path.
// Symbols from the "main" package are attributed to the main module. Stdlib and runtime symbols are not
// attributed to any module.
func moduleSymbols(symbols []binarySymbol, main *debug.Module, deps []*debug.Module) map[string][]string {
	if len(symbols) == 0 {
		return nil
	}

	var modulePaths []string
	if main != nil && main.Path != "" {
		modulePaths = append(modulePaths, main.Path)
	}
	for _, dep := range deps {
		if dep != nil && dep.Path != "" {
			modulePaths = append(modulePaths, dep.Path)
		}
	}

	results := make(map[string][]string)
	for _, sym := range symbols {
		pkgPath := sym.packagePath
		if pkgPath == "main" && main != nil {
			// the linker renames the main package's import path to "main"
			pkgPath = main.Path
		}

		var best string
		for _, modPath := range modulePaths {
			if len(modPath) > len(best) && (pkgPath == modPath || strings.HasPrefix(pkgPath, modPath+"/")) {
				best = modPath
			}
		}
		if best == "" {
			continue
		}
		results[best] = append(results[best], sym.name)
	}

	for modPath, names := range results {
		slices.Sort(names)
		results[modPath] = slices.Compact(names)
	}

	return results
}
