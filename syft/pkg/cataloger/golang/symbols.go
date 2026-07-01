package golang

import (
	"bytes"
	"debug/elf"
	"debug/gosym"
	"debug/macho"
	"encoding/binary"
	"fmt"
	"io"
	"runtime/debug"
	"slices"
	"strings"
)

// mainPackage is the import path the linker assigns to the binary's main package.
const mainPackage = "main"

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

	seen := make(map[string]struct{})
	for _, fn := range table.Funcs {
		if fn.Sym == nil {
			continue
		}
		seen[fn.Name] = struct{}{}
		syms = append(syms, binarySymbol{
			packagePath: fn.PackageName(),
			name:        fn.Name,
		})
	}

	// debug/gosym only exposes top-level functions; functions that the compiler inlined into their
	// callers are absent from table.Funcs even though their names are recorded in the pclntab funcname
	// table (used to reconstruct inlined frames in tracebacks). Recover those names so that a
	// vulnerable-but-inlined function (e.g. a small stdlib wrapper) is still reported as present.
	for _, name := range funcNameTable(pclntab) {
		if _, ok := seen[name]; ok {
			continue
		}
		pkgPath := packagePathFromSymbolName(name)
		if pkgPath == "" {
			continue
		}
		seen[name] = struct{}{}
		syms = append(syms, binarySymbol{packagePath: pkgPath, name: name})
	}

	return syms, nil
}

// packagePathFromSymbolName derives the owning package import path from a fully qualified symbol name.
// The package path is everything up to the first "." that follows the final "/" — e.g.
// "path/filepath.IsLocal" -> "path/filepath" and "golang.org/x/net/html.(*Tokenizer).Next" ->
// "golang.org/x/net/html". Returns "" when the name has no package-qualifying dot.
func packagePathFromSymbolName(name string) string {
	slash := strings.LastIndex(name, "/")
	dot := strings.IndexByte(name[slash+1:], '.')
	if dot < 0 {
		return ""
	}
	return name[:slash+1+dot]
}

// funcNameTable returns every function name recorded in the pclntab's funcname table, including the
// names of inlined functions that debug/gosym does not expose. It parses the pclntab header for the
// Go 1.16+ layouts; on any unrecognized layout or out-of-bounds offset it returns nil (fail-soft), so
// callers fall back to the debug/gosym function set. See the runtime's pcHeader / moduledata layout.
func funcNameTable(pclntab []byte) []string {
	if len(pclntab) < 8 {
		return nil
	}

	magic := binary.LittleEndian.Uint32(pclntab[0:4])
	// the field before funcnameOffset is textStart, which exists in the 1.18+ headers but not 1.16/1.17
	var hasTextStart bool
	switch magic {
	case 0xfffffff1, 0xfffffff0: // go1.20+, go1.18/1.19
		hasTextStart = true
	case 0xfffffffa: // go1.16/1.17
		hasTextStart = false
	default:
		return nil
	}

	ptrSize := int(pclntab[7])
	if ptrSize != 4 && ptrSize != 8 {
		return nil
	}

	readWord := func(idx int) (uint64, bool) {
		off := 8 + idx*ptrSize
		if off+ptrSize > len(pclntab) {
			return 0, false
		}
		if ptrSize == 8 {
			return binary.LittleEndian.Uint64(pclntab[off : off+8]), true
		}
		return uint64(binary.LittleEndian.Uint32(pclntab[off : off+4])), true
	}

	// header words after (nfunc, nfiles): [textStart,] funcnameOffset, cuOffset, ...
	funcnameIdx := 2
	if hasTextStart {
		funcnameIdx = 3
	}
	funcnameOffset, ok1 := readWord(funcnameIdx)
	cuOffset, ok2 := readWord(funcnameIdx + 1)
	if !ok1 || !ok2 {
		return nil
	}

	start, end := int(funcnameOffset), int(cuOffset)
	if start < 0 || end > len(pclntab) || start >= end {
		return nil
	}

	var names []string
	for _, raw := range bytes.Split(pclntab[start:end], []byte{0}) {
		if len(raw) == 0 {
			continue
		}
		names = append(names, string(raw))
	}
	return names
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
// Symbols from the "main" package are attributed to the main module. Standard-library symbols (which belong
// to no module) are collected separately and returned as the second value so they can be attached to the
// synthetic "stdlib" package. Compiler/runtime-internal symbols that are neither module-owned nor a
// recognizable stdlib import path are dropped.
func moduleSymbols(symbols []binarySymbol, main *debug.Module, deps []*debug.Module) (byModule map[string][]string, stdlib []string) {
	if len(symbols) == 0 {
		return nil, nil
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
		if pkgPath == mainPackage && main != nil {
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
			if pkgPath != mainPackage && isStandardImportPath(pkgPath) {
				stdlib = append(stdlib, sym.name)
			}
			continue
		}
		results[best] = append(results[best], sym.name)
	}

	for modPath, names := range results {
		slices.Sort(names)
		results[modPath] = slices.Compact(names)
	}
	if len(stdlib) > 0 {
		slices.Sort(stdlib)
		stdlib = slices.Compact(stdlib)
	}

	return results, stdlib
}

// isStandardImportPath reports whether path is a Go standard-library import path. This mirrors the rule
// the Go toolchain uses: a path is standard if the element before its first slash contains no dot (e.g.
// "net/http", "runtime", "internal/abi"), which distinguishes it from module paths like
// "github.com/foo/bar" whose leading element is a domain name.
func isStandardImportPath(path string) bool {
	first := path
	if i := strings.Index(path, "/"); i >= 0 {
		first = path[:i]
	}
	return first != "" && !strings.Contains(first, ".")
}
