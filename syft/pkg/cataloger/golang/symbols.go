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
			syms = nil
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
		if fn.Sym == nil || isCompilerGeneratedName(fn.Name) {
			continue
		}
		seen[fn.Name] = struct{}{}
		syms = append(syms, makeBinarySymbol(fn.Name, fn.PackageName()))
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
		syms = append(syms, makeBinarySymbol(name, pkgPath))
	}

	return syms, nil
}

// packagePathFromSymbolName derives the owning package import path from a fully qualified symbol name.
// The package path is everything up to the first "." that follows the final "/" — e.g.
// "path/filepath.IsLocal" -> "path/filepath" and "golang.org/x/net/html.(*Tokenizer).Next" ->
// "golang.org/x/net/html". Returns "" when the name has no package-qualifying dot or is compiler-generated.
func packagePathFromSymbolName(name string) string {
	if isCompilerGeneratedName(name) {
		return ""
	}
	name = nameWithoutTypeArgs(name)
	slash := strings.LastIndex(name, "/")
	dot := strings.IndexByte(name[slash+1:], '.')
	if dot < 0 {
		return ""
	}
	return name[:slash+1+dot]
}

// makeBinarySymbol builds a binarySymbol, unescaping the %xx sequences the go linker introduces in the
// import-path portion of a symbol name (see unescapePackagePath). The local-symbol suffix (method and
// function names) is left untouched, so only the path prefix shared by packagePath and name is rewritten.
func makeBinarySymbol(name, pkgPath string) binarySymbol {
	unescaped := unescapePackagePath(pkgPath)
	if unescaped != pkgPath && strings.HasPrefix(name, pkgPath) {
		name = unescaped + name[len(pkgPath):]
	}
	return binarySymbol{packagePath: unescaped, name: name}
}

// unescapePackagePath reverses the escaping cmd/internal/objabi.PathToPrefix applies to import paths in
// symbol names: bytes like '.' (at or after the final '/'), '%', '"', control bytes, and high bytes are
// written as lowercase "%xx". For example "gopkg.in/yaml.v2" is stored as "gopkg.in/yaml%2ev2", so this
// restores it before matching against the (unescaped) module paths from build info. A lone or malformed
// '%' sequence is left as-is.
func unescapePackagePath(path string) string {
	if !strings.Contains(path, "%") {
		return path
	}
	var b strings.Builder
	b.Grow(len(path))
	for i := 0; i < len(path); i++ {
		if path[i] == '%' && i+2 < len(path) {
			if hi, ok1 := unhex(path[i+1]); ok1 {
				if lo, ok2 := unhex(path[i+2]); ok2 {
					b.WriteByte(hi<<4 | lo)
					i += 2
					continue
				}
			}
		}
		b.WriteByte(path[i])
	}
	return b.String()
}

func unhex(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// nameWithoutTypeArgs strips the type-argument portion from an instantiated generic symbol name, e.g.
// "foo/bar.Do[net/url.Values]" -> "foo/bar.Do". The slashes and dots inside the brackets would otherwise
// corrupt package-path derivation (yielding "foo/bar.Do[net" for the example above). Mirrors
// debug/gosym's (*Sym).nameWithoutInst.
func nameWithoutTypeArgs(name string) string {
	start := strings.IndexByte(name, '[')
	if start < 0 {
		return name
	}
	end := strings.LastIndexByte(name, ']')
	if end < 0 {
		// malformed: an opening bracket should always have a closing one
		return name
	}
	return name[:start] + name[end+1:]
}

// oldStyleCompilerGeneratedPrefixes match compiler/linker-generated symbols from toolchains older than
// go1.20, which used "." where newer toolchains use ":" (e.g. "go.buildid" is now "go:buildid",
// "go.type.*" is now "go:type.*"). These must be prefix (not substring) matches, and a bare "go." prefix
// is not enough: legitimate module paths such as "go.uber.org/zap" also start with "go.".
var oldStyleCompilerGeneratedPrefixes = []string{
	"go.buildid",
	"go.builtin.",
	"go.constinfo.",
	"go.cuinfo.",
	"go.func.",
	"go.importpath.",
	"go.info.",
	"go.interface.",
	"go.itab.",
	"go.itablink.",
	"go.map.",
	"go.shape.",
	"go.string.",
	"go.type.",
	"go.typelink.",
	"type.",
}

// isCompilerGeneratedName reports whether a symbol name was synthesized by the compiler or linker rather
// than declared in Go source. Since go1.20 these names contain ':' or '..' (e.g. "type:.eq.*",
// "go:string.*") — byte sequences that never appear in a real Go import path or identifier. Older
// toolchains used '.' as the separator (e.g. "go.type.*", "type..hash.*"), which is matched against the
// known reserved prefixes. Such names belong to no package and are dropped rather than mis-attributed
// (e.g. bucketed under a bogus "type" stdlib package).
func isCompilerGeneratedName(name string) bool {
	if strings.Contains(name, ":") || strings.Contains(name, "..") {
		return true
	}
	for _, prefix := range oldStyleCompilerGeneratedPrefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
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
	for raw := range bytes.SplitSeq(pclntab[start:end], []byte{0}) {
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
// of the symbol's package path) and returns, per module path, the symbols grouped by the import path of the
// owning package. Each inner value is a sorted, deduplicated list of symbol names local to that package
// (the import path prefix stripped, e.g. "github.com/foo/bar.(*T).M" under key "github.com/foo/bar" becomes
// "(*T).M"). Symbols from the "main" package are attributed to the main module and keyed by the "main"
// import path the linker assigns. Standard-library symbols (which belong to no module) are collected
// separately and returned as the second value, grouped by import path, so they can be attached to the
// synthetic "stdlib" package. Compiler/runtime-internal symbols that are neither module-owned nor a
// recognizable stdlib import path are dropped.
func moduleSymbols(symbols []binarySymbol, main *debug.Module, deps []*debug.Module) (byModule map[string]map[string][]string, stdlib map[string][]string) {
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

	results := make(map[string]map[string][]string)
	stdlib = make(map[string][]string)
	for _, sym := range symbols {
		importPath := sym.packagePath

		// the linker renames the main package's import path to "main"; attribute it to the main module,
		// but keep "main" as the group key since the original import path is not recoverable.
		attrPath := importPath
		if importPath == mainPackage && main != nil {
			attrPath = main.Path
		}

		var best string
		for _, modPath := range modulePaths {
			if len(modPath) > len(best) && (attrPath == modPath || strings.HasPrefix(attrPath, modPath+"/")) {
				best = modPath
			}
		}

		local := localSymbolName(sym.name, importPath)
		if best == "" {
			if importPath != mainPackage && isStandardImportPath(importPath) {
				stdlib[importPath] = append(stdlib[importPath], local)
			}
			continue
		}
		if results[best] == nil {
			results[best] = make(map[string][]string)
		}
		results[best][importPath] = append(results[best][importPath], local)
	}

	for _, byImport := range results {
		sortCompactGroups(byImport)
	}
	sortCompactGroups(stdlib)
	if len(stdlib) == 0 {
		stdlib = nil
	}

	return results, stdlib
}

// localSymbolName strips the owning package's import path prefix from a fully qualified symbol name, e.g.
// "github.com/foo/bar.(*T).M" with import path "github.com/foo/bar" becomes "(*T).M". The name is returned
// unchanged when it does not carry the expected prefix.
func localSymbolName(name, importPath string) string {
	if importPath != "" && strings.HasPrefix(name, importPath+".") {
		return name[len(importPath)+1:]
	}
	return name
}

// sortCompactGroups sorts and deduplicates each symbol list in a group keyed by import path, in place.
func sortCompactGroups(groups map[string][]string) {
	for path, names := range groups {
		slices.Sort(names)
		groups[path] = slices.Compact(names)
	}
}

// isStandardImportPath reports whether path is a Go standard-library import path. This mirrors the rule
// the Go toolchain uses: a path is standard if the element before its first slash contains no dot (e.g.
// "net/http", "runtime", "internal/abi"), which distinguishes it from module paths like
// "github.com/foo/bar" whose leading element is a domain name.
func isStandardImportPath(path string) bool {
	first, _, _ := strings.Cut(path, "/")
	return first != "" && !strings.Contains(first, ".")
}
