package executable

import (
	"debug/buildinfo"
	"debug/elf"
	"io"
	"regexp"
	"strings"

	"github.com/scylladb/go-set/strset"

	"github.com/anchore/syft/syft/file"
)

// TODO: additional toolchain detectors we'd like to add. Each entry notes the signal location and the
// component it yields.
//
// ELF (.comment / notes / symbols — same mechanism as the detectors below):
//   1. rustc commit hash: scan rodata for "/rustc/<40-hex>/library/" panic paths; resolves rust provenance
//      for stripped or pre-1.73 binaries (where the .comment producer string is absent). needs a
//      commit->version lookup table to turn the hash into a semver. component: compiler.
//   2. gdc (GNU D): "GNU D" marker alongside the GCC version in .comment. component: compiler.
//   3. Swift (Linux): presence of "swift5_*" sections marks Swift; version only when a "swiftlang-"
//      producer string is present (debug builds). component: compiler.
//   4. Haskell GHC: RTS symbols (hs_init, stg_*) for identity; derive an approximate version from the
//      embedded "base_<x.y.z>" package symbol. component: compiler.
//   5. identity-only (no reliable version) via runtime symbol prefixes: OCaml (caml_*), Nim (NimMain),
//      Crystal (__crystal_main), FreePascal (FPC_*), ldc/dmd D (_Dmain). component: compiler.
//   6. GNU assembler (GNU AS): only present in DWARF .debug_info producer strings, NOT .comment, so it
//      requires DWARF parsing and is absent in stripped builds. component: assembler.
//   7. GNU ld (BFD): leaves no self-identifying marker; can only be inferred by elimination (ELF with a
//      compiler .comment but no lld/mold/gold evidence) at low confidence and with no version.
//
// PE (Windows — needs debug/pe, not covered by this ELF-only file):
//   8. MSVC link.exe + cl.exe: parse the Rich Header (the "DanS".."Rich" block, XOR-decoded into
//      ProdID/build pairs); map build numbers to Visual Studio/linker versions. components: linker + compiler.
//   9. .NET / CLR: COR20 header (optional-header DataDirectory[14]) marks a managed assembly; read the
//      "TargetFrameworkAttribute" string (e.g. ".NETCoreApp,Version=v8.0") for the runtime version.
//      component: runtime. (NativeAOT .NET is a native binary with runtime symbols only and no clean version.)
//
// Mach-O (macOS — needs debug/macho):
//   10. Swift: presence of "__swift5_*" sections; version via the "swiftlang-" producer when present.
//       component: compiler.

var (
	clangVersionPattern = regexp.MustCompile(`clang version (\d+\.\d+\.\d+)`)
	gccVersionPattern   = regexp.MustCompile(`GCC: \([^)]+\) (\d+\.\d+\.\d+)`)
	// rustc embeds its own producer string in .comment for binaries built with rust >= 1.73 (e.g.
	// "rustc version 1.83.0 (90b35a623 2024-11-26)"). The shipped libstd objects instead carry the
	// "clang LLVM (rustc version ...)" form, so accept both.
	rustcVersionPattern = regexp.MustCompile(`rustc version (\d+\.\d+\.\d+)`)
	// LLVM lld writes "Linker: LLD <version>" into .comment (see https://lld.llvm.org/).
	lldVersionPattern = regexp.MustCompile(`Linker: LLD (\d+\.\d+\.\d+)`)
	// mold writes "mold <version> (...; compatible with GNU ld)" into .comment.
	moldVersionPattern = regexp.MustCompile(`mold (\d+\.\d+\.\d+)`)
	// GNU gold writes a "gold <version>" descriptor into the .note.gnu.gold-version note section.
	goldVersionPattern = regexp.MustCompile(`gold (\d+\.\d+)`)
)

// golangToolchainEvidence attempts to extract Go toolchain information from the binary build info.
func golangToolchainEvidence(reader io.ReaderAt) *file.Toolchain {
	bi, err := buildinfo.Read(reader)
	if err != nil || bi == nil {
		// not a golang binary
		return nil
	}
	return &file.Toolchain{
		Name:      "go",
		Version:   bi.GoVersion,
		Component: file.ToolchainComponentCompiler,
	}
}

// cToolchainEvidence attempts to extract C/C++/Fortran compiler information from the ELF .comment section.
// This detects GCC, Clang, and gfortran compilers based on their version strings.
func cToolchainEvidence(comments []string, symbols *strset.Set) *file.Toolchain {
	for _, comment := range comments {
		// check for clang first since clang binaries often have both GCC and clang entries
		// (clang includes GCC compatibility info)
		if match := clangVersionPattern.FindStringSubmatch(comment); match != nil {
			return &file.Toolchain{
				Name:      "clang",
				Version:   match[1],
				Component: file.ToolchainComponentCompiler,
			}
		}
	}

	for _, comment := range comments {
		if match := gccVersionPattern.FindStringSubmatch(comment); match != nil {
			// gfortran is a GCC frontend and shares the GCC version string in .comment, so the only way
			// to distinguish a Fortran build from a C build is by the presence of libgfortran runtime symbols.
			name := "gcc"
			if hasFortranEvidence(symbols) {
				name = "gfortran"
			}
			return &file.Toolchain{
				Name:      name,
				Version:   match[1],
				Component: file.ToolchainComponentCompiler,
			}
		}
	}

	return nil
}

// rustToolchainEvidence attempts to extract Rust compiler information from the ELF .comment section.
func rustToolchainEvidence(comments []string) *file.Toolchain {
	for _, comment := range comments {
		if match := rustcVersionPattern.FindStringSubmatch(comment); match != nil {
			return &file.Toolchain{
				Name:      "rust",
				Version:   match[1],
				Component: file.ToolchainComponentCompiler,
			}
		}
	}
	return nil
}

// linkerToolchainEvidence attempts to extract linker information from the binary. lld and mold leave a
// version string in the ELF .comment section, while gold writes a dedicated .note.gnu.gold-version note.
// GNU ld (BFD) leaves no self-identifying marker, so it cannot be detected here.
func linkerToolchainEvidence(f *elf.File, comments []string) *file.Toolchain {
	for _, comment := range comments {
		if match := lldVersionPattern.FindStringSubmatch(comment); match != nil {
			return &file.Toolchain{
				Name:      "lld",
				Version:   match[1],
				Component: file.ToolchainComponentLinker,
			}
		}
		if match := moldVersionPattern.FindStringSubmatch(comment); match != nil {
			return &file.Toolchain{
				Name:      "mold",
				Version:   match[1],
				Component: file.ToolchainComponentLinker,
			}
		}
	}

	if section := f.Section(".note.gnu.gold-version"); section != nil {
		data, err := section.Data()
		if err == nil {
			if match := goldVersionPattern.FindStringSubmatch(string(data)); match != nil {
				return &file.Toolchain{
					Name:      "gold",
					Version:   match[1],
					Component: file.ToolchainComponentLinker,
				}
			}
		}
	}

	return nil
}

// elfComments returns the null-delimited strings within the ELF .comment section, which may contain
// multiple producer entries (compiler, assembler, linker, etc.).
func elfComments(f *elf.File) []string {
	section := f.Section(".comment")
	if section == nil {
		return nil
	}

	data, err := section.Data()
	if err != nil {
		return nil
	}

	// the .comment section contains null-terminated strings
	return strings.Split(string(data), "\x00")
}

// hasFortranEvidence reports whether the binary references the libgfortran runtime, which indicates a
// gfortran build (MAIN__ is the real Fortran program entry, and _gfortran_* are runtime calls).
func hasFortranEvidence(symbols *strset.Set) bool {
	return symbols.HasAny("MAIN__", "_gfortran_set_args", "_gfortran_set_options", "_gfortran_st_write")
}
