package executable

import (
	"debug/elf"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/scylladb/go-set/strset"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/internal/unionreader"
)

// hasGoToolchain is a test helper to check whether the go toolchain was detected.
func hasGoToolchain(toolchains []file.Toolchain) bool {
	for _, tc := range toolchains {
		if tc.Name == "go" {
			return true
		}
	}
	return false
}

func Test_elfToolchains(t *testing.T) {
	readerForFixture := func(t *testing.T, fixture string) unionreader.UnionReader {
		t.Helper()
		f, err := os.Open(filepath.Join("testdata/toolchains", fixture))
		require.NoError(t, err)
		return f
	}

	compiler := file.ToolchainComponentCompiler
	linker := file.ToolchainComponentLinker

	tests := []struct {
		name    string
		fixture string
		want    []file.Toolchain
	}{
		{
			name:    "gcc: compiler only",
			fixture: "gcc/bin/hello_gcc",
			want: []file.Toolchain{
				{Name: "gcc", Version: "13.4.0", Component: compiler},
			},
		},
		{
			name:    "clang: compiler only",
			fixture: "clang/bin/hello_clang",
			want: []file.Toolchain{
				{Name: "clang", Version: "18.1.8", Component: compiler},
			},
		},
		{
			name:    "lld: clang compiler + lld linker",
			fixture: "lld/bin/hello_lld",
			want: []file.Toolchain{
				{Name: "clang", Version: "18.1.8", Component: compiler},
				{Name: "lld", Version: "19.1.4", Component: linker},
			},
		},
		{
			name:    "mold: gcc compiler + mold linker",
			fixture: "mold/bin/hello_mold",
			want: []file.Toolchain{
				{Name: "gcc", Version: "14.2.0", Component: compiler},
				{Name: "mold", Version: "2.34.1", Component: linker},
			},
		},
		{
			name:    "gold: gcc compiler + gold linker",
			fixture: "gold/bin/hello_gold",
			want: []file.Toolchain{
				{Name: "gcc", Version: "14.2.0", Component: compiler},
				{Name: "gold", Version: "1.16", Component: linker},
			},
		},
		{
			// rust binaries also carry a GCC producer string from the gcc-compiled C runtime glue that is
			// linked in, so both compilers are reported (akin to how cgo binaries report go and gcc).
			name:    "rust: gcc glue + rustc",
			fixture: "rust/bin/hello_rust",
			want: []file.Toolchain{
				{Name: "gcc", Version: "12.2.0", Component: compiler},
				{Name: "rust", Version: "1.83.0", Component: compiler},
			},
		},
		{
			// gfortran shares the GCC version string in .comment, so it is only distinguishable from a
			// C build by the presence of libgfortran runtime symbols (gcc gets relabeled to gfortran).
			name:    "fortran: gfortran compiler only",
			fixture: "fortran/bin/hello_fortran",
			want: []file.Toolchain{
				{Name: "gfortran", Version: "13.4.0", Component: compiler},
			},
		},
		{
			// gdc is a GCC frontend that shares the GCC version string, so it is distinguished from a C
			// build only by the D runtime symbols (_Dmain, __gdc_personality_v0).
			name:    "gdc: GNU D compiler only",
			fixture: "gdc/bin/hello_gdc",
			want: []file.Toolchain{
				{Name: "gdc", Version: "12.2.0", Component: compiler},
			},
		},
		{
			// gccgo is a GCC frontend (not the gc toolchain, so it has no Go build info); it shares the
			// GCC version string and is distinguished only by the libgo __go_* runtime symbols.
			name:    "gccgo: GNU Go compiler only",
			fixture: "gccgo/bin/hello_gccgo",
			want: []file.Toolchain{
				{Name: "gccgo", Version: "12.2.0", Component: compiler},
			},
		},
		{
			// gnat is the GCC Ada frontend; it shares the GCC version string and is distinguished only by
			// the GNAT runtime symbols (adainit, __gnat_*).
			name:    "gnat: GNU Ada compiler only",
			fixture: "gnat/bin/hello_gnat",
			want: []file.Toolchain{
				{Name: "gnat", Version: "12.2.0", Component: compiler},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := readerForFixture(t, tt.fixture)
			f, err := elf.NewFile(reader)
			require.NoError(t, err)

			got := elfToolchains(reader, f)

			if d := cmp.Diff(tt.want, got); d != "" {
				t.Errorf("elfToolchains() mismatch (-want +got):\n%s", d)
			}
		})
	}
}

func Test_cToolchainEvidence(t *testing.T) {
	compiler := file.ToolchainComponentCompiler

	tests := []struct {
		name     string
		comments []string
		symbols  []string
		want     *file.Toolchain
	}{
		{
			// icx (Intel oneAPI DPC++/C++) is an LLVM/clang fork. there is no freely buildable linux/amd64
			// image to anchor a real fixture, so the literal .comment producer string is asserted here. the
			// exact form is confirmed by a real `readelf -x .comment` dump (which yielded
			// "Intel(R) oneAPI DPC++/C++ Compiler 2024.0.2 (2024.0.2.20231223)"):
			//   - https://briancallahan.net/blog/20240306.html
			//   - https://www.intel.com/content/www/us/en/developer/articles/release-notes/oneapi-dpcpp/2025.html
			// because it is a clang fork, the Intel string must be matched before the generic clang pattern;
			// the second "clang version" entry below guards that ordering (a generic clang match must not win).
			name: "intel oneAPI icx is matched before clang",
			comments: []string{
				"Intel(R) oneAPI DPC++/C++ Compiler 2024.0.2 (2024.0.2.20231223)",
				"clang version 18.1.0",
			},
			want: &file.Toolchain{Name: "icx", Version: "2024.0.2", Component: compiler},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := cToolchainEvidence(tt.comments, strset.New(tt.symbols...))
			if d := cmp.Diff(tt.want, got); d != "" {
				t.Errorf("cToolchainEvidence() mismatch (-want +got):\n%s", d)
			}
		})
	}
}

func Test_linkerToolchainEvidence(t *testing.T) {
	linker := file.ToolchainComponentLinker

	tests := []struct {
		name     string
		comments []string
		want     *file.Toolchain
	}{
		{
			// lld writes "Linker: " + getLLDVersion() into .comment. docs and source:
			//   - https://lld.llvm.org/ ("If the string \"Linker: LLD\" is included ... you are using LLD")
			//   - https://github.com/llvm/llvm-project/blob/main/lld/ELF/SyntheticSections.cpp (Twine("Linker: ") + getLLDVersion())
			name:     "vanilla lld",
			comments: []string{"Linker: LLD 19.1.4"},
			want:     &file.Toolchain{Name: "lld", Version: "19.1.4", Component: linker},
		},
		{
			// debian/ubuntu prepend a vendor to getLLDVersion() (the same packaging mechanism behind clang's
			// "Ubuntu clang version ..."), so .comment reads "Linker: Ubuntu LLD <version>". reproduced on
			// ubuntu:24.04: `readelf -p .comment <bin>` => "Linker: Ubuntu LLD 18.1.3".
			name:     "vendor-prefixed lld",
			comments: []string{"Linker: Ubuntu LLD 18.1.3"},
			want:     &file.Toolchain{Name: "lld", Version: "18.1.3", Component: linker},
		},
		{
			// mold writes "mold <version> (<commit>; compatible with GNU ld)" into .comment. this format is
			// documented by mold and is also exercised end-to-end by the real fixture in Test_elfToolchains:
			//   - https://github.com/rui314/mold (README: "mold leaves its identification string in .comment")
			name:     "mold",
			comments: []string{"mold 2.34.1 (compatible with GNU ld)"},
			want:     &file.Toolchain{Name: "mold", Version: "2.34.1", Component: linker},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// f is only consulted for the gold note, which these comment-based cases match before reaching.
			got := linkerToolchainEvidence(nil, tt.comments)
			if d := cmp.Diff(tt.want, got); d != "" {
				t.Errorf("linkerToolchainEvidence() mismatch (-want +got):\n%s", d)
			}
		})
	}
}
