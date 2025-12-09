package executable

import (
	"debug/elf"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
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
