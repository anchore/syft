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

func Test_cToolchainDetection(t *testing.T) {
	readerForFixture := func(t *testing.T, fixture string) unionreader.UnionReader {
		t.Helper()
		f, err := os.Open(filepath.Join("test-fixtures/toolchains", fixture))
		require.NoError(t, err)
		return f
	}

	tests := []struct {
		name    string
		fixture string
		want    *file.Toolchain
	}{
		{
			name:    "gcc binary",
			fixture: "gcc/bin/hello_gcc",
			want: &file.Toolchain{
				Name:    "gcc",
				Version: "13.4.0",
				Kind:    file.ToolchainKindCompiler,
			},
		},
		{
			name:    "clang binary",
			fixture: "clang/bin/hello_clang",
			want: &file.Toolchain{
				Name:    "clang",
				Version: "18.1.8",
				Kind:    file.ToolchainKindCompiler,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := readerForFixture(t, tt.fixture)
			f, err := elf.NewFile(reader)
			require.NoError(t, err)

			got := cToolchainEvidence(f)

			if d := cmp.Diff(tt.want, got); d != "" {
				t.Errorf("cToolchainEvidence() mismatch (-want +got):\n%s", d)
			}
		})
	}
}
