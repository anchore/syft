package executable

import (
	"debug/elf"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/internal/unionreader"
)

func Test_findELFSecurityFeatures(t *testing.T) {

	readerForFixture := func(t *testing.T, fixture string) unionreader.UnionReader {
		t.Helper()
		f, err := os.Open(filepath.Join("test-fixtures/elf", fixture))
		require.NoError(t, err)
		return f
	}

	tests := []struct {
		name         string
		fixture      string
		want         *file.ELFSecurityFeatures
		wantErr      require.ErrorAssertionFunc
		wantStripped bool
	}{
		{
			name:    "detect canary",
			fixture: "bin/with_canary",
			want: &file.ELFSecurityFeatures{
				StackCanary:              boolRef(true), // ! important !
				RelocationReadOnly:       file.RelocationReadOnlyNone,
				LlvmSafeStack:            boolRef(false),
				LlvmControlFlowIntegrity: boolRef(false),
				ClangFortifySource:       boolRef(false),
			},
		},
		{
			name:    "detect nx",
			fixture: "bin/with_nx",
			want: &file.ELFSecurityFeatures{
				StackCanary:              boolRef(false),
				NoExecutable:             true, // ! important !
				RelocationReadOnly:       file.RelocationReadOnlyNone,
				LlvmSafeStack:            boolRef(false),
				LlvmControlFlowIntegrity: boolRef(false),
				ClangFortifySource:       boolRef(false),
			},
		},
		{
			name:    "detect relro",
			fixture: "bin/with_relro",
			want: &file.ELFSecurityFeatures{
				StackCanary:              boolRef(false),
				RelocationReadOnly:       file.RelocationReadOnlyFull, // ! important !
				LlvmSafeStack:            boolRef(false),
				LlvmControlFlowIntegrity: boolRef(false),
				ClangFortifySource:       boolRef(false),
			},
		},
		{
			name:    "detect partial relro",
			fixture: "bin/with_partial_relro",
			want: &file.ELFSecurityFeatures{
				StackCanary:              boolRef(false),
				RelocationReadOnly:       file.RelocationReadOnlyPartial, // ! important !
				LlvmSafeStack:            boolRef(false),
				LlvmControlFlowIntegrity: boolRef(false),
				ClangFortifySource:       boolRef(false),
			},
		},
		{
			name:    "detect pie",
			fixture: "bin/with_pie",
			want: &file.ELFSecurityFeatures{
				StackCanary:                   boolRef(false),
				RelocationReadOnly:            file.RelocationReadOnlyNone,
				PositionIndependentExecutable: true, // ! important !
				DynamicSharedObject:           true, // ! important !
				LlvmSafeStack:                 boolRef(false),
				LlvmControlFlowIntegrity:      boolRef(false),
				ClangFortifySource:            boolRef(false),
			},
		},
		{
			name:    "detect dso",
			fixture: "bin/pie_false_positive.so",
			want: &file.ELFSecurityFeatures{
				StackCanary:                   boolRef(false),
				RelocationReadOnly:            file.RelocationReadOnlyPartial,
				NoExecutable:                  true,
				PositionIndependentExecutable: false, // ! important !
				DynamicSharedObject:           true,  // ! important !
				LlvmSafeStack:                 boolRef(false),
				LlvmControlFlowIntegrity:      boolRef(false),
				ClangFortifySource:            boolRef(false),
			},
		},
		{
			name:    "detect safestack",
			fixture: "bin/with_safestack",
			want: &file.ELFSecurityFeatures{
				NoExecutable:                  true,
				StackCanary:                   boolRef(false),
				RelocationReadOnly:            file.RelocationReadOnlyPartial,
				PositionIndependentExecutable: false,
				DynamicSharedObject:           false,
				LlvmSafeStack:                 boolRef(true), // ! important !
				LlvmControlFlowIntegrity:      boolRef(false),
				ClangFortifySource:            boolRef(false),
			},
		},
		{
			name:    "detect cfi",
			fixture: "bin/with_cfi",
			want: &file.ELFSecurityFeatures{
				NoExecutable:                  true,
				StackCanary:                   boolRef(false),
				RelocationReadOnly:            file.RelocationReadOnlyPartial,
				PositionIndependentExecutable: false,
				DynamicSharedObject:           false,
				LlvmSafeStack:                 boolRef(false),
				LlvmControlFlowIntegrity:      boolRef(true), // ! important !
				ClangFortifySource:            boolRef(false),
			},
		},
		{
			name:    "detect fortify",
			fixture: "bin/with_fortify",
			want: &file.ELFSecurityFeatures{
				NoExecutable:                  true,
				StackCanary:                   boolRef(false),
				RelocationReadOnly:            file.RelocationReadOnlyPartial,
				PositionIndependentExecutable: false,
				DynamicSharedObject:           false,
				LlvmSafeStack:                 boolRef(false),
				LlvmControlFlowIntegrity:      boolRef(false),
				ClangFortifySource:            boolRef(true), // ! important !
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := elf.NewFile(readerForFixture(t, tt.fixture))
			require.NoError(t, err)

			got := findELFSecurityFeatures(f)

			if d := cmp.Diff(tt.want, got); d != "" {
				t.Errorf("findELFSecurityFeatures() mismatch (-want +got):\n%s", d)
			}
		})
	}
}

func Test_elfHasEntrypoint(t *testing.T) {

	readerForFixture := func(t *testing.T, fixture string) unionreader.UnionReader {
		t.Helper()
		f, err := os.Open(filepath.Join("test-fixtures/shared-info", fixture))
		require.NoError(t, err)
		return f
	}

	tests := []struct {
		name    string
		fixture string
		want    bool
	}{
		{
			name:    "shared lib",
			fixture: "bin/libhello.so",
			want:    false,
		},
		{
			name:    "application",
			fixture: "bin/hello_linux",
			want:    true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := elf.NewFile(readerForFixture(t, tt.fixture))
			require.NoError(t, err)
			assert.Equal(t, tt.want, elfHasEntrypoint(f))
		})
	}
}

func Test_elfHasExports(t *testing.T) {
	readerForFixture := func(t *testing.T, fixture string) unionreader.UnionReader {
		t.Helper()
		f, err := os.Open(filepath.Join("test-fixtures/shared-info", fixture))
		require.NoError(t, err)
		return f
	}

	tests := []struct {
		name    string
		fixture string
		want    bool
	}{
		{
			name:    "shared lib",
			fixture: "bin/libhello.so",
			want:    true,
		},
		{
			name:    "application",
			fixture: "bin/hello_linux",
			want:    false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := elf.NewFile(readerForFixture(t, tt.fixture))
			require.NoError(t, err)
			assert.Equal(t, tt.want, elfHasExports(f))
			require.NoError(t, err)
		})
	}
}
