package executable

import (
	"debug/macho"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/internal/unionreader"
)

func Test_machoHasEntrypoint(t *testing.T) {

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
			fixture: "bin/libhello.dylib",
			want:    false,
		},
		{
			name:    "application",
			fixture: "bin/hello_mac",
			want:    true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := macho.NewFile(readerForFixture(t, tt.fixture))
			require.NoError(t, err)
			if got := machoHasEntrypoint(f); got != tt.want {
				t.Errorf("machoHasEntrypoint() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_machoHasExports(t *testing.T) {
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
			fixture: "bin/libhello.dylib",
			want:    true,
		},
		{
			name:    "application",
			fixture: "bin/hello_mac",
			want:    false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := macho.NewFile(readerForFixture(t, tt.fixture))
			require.NoError(t, err)
			if got := machoHasExports(f); got != tt.want {
				t.Errorf("machoHasExports() = %v, want %v", got, tt.want)
			}
		})
	}
}
