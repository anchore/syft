package executable

import (
	"debug/pe"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/internal/unionreader"
)

func Test_peHasEntrypoint(t *testing.T) {

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
			fixture: "bin/hello.dll", // though this is a shared lib, it has an entrypoint (DLLMain)
			want:    false,
		},
		{
			name:    "application",
			fixture: "bin/hello.exe",
			want:    true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := pe.NewFile(readerForFixture(t, tt.fixture))
			require.NoError(t, err)
			assert.Equal(t, tt.want, peHasEntrypoint(f))
		})
	}
}

func Test_peHasExports(t *testing.T) {
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
			fixture: "bin/hello.dll",
			want:    true,
		},
		{
			name:    "application",
			fixture: "bin/hello.exe",
			want:    false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := pe.NewFile(readerForFixture(t, tt.fixture))
			require.NoError(t, err)
			assert.Equal(t, tt.want, peHasExports(f))
		})
	}
}
