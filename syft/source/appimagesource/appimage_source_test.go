package appimagesource

import (
	"crypto"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/go-homedir"
	"github.com/anchore/syft/syft/file"
)

// createMockAppImageFile writes a minimal file with the AppImage magic bytes at offset 8 ("AI\x02").
// It also writes a minimal ELF header so that isAppImageFile passes, but findSquashFSOffset
// will fail — sufficient for testing detection logic without a real squashfs payload.
func createMockAppImageFile(fs afero.Fs, path string) error {
	if err := fs.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	f, err := fs.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	// Write 64 bytes: ELF magic (4 bytes) + class/data/etc (4 bytes) + AppImage magic "AI\x02" (3 bytes at offset 8)
	buf := make([]byte, 64)
	// ELF magic
	copy(buf[0:], []byte{0x7f, 'E', 'L', 'F'})
	// ELF class=2 (64-bit), data=1 (little endian), version=1
	buf[4] = 2
	buf[5] = 1
	buf[6] = 1
	// AppImage type 2 magic at offset 8
	copy(buf[8:], []byte{'A', 'I', 0x02})
	// ELF type, machine, version (offset 16–23) — dummy
	binary.LittleEndian.PutUint16(buf[16:], 2) // ET_EXEC
	binary.LittleEndian.PutUint16(buf[18:], 0) // EM_NONE
	binary.LittleEndian.PutUint32(buf[20:], 1) // EV_CURRENT

	_, err = f.Write(buf)
	return err
}

// createNonAppImageFile writes a file that does NOT have the AppImage magic bytes.
func createNonAppImageFile(fs afero.Fs, path string) error {
	if err := fs.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	f, err := fs.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write([]byte("this is not an appimage"))
	return err
}

// --- isAppImageFile ---

func TestIsAppImageFile(t *testing.T) {
	tests := []struct {
		name     string
		content  []byte
		expected bool
	}{
		{
			name: "valid AppImage magic",
			content: func() []byte {
				b := make([]byte, 11)
				copy(b[8:], []byte{'A', 'I', 0x02})
				return b
			}(),
			expected: true,
		},
		{
			name:     "AppImage type 1 (not type 2)",
			content:  append(make([]byte, 8), 'A', 'I', 0x01),
			expected: false,
		},
		{
			name:     "random bytes",
			content:  []byte("hello world"),
			expected: false,
		},
		{
			name:     "too short",
			content:  []byte{0x01, 0x02},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Write temp file
			f, err := os.CreateTemp(t.TempDir(), "appimage-test")
			require.NoError(t, err)
			_, err = f.Write(tt.content)
			require.NoError(t, err)
			require.NoError(t, f.Close())

			// Re-open as ReaderAt
			rf, err := os.Open(f.Name())
			require.NoError(t, err)
			defer rf.Close()

			result := isAppImageFile(rf)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// --- fileExists ---

func TestFileExists(t *testing.T) {
	fs := afero.NewMemMapFs()

	tests := []struct {
		name     string
		setup    func() string
		expected bool
	}{
		{
			name: "file exists",
			setup: func() string {
				path := "/test/file.AppImage"
				require.NoError(t, createMockAppImageFile(fs, path))
				return path
			},
			expected: true,
		},
		{
			name: "file does not exist",
			setup: func() string {
				return "/nonexistent/file.AppImage"
			},
			expected: false,
		},
		{
			name: "path is a directory",
			setup: func() string {
				path := "/test/mydir"
				require.NoError(t, fs.MkdirAll(path, 0755))
				return path
			},
			expected: false,
		},
		{
			name: "file exists in nested directory",
			setup: func() string {
				path := "/a/b/c/app.AppImage"
				require.NoError(t, createMockAppImageFile(fs, path))
				return path
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := tt.setup()
			result := fileExists(fs, path)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// --- NewFromPath error paths ---

func TestNewFromPath_Errors(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		setup   func(fs afero.Fs) string
		wantErr assert.ErrorAssertionFunc
		wantNil bool
	}{
		{
			name: "file does not exist",
			cfg:  Config{},
			setup: func(fs afero.Fs) string {
				return "/nonexistent/App.AppImage"
			},
			wantErr: assert.Error,
			wantNil: true,
		},
		{
			name: "path is a directory",
			cfg:  Config{},
			setup: func(fs afero.Fs) string {
				path := "/test/mydir"
				require.NoError(t, fs.MkdirAll(path, 0755))
				return path
			},
			wantErr: assert.Error,
			wantNil: true,
		},
		{
			name: "home dir expansion succeeds for existing path",
			cfg:  Config{},
			setup: func(fs afero.Fs) string {
				home, err := homedir.Expand("~/")
				require.NoError(t, err)
				return home
			},
			// directory → error
			wantErr: assert.Error,
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			memFs := afero.NewMemMapFs()
			tt.cfg.fs = memFs
			path := tt.setup(memFs)
			tt.cfg.Request = path

			got, err := NewFromPath(tt.cfg)
			tt.wantErr(t, err, fmt.Sprintf("NewFromPath(%v)", tt.cfg))
			if tt.wantNil {
				assert.Nil(t, got)
			}
		})
	}
}

// --- deriveID ---

func TestDeriveID(t *testing.T) {
	digests := []file.Digest{
		{Algorithm: "xxh-64", Value: "aabbccdd"},
	}

	// Same inputs → same ID
	id1 := deriveID("/some/path", "MyApp", "1.0.0", digests)
	id2 := deriveID("/some/path", "MyApp", "1.0.0", digests)
	assert.Equal(t, id1, id2, "same inputs should produce the same ID")

	// Different name → different ID
	id3 := deriveID("/some/path", "OtherApp", "1.0.0", digests)
	assert.NotEqual(t, id1, id3)

	// Different version → different ID
	id4 := deriveID("/some/path", "MyApp", "2.0.0", digests)
	assert.NotEqual(t, id1, id4)

	// No digests → falls back to path digest, still stable
	id5 := deriveID("/some/path", "MyApp", "1.0.0", nil)
	id6 := deriveID("/some/path", "MyApp", "1.0.0", nil)
	assert.Equal(t, id5, id6, "no-digest derivation should be stable")
	assert.NotEmpty(t, id5)

	// ID should never be empty
	assert.NotEmpty(t, id1)
}

// --- digestOfReader ---

func TestDigestOfReader_Stable(t *testing.T) {
	input := []byte("hello world")

	// Create two temp files with the same content
	d1 := digestOfFileContents(writeTempFile(t, input))
	d2 := digestOfFileContents(writeTempFile(t, input))
	assert.Equal(t, d1, d2)
	assert.NotEmpty(t, d1)
}

func writeTempFile(t *testing.T, content []byte) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "test")
	require.NoError(t, err)
	_, err = f.Write(content)
	require.NoError(t, err)
	require.NoError(t, f.Close())
	return f.Name()
}

// --- Config.fs field (fileExists nil-fallback) ---

func TestFileExists_NilFsUsesOsFs(t *testing.T) {
	// fileExists with nil fs should use real OS fs; test with a real temp file
	f, err := os.CreateTemp(t.TempDir(), "real-file")
	require.NoError(t, err)
	require.NoError(t, f.Close())

	assert.True(t, fileExists(nil, f.Name()), "real file should exist")
	assert.False(t, fileExists(nil, f.Name()+".nope"), "non-existent file should return false")
}

// --- NewFromPath returns nil, nil for non-AppImage ---

func TestNewFromPath_NotAnAppImage(t *testing.T) {
	// Write a file with squashfs magic at position 0 (i.e. NOT AppImage magic at offset 8)
	dir := t.TempDir()
	path := filepath.Join(dir, "notanappimage.AppImage")
	f, err := os.Create(path)
	require.NoError(t, err)
	_, err = f.Write([]byte("hsqsthisisnotan"))
	require.NoError(t, err)
	require.NoError(t, f.Close())

	cfg := Config{
		Request:          path,
		DigestAlgorithms: []crypto.Hash{},
	}
	src, err := NewFromPath(cfg)
	// Should return nil, nil — letting other providers try
	assert.NoError(t, err)
	assert.Nil(t, src)
}
