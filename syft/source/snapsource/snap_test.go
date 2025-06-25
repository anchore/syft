package snapsource

import (
	"context"
	"crypto"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/wagoodman/go-progress"

	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/internal/file"
)

func TestSnapIdentity_String(t *testing.T) {
	tests := []struct {
		name     string
		identity snapIdentity
		expected string
	}{
		{
			name: "name only",
			identity: snapIdentity{
				Name: "etcd",
			},
			expected: "etcd",
		},
		{
			name: "name with channel",
			identity: snapIdentity{
				Name:    "etcd",
				Channel: "stable",
			},
			expected: "etcd@stable",
		},
		{
			name: "name with architecture",
			identity: snapIdentity{
				Name:         "etcd",
				Architecture: "amd64",
			},
			expected: "etcd (amd64)",
		},
		{
			name: "name with channel and architecture",
			identity: snapIdentity{
				Name:         "etcd",
				Channel:      "beta",
				Architecture: "arm64",
			},
			expected: "etcd@beta (arm64)",
		},
		{
			name: "empty channel with architecture",
			identity: snapIdentity{
				Name:         "mysql",
				Channel:      "",
				Architecture: "amd64",
			},
			expected: "mysql (amd64)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.identity.String()
			assert.Equal(t, tt.expected, result)
		})
	}
}

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
				path := "/test/file.snap"
				require.NoError(t, createMockSquashfsFile(fs, path))
				return path
			},
			expected: true,
		},
		{
			name: "file does not exist",
			setup: func() string {
				return "/nonexistent/file.snap"
			},
			expected: false,
		},
		{
			name: "path is directory",
			setup: func() string {
				path := "/test/dir"
				require.NoError(t, fs.MkdirAll(path, 0755))
				return path
			},
			expected: false,
		},
		{
			name: "file exists in subdirectory",
			setup: func() string {
				path := "/deep/nested/path/file.snap"
				require.NoError(t, createMockSquashfsFile(fs, path))
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

func TestNewSnapFromFile(t *testing.T) {
	ctx := context.Background()
	fs := afero.NewMemMapFs()

	tests := []struct {
		name        string
		cfg         Config
		setup       func() string
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid local snap file",
			cfg: Config{
				DigestAlgorithms: []crypto.Hash{crypto.SHA256},
			},
			setup: func() string {
				path := "/test/valid.snap"
				require.NoError(t, createMockSquashfsFile(fs, path))
				return path
			},
			expectError: false,
		},
		{
			name: "architecture specified for local file",
			cfg: Config{
				Platform: &image.Platform{
					Architecture: "arm64",
				},
			},
			setup: func() string {
				path := "/test/valid.snap"
				require.NoError(t, createMockSquashfsFile(fs, path))
				return path
			},
			expectError: true,
			errorMsg:    "architecture cannot be specified for local snap files",
		},
		{
			name: "file does not exist",
			cfg:  Config{},
			setup: func() string {
				return "/nonexistent/file.snap"
			},
			expectError: true,
			errorMsg:    "unable to stat path",
		},
		{
			name: "path is directory",
			cfg:  Config{},
			setup: func() string {
				path := "/test/directory"
				require.NoError(t, fs.MkdirAll(path, 0755))
				return path
			},
			expectError: true,
			errorMsg:    "given path is a directory",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := tt.setup()
			tt.cfg.Request = path

			result, err := newSnapFromFile(ctx, fs, tt.cfg)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, result)
				assert.Equal(t, path, result.Path)
				assert.NotEmpty(t, result.MimeType)
				assert.NotEmpty(t, result.Digests)
				assert.Nil(t, result.Cleanup) // Local files don't have cleanup
			}
		})
	}
}

func TestNewSnapFileFromRemote(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name        string
		cfg         Config
		info        *remoteSnap
		setupMock   func(*mockFileGetter, afero.Fs)
		expectError bool
		errorMsg    string
		validate    func(t *testing.T, result *snapFile, fs afero.Fs)
	}{
		{
			name: "successful remote snap download",
			cfg: Config{
				DigestAlgorithms: []crypto.Hash{crypto.SHA256},
			},
			info: &remoteSnap{
				snapIdentity: snapIdentity{
					Name:         "etcd",
					Channel:      "stable",
					Architecture: "amd64",
				},
				URL: "https://api.snapcraft.io/download/etcd_123.snap",
			},
			setupMock: func(mockGetter *mockFileGetter, fs afero.Fs) {
				mockGetter.On("GetFile", mock.MatchedBy(func(dst string) bool {
					// expect destination to end with etcd_123.snap
					return filepath.Base(dst) == "etcd_123.snap"
				}), "https://api.snapcraft.io/download/etcd_123.snap", mock.Anything).Run(func(args mock.Arguments) {
					// simulate successful download by creating the file
					dst := args.String(0)
					require.NoError(t, createMockSquashfsFile(fs, dst))
				}).Return(nil)
			},
			expectError: false,
			validate: func(t *testing.T, result *snapFile, fs afero.Fs) {
				assert.NotNil(t, result)
				assert.Contains(t, result.Path, "etcd_123.snap")
				assert.NotEmpty(t, result.MimeType)
				assert.NotEmpty(t, result.Digests)
				assert.NotNil(t, result.Cleanup)

				_, err := fs.Stat(result.Path)
				assert.NoError(t, err)

				err = result.Cleanup()
				require.NoError(t, err)

				_, err = fs.Stat(result.Path)
				assert.True(t, os.IsNotExist(err))
			},
		},
		{
			name: "successful download with no digest algorithms",
			cfg: Config{
				DigestAlgorithms: []crypto.Hash{}, // no digests requested
			},
			info: &remoteSnap{
				snapIdentity: snapIdentity{
					Name:         "mysql",
					Channel:      "8.0/stable",
					Architecture: "arm64",
				},
				URL: "https://api.snapcraft.io/download/mysql_456.snap",
			},
			setupMock: func(mockGetter *mockFileGetter, fs afero.Fs) {
				mockGetter.On("GetFile", mock.MatchedBy(func(dst string) bool {
					return filepath.Base(dst) == "mysql_456.snap"
				}), "https://api.snapcraft.io/download/mysql_456.snap", mock.Anything).Run(func(args mock.Arguments) {
					dst := args.String(0)
					require.NoError(t, createMockSquashfsFile(fs, dst))
				}).Return(nil)
			},
			expectError: false,
			validate: func(t *testing.T, result *snapFile, fs afero.Fs) {
				assert.NotNil(t, result)
				assert.Contains(t, result.Path, "mysql_456.snap")
				assert.NotEmpty(t, result.MimeType)
				assert.Empty(t, result.Digests) // no digests requested
				assert.NotNil(t, result.Cleanup)
			},
		},
		{
			name: "download fails",
			cfg: Config{
				DigestAlgorithms: []crypto.Hash{crypto.SHA256},
			},
			info: &remoteSnap{
				snapIdentity: snapIdentity{
					Name:         "failing-snap",
					Channel:      "stable",
					Architecture: "amd64",
				},
				URL: "https://api.snapcraft.io/download/failing_snap.snap",
			},
			setupMock: func(mockGetter *mockFileGetter, fs afero.Fs) {
				mockGetter.On("GetFile", mock.AnythingOfType("string"), "https://api.snapcraft.io/download/failing_snap.snap", mock.Anything).Return(fmt.Errorf("network timeout"))
			},
			expectError: true,
			errorMsg:    "failed to download snap file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := afero.NewOsFs()
			mockGetter := &mockFileGetter{}

			if tt.setupMock != nil {
				tt.setupMock(mockGetter, fs)
			}

			result, err := newSnapFileFromRemote(ctx, fs, tt.cfg, mockGetter, tt.info)

			if tt.expectError {
				require.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
				assert.Nil(t, result)
			} else {
				require.NoError(t, err)
				if tt.validate != nil {
					tt.validate(t, result, fs)
				}
			}

			mockGetter.AssertExpectations(t)
		})
	}
}

func TestGetSnapFileInfo(t *testing.T) {
	ctx := context.Background()
	fs := afero.NewMemMapFs()

	tests := []struct {
		name        string
		setup       func() string
		hashes      []crypto.Hash
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid squashfs file with hashes",
			setup: func() string {
				path := "/test/valid.snap"
				require.NoError(t, createMockSquashfsFile(fs, path))
				return path
			},
			hashes:      []crypto.Hash{crypto.SHA256, crypto.MD5},
			expectError: false,
		},
		{
			name: "valid squashfs file without hashes",
			setup: func() string {
				path := "/test/valid.snap"
				require.NoError(t, createMockSquashfsFile(fs, path))
				return path
			},
			hashes:      []crypto.Hash{},
			expectError: false,
		},
		{
			name: "file does not exist",
			setup: func() string {
				return "/nonexistent/file.snap"
			},
			expectError: true,
			errorMsg:    "unable to stat path",
		},
		{
			name: "path is directory",
			setup: func() string {
				path := "/test/directory"
				require.NoError(t, fs.MkdirAll(path, 0755))
				return path
			},
			expectError: true,
			errorMsg:    "given path is a directory",
		},
		{
			name: "invalid file format",
			setup: func() string {
				path := "/test/invalid.txt"
				require.NoError(t, fs.MkdirAll(filepath.Dir(path), 0755))
				file, err := fs.Create(path)
				require.NoError(t, err)
				defer file.Close()
				_, err = file.Write([]byte("not a squashfs file"))
				require.NoError(t, err)
				return path
			},
			expectError: true,
			errorMsg:    "not a valid squashfs/snap file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := tt.setup()

			mimeType, digests, err := getSnapFileInfo(ctx, fs, path, tt.hashes)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
				assert.NotEmpty(t, mimeType)
				if len(tt.hashes) > 0 {
					assert.Len(t, digests, len(tt.hashes))
				} else {
					assert.Empty(t, digests)
				}
			}
		})
	}
}

func TestDownloadSnap(t *testing.T) {
	mockGetter := &mockFileGetter{}

	tests := []struct {
		name        string
		info        *remoteSnap
		dest        string
		setupMock   func()
		expectError bool
		errorMsg    string
	}{
		{
			name: "successful download",
			info: &remoteSnap{
				snapIdentity: snapIdentity{
					Name:         "etcd",
					Channel:      "stable",
					Architecture: "amd64",
				},
				URL: "https://example.com/etcd.snap",
			},
			dest: "/tmp/etcd.snap",
			setupMock: func() {
				mockGetter.On("GetFile", "/tmp/etcd.snap", "https://example.com/etcd.snap", mock.AnythingOfType("[]*progress.Manual")).Return(nil)
			},
			expectError: false,
		},
		{
			name: "download fails",
			info: &remoteSnap{
				snapIdentity: snapIdentity{
					Name:         "etcd",
					Channel:      "stable",
					Architecture: "amd64",
				},
				URL: "https://example.com/etcd.snap",
			},
			dest: "/tmp/etcd.snap",
			setupMock: func() {
				mockGetter.On("GetFile", "/tmp/etcd.snap", "https://example.com/etcd.snap", mock.AnythingOfType("[]*progress.Manual")).Return(fmt.Errorf("network error"))
			},
			expectError: true,
			errorMsg:    "failed to download snap file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// reset mock for each test
			mockGetter.ExpectedCalls = nil
			if tt.setupMock != nil {
				tt.setupMock()
			}

			err := downloadSnap(mockGetter, tt.info, tt.dest)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
			}

			mockGetter.AssertExpectations(t)
		})
	}
}

func TestParseSnapRequest(t *testing.T) {
	tests := []struct {
		name            string
		request         string
		expectedName    string
		expectedChannel string
	}{
		{
			name:            "snap name only - uses default channel",
			request:         "etcd",
			expectedName:    "etcd",
			expectedChannel: "stable",
		},
		{
			name:            "snap with beta channel",
			request:         "etcd@beta",
			expectedName:    "etcd",
			expectedChannel: "beta",
		},
		{
			name:            "snap with edge channel",
			request:         "etcd@edge",
			expectedName:    "etcd",
			expectedChannel: "edge",
		},
		{
			name:            "snap with version track",
			request:         "etcd@2.3/stable",
			expectedName:    "etcd",
			expectedChannel: "2.3/stable",
		},
		{
			name:            "snap with complex channel path",
			request:         "mysql@8.0/candidate",
			expectedName:    "mysql",
			expectedChannel: "8.0/candidate",
		},
		{
			name:            "snap with multiple @ symbols - only first is delimiter",
			request:         "app@beta@test",
			expectedName:    "app",
			expectedChannel: "beta@test",
		},
		{
			name:            "empty snap name with channel",
			request:         "@stable",
			expectedName:    "",
			expectedChannel: "stable",
		},
		{
			name:            "snap name with empty channel - uses default",
			request:         "etcd@",
			expectedName:    "etcd",
			expectedChannel: "stable",
		},
		{
			name:            "hyphenated snap name",
			request:         "hello-world@stable",
			expectedName:    "hello-world",
			expectedChannel: "stable",
		},
		{
			name:            "snap name with numbers",
			request:         "app123",
			expectedName:    "app123",
			expectedChannel: "stable",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name, channel := parseSnapRequest(tt.request)
			assert.Equal(t, tt.expectedName, name)
			assert.Equal(t, tt.expectedChannel, channel)
		})
	}
}

type mockFileGetter struct {
	mock.Mock
	file.Getter
}

func (m *mockFileGetter) GetFile(dst, src string, monitor ...*progress.Manual) error {
	args := m.Called(dst, src, monitor)
	return args.Error(0)
}

func createMockSquashfsFile(fs afero.Fs, path string) error {
	dir := filepath.Dir(path)
	if err := fs.MkdirAll(dir, 0755); err != nil {
		return err
	}

	file, err := fs.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	// write squashfs magic header
	_, err = file.Write([]byte("hsqs"))
	return err
}
