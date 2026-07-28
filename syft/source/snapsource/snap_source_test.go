package snapsource

import (
	"crypto"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/go-homedir"
	"github.com/anchore/stereoscope/pkg/image"
)

func TestNewFromLocal(t *testing.T) {
	tests := []struct {
		name        string
		cfg         Config
		setup       func(fs afero.Fs)
		wantRequest string
		wantErr     assert.ErrorAssertionFunc
	}{
		{
			name: "local file exists",
			cfg: Config{
				Request:          "/test/local.snap",
				DigestAlgorithms: []crypto.Hash{crypto.SHA256},
			},
			setup: func(fs afero.Fs) {
				require.NoError(t, createMockSquashfsFile(fs, "/test/local.snap"))
			},
			wantRequest: "/test/local.snap",
		},
		{
			name: "resolve home dir exists",
			cfg: Config{
				Request:          "~/test/local.snap",
				DigestAlgorithms: []crypto.Hash{crypto.SHA256},
			},
			wantErr: assert.Error,
			wantRequest: func() string {
				homeDir, err := homedir.Expand("~/test/local.snap")
				require.NoError(t, err, "failed to expand home directory")
				require.NotContains(t, homeDir, "~")
				return homeDir
			}(),
		},
		{
			name: "local file with architecture specified",
			cfg: Config{
				Request: "/test/local.snap",
				Platform: &image.Platform{
					Architecture: "arm64",
				},
			},
			setup: func(fs afero.Fs) {
				require.NoError(t, createMockSquashfsFile(fs, "/test/local.snap"))
			},
			wantErr: func(t assert.TestingT, err error, msgAndArgs ...any) bool {
				return assert.Error(t, err, msgAndArgs...) && assert.Contains(t, err.Error(), "architecture cannot be specified for local snap files", msgAndArgs...)
			},
			wantRequest: "/test/local.snap",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr == nil {
				tt.wantErr = assert.NoError
			}
			tt.cfg.fs = afero.NewMemMapFs() // Use an in-memory filesystem for testing
			if tt.setup != nil {
				tt.setup(tt.cfg.fs)
			}
			got, err := getLocalSnapFile(&tt.cfg)
			tt.wantErr(t, err, fmt.Sprintf("NewFromLocal(%v)", tt.cfg))
			assert.Equal(t, tt.wantRequest, tt.cfg.Request, "expected request path to match")
			if err != nil {
				require.Nil(t, got, "expected nil source on error")
				return
			}
			require.NotNil(t, got, "expected non-nil source on success")

		})
	}
}

func TestNewFromPathOnResolverError(t *testing.T) {
	tests := []struct {
		name string
		// remote snaps carry a cleanup closure for the temp directory holding the download; local snaps
		// have none, since the file belongs to the user
		remote          bool
		wantCleanupRuns int
		wantFileRemoved bool
	}{
		{
			name:            "downloaded snap is cleaned up",
			remote:          true,
			wantCleanupRuns: 1,
			wantFileRemoved: true,
		},
		{
			name:            "local snap file is left in place",
			remote:          false,
			wantCleanupRuns: 0,
			wantFileRemoved: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// the resolver reads the squashfs from the real filesystem, so the payload must live on disk
			tempDir := t.TempDir()
			snapPath := filepath.Join(tempDir, "not-really-a-snap.snap")
			require.NoError(t, os.WriteFile(snapPath, []byte("not squashfs"), 0600))

			var cleanupRuns int
			f := &snapFile{
				Path:     snapPath,
				MimeType: "text/plain",
			}
			if tt.remote {
				f.Cleanup = func() error {
					cleanupRuns++
					return os.RemoveAll(tempDir)
				}
			}

			got, err := newFromPath(Config{Request: snapPath}, f)

			require.Error(t, err)
			assert.Contains(t, err.Error(), "unable to create snap file resolver")

			// a source returned alongside an error is discarded by callers without being closed, which
			// would leave the downloaded snap behind
			assert.Nil(t, got, "expected nil source on error")
			assert.Equal(t, tt.wantCleanupRuns, cleanupRuns)

			_, statErr := os.Stat(snapPath)
			if tt.wantFileRemoved {
				assert.True(t, os.IsNotExist(statErr), "snap file was not cleaned up")
			} else {
				assert.NoError(t, statErr, "the user's snap file must never be removed")
			}
		})
	}
}
