package snapsource

import (
	"crypto"
	"fmt"
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
			wantErr: func(t assert.TestingT, err error, msgAndArgs ...interface{}) bool {
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
