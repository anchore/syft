package options

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/adrg/xdg"
	"github.com/mitchellh/go-homedir"
	"github.com/stretchr/testify/require"
)

func Test_defaultDir(t *testing.T) {
	tmpDir := filepath.Join(t.TempDir(), "cache-temp")
	xdgCacheDir := filepath.Join(tmpDir, "fake-xdg-cache")
	homeDir := filepath.Join(tmpDir, "fake-home")

	tests := []struct {
		name     string
		env      map[string]string
		expected string
	}{
		{
			name: "no-xdg",
			env: map[string]string{
				"HOME": homeDir,
			},
			expected: homeDir,
		},
		{
			name: "xdg-cache",
			env: map[string]string{
				"XDG_CACHE_HOME": xdgCacheDir,
			},
			expected: xdgCacheDir,
		},
	}

	// capture all the initial environment variables to reset them before we reset library caches
	env := map[string]string{
		"HOME":            "",
		"XDG_DATA_HOME":   "",
		"XDG_DATA_DIRS":   "",
		"XDG_CONFIG_HOME": "",
		"XDG_CONFIG_DIRS": "",
		"XDG_STATE_HOME":  "",
		"XDG_CACHE_HOME":  "",
		"XDG_RUNTIME_DIR": "",
	}
	for k := range env {
		env[k] = os.Getenv(k)
	}

	unsetEnv := func(t *testing.T) {
		for k := range env {
			t.Setenv(k, "")
		}
	}

	resetEnv := func() {
		for k, v := range env {
			if v == "" {
				_ = os.Unsetenv(k)
			} else {
				_ = os.Setenv(k, v)
			}
		}
		homedir.Reset()
		xdg.Reload()
	}

	t.Cleanup(resetEnv)

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			defer resetEnv()

			unsetEnv(t)
			for k, v := range test.env {
				t.Setenv(k, v)
			}
			homedir.Reset()
			xdg.Reload()

			got := defaultDir()

			require.True(t, strings.HasPrefix(got, test.expected))
		})
	}
}
