package options

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

func Test_parseDuration(t *testing.T) {
	tests := []struct {
		duration string
		expect   time.Duration
		err      require.ErrorAssertionFunc
	}{
		{
			duration: "1d",
			expect:   24 * time.Hour,
		},
		{
			duration: "7d",
			expect:   7 * 24 * time.Hour,
		},
		{
			duration: "365D",
			expect:   365 * 24 * time.Hour,
		},
		{
			duration: "7d1h1m1s",
			expect:   7*24*time.Hour + time.Hour + time.Minute + time.Second,
		},
		{
			duration: "7d  1h 1m 1s",
			expect:   7*24*time.Hour + time.Hour + time.Minute + time.Second,
		},
		{
			duration: "2h",
			expect:   2 * time.Hour,
		},
		{
			duration: "2h5m",
			expect:   2*time.Hour + 5*time.Minute,
		},
		{
			duration: "2h 5m",
			expect:   2*time.Hour + 5*time.Minute,
		},
		{
			duration: "d24h",
			err:      require.Error,
		},
	}

	for _, test := range tests {
		t.Run(test.duration, func(t *testing.T) {
			got, err := parseDuration(test.duration)
			if test.err != nil {
				test.err(t, err)
				return
			}
			require.Equal(t, test.expect, got)
		})
	}
}

func Test_durationToString(t *testing.T) {
	tests := []struct {
		duration time.Duration
		expect   string
		err      require.ErrorAssertionFunc
	}{
		{
			expect:   "1d",
			duration: 24 * time.Hour,
		},
		{
			expect:   "7d",
			duration: 7 * 24 * time.Hour,
		},
		{
			expect:   "7d1h1m1s",
			duration: 7*24*time.Hour + time.Hour + time.Minute + time.Second,
		},
		{
			expect:   "2h0m0s",
			duration: 2 * time.Hour,
		},
		{
			expect:   "2h5m0s",
			duration: 2*time.Hour + 5*time.Minute,
		},
	}

	for _, test := range tests {
		t.Run(test.expect, func(t *testing.T) {
			got := durationToString(test.duration)
			require.Equal(t, test.expect, got)
		})
	}
}
