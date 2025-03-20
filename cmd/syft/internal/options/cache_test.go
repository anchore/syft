package options

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/adrg/xdg"
	"github.com/stretchr/testify/require"

	"github.com/anchore/go-homedir"
	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/cache"
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

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			restoreCache(t)

			for k, v := range test.env {
				patchEnv(t, k, v)
			}
			xdg.Reload()

			got := defaultDir()

			require.True(t, strings.HasPrefix(got, test.expected))
		})
	}
}

func Test_cacheOptions(t *testing.T) {
	tmp := t.TempDir()
	tests := []struct {
		name string
		opts Cache
		test func(t *testing.T)
	}{
		{
			name: "disable-1",
			opts: Cache{
				Dir: "some-dir",
				TTL: "0",
			},
			test: func(t *testing.T) {
				c := cache.GetManager().GetCache("test-disable-1", "v-disable-1")
				err := c.Write("key-disable-1", strings.NewReader("some-value-disable-1"))
				require.NoError(t, err)
				rdr, err := c.Read("key-disable-1")
				require.Nil(t, rdr)
				require.Error(t, err)
			},
		},
		{
			name: "disable-2",
			opts: Cache{
				Dir: "some-dir",
				TTL: "0s",
			},
			test: func(t *testing.T) {
				c := cache.GetManager().GetCache("test-disable-2", "v-disable-2")
				err := c.Write("key-disable-2", strings.NewReader("some-value-disable-2"))
				require.NoError(t, err)
				rdr, err := c.Read("key-disable-2")
				require.Nil(t, rdr)
				require.Error(t, err)
			},
		},

		{
			name: "disable-3",
			opts: Cache{
				Dir: "some-dir",
				TTL: "0d",
			},
			test: func(t *testing.T) {
				c := cache.GetManager().GetCache("test-disable-3", "v-disable-3")
				err := c.Write("key-disable-3", strings.NewReader("some-value-disable-3"))
				require.NoError(t, err)
				rdr, err := c.Read("key-disable-3")
				require.Nil(t, rdr)
				require.Error(t, err)
			},
		},
		{
			name: "in-memory",
			opts: Cache{
				Dir: "",
				TTL: "10m",
			},
			test: func(t *testing.T) {
				c := cache.GetManager().GetCache("test-mem", "v-mem")
				err := c.Write("key-mem", strings.NewReader("some-value-mem"))
				require.NoError(t, err)
				rdr, err := c.Read("key-mem")
				require.NotNil(t, rdr)
				defer internal.CloseAndLogError(rdr, "")
				require.NoError(t, err)
				data, err := io.ReadAll(rdr)
				require.NoError(t, err)
				require.Equal(t, "some-value-mem", string(data))
				require.NoDirExists(t, filepath.Join("test-mem", "v-mem"))
			},
		},
		{
			name: "on disk",
			opts: Cache{
				Dir: tmp,
				TTL: "10m",
			},
			test: func(t *testing.T) {
				c := cache.GetManager().GetCache("test-disk", "v-disk")
				err := c.Write("key-disk", strings.NewReader("some-value-disk"))
				require.NoError(t, err)
				rdr, err := c.Read("key-disk")
				require.NotNil(t, rdr)
				defer internal.CloseAndLogError(rdr, "")
				require.NoError(t, err)
				data, err := io.ReadAll(rdr)
				require.NoError(t, err)
				require.Equal(t, "some-value-disk", string(data))
				require.DirExists(t, filepath.Join(tmp, "test-disk", "v-disk"))
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			original := cache.GetManager()
			defer cache.SetManager(original)

			err := test.opts.PostLoad()
			require.NoError(t, err)

			test.test(t)
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
			duration: "0d",
			expect:   0,
		},
		{
			duration: "0m",
			expect:   0,
		},
		{
			duration: "0s",
			expect:   0,
		},
		{
			duration: "0",
			expect:   0,
		},
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
			} else {
				require.NoError(t, err)
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

// restoreCache ensures cache settings are restored after test
func restoreCache(t testing.TB) {
	t.Helper()
	origEnabled := homedir.CacheEnabled()

	t.Cleanup(func() {
		homedir.SetCacheEnable(origEnabled)
		homedir.Reset()
	})
}

// patchEnv modifies an environment variable for the duration of the test
func patchEnv(t testing.TB, key, value string) {
	t.Helper()
	original := os.Getenv(key)

	if value != "" {
		os.Setenv(key, value)
	} else {
		os.Unsetenv(key)
	}

	t.Cleanup(func() {
		if original != "" {
			os.Setenv(key, original)
		} else {
			os.Unsetenv(key)
		}
		xdg.Reload()
	})
}
