package golang

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/go-homedir"
)

func Test_Config(t *testing.T) {
	type opts struct {
		local     bool
		cacheDir  string
		vendorDir string
		remote    bool
		proxy     string
		noProxy   string
	}

	restoreCache(t)
	homedir.SetCacheEnable(false)

	allEnv := map[string]string{
		"HOME":      "/usr/home",
		"GOPATH":    "",
		"GOPROXY":   "",
		"GOPRIVATE": "",
		"GONOPROXY": "",
	}

	tests := []struct {
		name     string
		env      map[string]string
		opts     opts
		expected CatalogerConfig
	}{
		{
			name: "set via env defaults",
			env: map[string]string{
				"GOPATH":    "/go",
				"GOPROXY":   "https://my.proxy",
				"GOPRIVATE": "my.private",
				"GONOPROXY": "no.proxy",
			},
			opts: opts{
				// defaults to $cwd/vendor, we need to set it to make the output predictable
				vendorDir: "/vendor",
			},
			expected: CatalogerConfig{
				SearchLocalModCacheLicenses: false,
				LocalModCacheDir:            filepath.Join("/go", "pkg", "mod"),
				SearchLocalVendorLicenses:   false,
				LocalVendorDir:              "/vendor",
				SearchRemoteLicenses:        false,
				Proxies:                     []string{"https://my.proxy"},
				NoProxy:                     []string{"my.private", "no.proxy"},
				MainModuleVersion:           DefaultMainModuleVersionConfig(),
			},
		},
		{
			name: "set via configuration",
			env: map[string]string{
				"GOPATH":    "/go",
				"GOPROXY":   "https://my.proxy",
				"GOPRIVATE": "my.private",
				"GONOPROXY": "no.proxy",
			},
			opts: opts{
				local:     true,
				cacheDir:  "/go-cache",
				vendorDir: "/vendor",
				remote:    true,
				proxy:     "https://alt.proxy,direct",
				noProxy:   "alt.no.proxy",
			},
			expected: CatalogerConfig{
				SearchLocalModCacheLicenses: true,
				LocalModCacheDir:            "/go-cache",
				SearchLocalVendorLicenses:   true,
				LocalVendorDir:              "/vendor",
				SearchRemoteLicenses:        true,
				Proxies:                     []string{"https://alt.proxy", "direct"},
				NoProxy:                     []string{"alt.no.proxy"},
				MainModuleVersion:           DefaultMainModuleVersionConfig(),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for k, v := range allEnv {
				t.Setenv(k, v)
			}
			for k, v := range test.env {
				t.Setenv(k, v)
			}
			got := DefaultCatalogerConfig().
				WithSearchLocalModCacheLicenses(test.opts.local).
				WithLocalModCacheDir(test.opts.cacheDir).
				WithSearchLocalVendorLicenses(test.opts.local).
				WithLocalVendorDir(test.opts.vendorDir).
				WithSearchRemoteLicenses(test.opts.remote).
				WithProxy(test.opts.proxy).
				WithNoProxy(test.opts.noProxy)

			assert.Equal(t, test.expected, got)
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
