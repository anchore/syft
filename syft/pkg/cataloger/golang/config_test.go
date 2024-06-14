package golang

import (
	"path/filepath"
	"testing"

	"github.com/mitchellh/go-homedir"
	"github.com/stretchr/testify/assert"
)

func Test_Config(t *testing.T) {
	type opts struct {
		local    bool
		cacheDir string
		remote   bool
		proxy    string
		noProxy  string
	}

	homedirCacheDisabled := homedir.DisableCache
	homedir.DisableCache = true
	t.Cleanup(func() {
		homedir.DisableCache = homedirCacheDisabled
	})

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
			opts: opts{},
			expected: CatalogerConfig{
				SearchLocalModCacheLicenses: false,
				LocalModCacheDir:            filepath.Join("/go", "pkg", "mod"),
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
				local:    true,
				cacheDir: "/go-cache",
				remote:   true,
				proxy:    "https://alt.proxy,direct",
				noProxy:  "alt.no.proxy",
			},
			expected: CatalogerConfig{
				SearchLocalModCacheLicenses: true,
				LocalModCacheDir:            "/go-cache",
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
				WithSearchRemoteLicenses(test.opts.remote).
				WithProxy(test.opts.proxy).
				WithNoProxy(test.opts.noProxy)

			assert.Equal(t, test.expected, got)
		})
	}
}
