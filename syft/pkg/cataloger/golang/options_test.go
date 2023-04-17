package golang

import (
	"testing"

	"github.com/mitchellh/go-homedir"
	"github.com/stretchr/testify/assert"
)

func Test_Options(t *testing.T) {
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
		expected GoCatalogerOpts
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
			expected: GoCatalogerOpts{
				searchLocalModCacheLicenses: false,
				localModCacheDir:            "/go/pkg/mod",
				searchRemoteLicenses:        false,
				proxies:                     []string{"https://my.proxy"},
				noProxy:                     []string{"my.private", "no.proxy"},
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
			expected: GoCatalogerOpts{
				searchLocalModCacheLicenses: true,
				localModCacheDir:            "/go-cache",
				searchRemoteLicenses:        true,
				proxies:                     []string{"https://alt.proxy", "direct"},
				noProxy:                     []string{"alt.no.proxy"},
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
			got := NewGoCatalogerOpts().
				WithSearchLocalModCacheLicenses(test.opts.local).
				WithLocalModCacheDir(test.opts.cacheDir).
				WithSearchRemoteLicenses(test.opts.remote).
				WithProxy(test.opts.proxy).
				WithNoProxy(test.opts.noProxy)

			assert.Equal(t, test.expected, got)
		})
	}
}
