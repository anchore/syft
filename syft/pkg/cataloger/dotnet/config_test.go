package dotnet

import (
	"testing"

	"github.com/mitchellh/go-homedir"
	"github.com/stretchr/testify/assert"
)

func Test_Config(t *testing.T) {
	type opts struct {
		local       *bool
		remote      *bool
		providers   *string
		credentials *string
	}

	trueVal := true
	falseVal := false
	optProvider := "https://www.nuget.org/api/v2/package"
	optCredentials := "johnDoe:1234567890"

	homedirCacheDisabled := homedir.DisableCache
	homedir.DisableCache = true
	t.Cleanup(func() {
		homedir.DisableCache = homedirCacheDisabled
	})

	allEnv := map[string]string{
		"HOME":                               "/usr/home",
		"NUGET_SEARCH_LOCAL_LICENSES":        "",
		"NUGET_SEARCH_REMOTE_LICENSES":       "",
		"NUGET_PACKAGE_PROVIDERS":            "",
		"NUGET_PACKAGE_PROVIDER_CREDENTIALS": "",
	}

	tests := []struct {
		name     string
		env      map[string]string
		opts     opts
		expected CatalogerConfig
	}{
		{
			name: "absolute defaults",
			env:  map[string]string{},
			opts: opts{},
			expected: CatalogerConfig{
				SearchLocalLicenses:  false,
				SearchRemoteLicenses: false,
				Providers:            []string{"https://api.nuget.org/v3-flatcontainer/"},
				ProviderCredentials:  []nugetProviderCredential{},
			},
		},
		{
			name: "set via env defaults",
			env: map[string]string{
				"NUGET_SEARCH_LOCAL_LICENSES":        "true",
				"NUGET_SEARCH_REMOTE_LICENSES":       "false",
				"NUGET_PACKAGE_PROVIDERS":            "https://my.proxy",
				"NUGET_PACKAGE_PROVIDER_CREDENTIALS": "user:password",
			},
			opts: opts{},
			expected: CatalogerConfig{
				SearchLocalLicenses:  true,
				SearchRemoteLicenses: false,
				Providers:            []string{"https://my.proxy"},
				ProviderCredentials: []nugetProviderCredential{
					{
						Username: "user",
						Password: "password",
					},
				},
			},
		},
		{
			name: "set via configuration",
			env: map[string]string{
				"NUGET_SEARCH_LOCAL_LICENSES":        "true",
				"NUGET_SEARCH_REMOTE_LICENSES":       "false",
				"NUGET_PACKAGE_PROVIDERS":            "https://my.proxy",
				"NUGET_PACKAGE_PROVIDER_CREDENTIALS": "user:password",
			},
			opts: opts{
				local:       &falseVal,
				remote:      &trueVal,
				providers:   &optProvider,
				credentials: &optCredentials,
			},
			expected: CatalogerConfig{
				SearchLocalLicenses:  false,
				SearchRemoteLicenses: true,
				Providers:            []string{"https://www.nuget.org/api/v2/package"},
				ProviderCredentials: []nugetProviderCredential{
					{
						Username: "johnDoe",
						Password: "1234567890",
					},
				},
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
			got := DefaultCatalogerConfig()

			if test.opts.local != nil {
				got = got.WithSearchLocalLicenses(*test.opts.local)
			}
			if test.opts.remote != nil {
				got = got.WithSearchRemoteLicenses(*test.opts.remote)
			}
			if test.opts.providers != nil {
				got = got.WithProviders(*test.opts.providers)
			}
			if test.opts.credentials != nil {
				got = got.WithCredentials(*test.opts.credentials)
			}

			assert.Equal(t, test.expected, got)
		})
	}
}
