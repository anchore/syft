package dotnet

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultProvider = "https://api.nuget.org/v3-flatcontainer/"
)

var (
	httpClient = &http.Client{
		Timeout: time.Second * 5,
	}

	defaultProvidersMutex sync.Mutex
	defaultProviders      = ""
)

type Credential struct {
	Username string `yaml:"username" json:"username" mapstructure:"username"`
	Password string `yaml:"password" json:"password" mapstructure:"password"`
}

type CatalogerConfig struct {
	SearchLocalLicenses  bool         `yaml:"search-local-licenses" json:"search-local-licenses" mapstructure:"search-local-licenses"`
	SearchRemoteLicenses bool         `yaml:"search-remote-licenses" json:"search-remote-licenses" mapstructure:"search-remote-licenses"`
	Providers            []string     `yaml:"package-providers,omitempty" json:"package-providers,omitempty" mapstructure:"package-providers"`
	ProviderCredentials  []Credential `yaml:"package-provider-credentials,omitempty" json:"package-provider-credentials,omitempty" mapstructure:"package-provider-credentials"`
}

// DefaultCatalogerConfig create a CatalogerConfig with default options, which includes:
// - setting the default remote package providers if none are provided
func DefaultCatalogerConfig() CatalogerConfig {
	g := CatalogerConfig{
		SearchLocalLicenses:  false,
		SearchRemoteLicenses: false,
		Providers:            []string{},
		ProviderCredentials:  []Credential{},
	}

	nuget := os.Getenv("NUGET_SEARCH_LOCAL_LICENSES")
	if value, err := strconv.ParseBool(nuget); err == nil {
		g = g.WithSearchLocalLicenses(value)
	}

	remote := os.Getenv("NUGET_SEARCH_REMOTE_LICENSES")
	if value, err := strconv.ParseBool(remote); err == nil {
		g = g.WithSearchRemoteLicenses(value)
	}

	// process the Nuget package repository settings (for remote search)
	nugetProviders := os.Getenv("NUGET_PACKAGE_PROVIDERS")
	if nugetProviders == "" {
		nugetProviders = getDefaultProviders()
	}
	g = g.WithProviders(nugetProviders)

	// process the Nuget package repository credential settings (for remote search)
	g = g.WithCredentials(os.Getenv("NUGET_PACKAGE_PROVIDER_CREDENTIALS"))

	return g
}

func (g CatalogerConfig) WithSearchLocalLicenses(input bool) CatalogerConfig {
	g.SearchLocalLicenses = input
	return g
}

func (g CatalogerConfig) WithSearchRemoteLicenses(input bool) CatalogerConfig {
	g.SearchRemoteLicenses = input
	return g
}

func (g CatalogerConfig) WithProviders(input string) CatalogerConfig {
	if input == "" {
		return g
	}
	g.Providers = strings.Split(input, ",")
	return g
}

func (g CatalogerConfig) WithCredentials(input string) CatalogerConfig {
	if input == "" {
		return g
	}
	g.ProviderCredentials = []Credential{}
	credentials := strings.Split(input, ",")
	for _, credential := range credentials {
		if credentialParts := strings.Split(credential, ":"); len(credentialParts) == 2 {
			g.ProviderCredentials = append(g.ProviderCredentials, Credential{
				Username: credentialParts[0],
				Password: credentialParts[1],
			})
		}
	}
	return g
}

type sourceAPIResource struct {
	ID      string `json:"@id"`
	Type    string `json:"@type"`
	Comment string `json:"comment,omitempty"`
}

type sourceAPIContext struct {
	Vocab   string `json:"@vocab"`
	Comment string `json:"comment,omitempty"`
}

type sourceAPI struct {
	Version   string              `json:"version"`
	Resources []sourceAPIResource `json:"resources"`
	Context   *sourceAPIContext   `json:"@context,omitempty"`
}

func determineDotnetExecutablePath() (string, error) {
	dotnetPath := ""
	var err error
	if runtime.GOOS == "windows" {
		dotnetPath, err = exec.LookPath("dotnet.exe")
	} else {
		dotnetPath, err = exec.LookPath("dotnet")
	}

	if errors.Is(err, exec.ErrDot) {
		err = nil
	}

	return dotnetPath, err
}

func getPackageSourcesFromSDK(includeDisabledSources bool) []string {
	// Try to find enabled remote nuget package sources
	packageSources := []string{}

	if dotnetPath, err := determineDotnetExecutablePath(); err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()

		cmd := exec.CommandContext(ctx, dotnetPath, "nuget", "list", "source", "--format", "Short")
		if stdout, err := cmd.StdoutPipe(); err == nil {
			if err := cmd.Start(); err == nil {
				if data, err := io.ReadAll(stdout); err == nil {
					lines := strings.Split(string(data), "\n")
					for _, line := range lines {
						line = strings.TrimSpace(line)
						// Expect something like
						// E https://api.nuget.org/v3/index.json
						// or
						// D https://api.nuget.org/v3/index.json

						// Only enabled sources
						if strings.HasPrefix(line, "E ") || (strings.HasPrefix(line, "D ") && includeDisabledSources) {
							packageSource := strings.TrimSpace(line[2:])
							if strings.HasPrefix(packageSource, "https://") {
								found := false
								for _, knownSource := range packageSources {
									if packageSource == knownSource {
										found = true
									}
								}
								if !found {
									packageSources = append(packageSources, packageSource)
								}
							}
						}
					}
				}
			}
		}
	}

	return packageSources
}

func getDefaultProviders() string {
	defaultProvidersMutex.Lock()
	defer defaultProvidersMutex.Unlock()

	if defaultProviders != "" {
		return defaultProviders
	}

	defaultProviders = defaultProvider

	packageSources := getPackageSourcesFromSDK(false)

	if len(packageSources) > 0 {
		providers := []string{}

		for _, packageSource := range packageSources {
			// Test the availability of the external package providers
			if response, err := httpClient.Get(packageSource); err == nil && response.StatusCode == http.StatusOK {
				apiData, err := io.ReadAll(response.Body)
				response.Body.Close()

				if err == nil {
					api := sourceAPI{}
					if err = json.Unmarshal(apiData, &api); err == nil {
						// Find all (NuGet) package resources of the API
						for _, apiResource := range api.Resources {
							// cf. https://learn.microsoft.com/en-us/nuget/api/overview#resources-and-schema
							if strings.HasPrefix(apiResource.Type, "PackageBaseAddress/") {
								providers = append(providers, apiResource.ID)
							}
						}
					}
				}
			}
		}

		if len(providers) > 0 {
			defaultProviders = strings.Join(providers, ",")
		}
	}

	return defaultProviders
}
