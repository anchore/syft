package dotnet

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os/exec"
	"runtime"
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

type nugetProviderCredential struct {
	Username string `yaml:"username" json:"username" mapstructure:"username"`
	Password string `yaml:"password" json:"password" mapstructure:"password"`
}

type CatalogerConfig struct {
	SearchLocalLicenses  bool                      `yaml:"search-local-licenses" json:"search-local-licenses" mapstructure:"search-local-licenses"`
	LocalCachePaths      []string                  `yaml:"local-cache-paths" json:"local-cache-paths" mapstructure:"local-cache-paths"`
	SearchRemoteLicenses bool                      `yaml:"search-remote-licenses" json:"search-remote-licenses" mapstructure:"search-remote-licenses"`
	Providers            []string                  `yaml:"package-providers,omitempty" json:"package-providers,omitempty" mapstructure:"package-providers"`
	ProviderCredentials  []nugetProviderCredential `yaml:"package-provider-credentials,omitempty" json:"package-provider-credentials,omitempty" mapstructure:"package-provider-credentials"`
}

// DefaultCatalogerConfig create a CatalogerConfig with default options, which includes:
// - setting the default remote package providers if none are provided
func DefaultCatalogerConfig() CatalogerConfig {
	return CatalogerConfig{}
}

func (g CatalogerConfig) WithSearchLocalLicenses(input bool) CatalogerConfig {
	g.SearchLocalLicenses = input
	if input && len(g.LocalCachePaths) == 0 {
		g.WithLocalCachePaths(getDefaultProviders())
	}
	return g
}

func (g CatalogerConfig) WithLocalCachePaths(input string) CatalogerConfig {
	if input == "" {
		return g
	}
	g.LocalCachePaths = strings.Split(input, ",")
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
	g.ProviderCredentials = []nugetProviderCredential{}
	credentials := strings.Split(input, ",")
	for _, credential := range credentials {
		if credentialParts := strings.Split(credential, ":"); len(credentialParts) == 2 {
			g.ProviderCredentials = append(g.ProviderCredentials, nugetProviderCredential{
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
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			return packageSources
		}

		err = cmd.Start()
		if err != nil {
			return packageSources
		}

		data, err := io.ReadAll(stdout)
		if err != nil {
			return packageSources
		}

		lines := strings.Split(string(data), "\n")

		packageSources = append(packageSources, parseSDKPackageSourcePathsOutput(lines, includeDisabledSources)...)
	}

	return packageSources
}

func parseSDKPackageSourcePathsOutput(outputLines []string, includeDisabledSources bool) []string {
	packageSources := []string{}

	for _, line := range outputLines {
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
			response, err := httpClient.Get(packageSource)
			if err != nil || response.StatusCode != http.StatusOK {
				continue
			}

			apiData, err := io.ReadAll(response.Body)
			response.Body.Close()
			if err != nil {
				continue
			}

			api := sourceAPI{}
			err = json.Unmarshal(apiData, &api)
			if err != nil {
				continue
			}

			// Find all (NuGet) package resources of the API
			for _, apiResource := range api.Resources {
				// cf. https://learn.microsoft.com/en-us/nuget/api/overview#resources-and-schema
				if strings.HasPrefix(apiResource.Type, "PackageBaseAddress/") {
					providers = append(providers, apiResource.ID)
				}
			}
		}

		if len(providers) > 0 {
			defaultProviders = strings.Join(providers, ",")
		}
	}

	return defaultProviders
}