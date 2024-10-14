package dotnet

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

const (
	defaultProvider = "https://www.nuget.org/api/v2/package"
)

type CatalogerConfig struct {
	SearchLocalLicenses  bool     `yaml:"search-local-licenses" json:"search-local-licenses" mapstructure:"search-local-licenses"`
	SearchRemoteLicenses bool     `yaml:"search-remote-licenses" json:"search-remote-licenses" mapstructure:"search-remote-licenses"`
	Providers            []string `yaml:"package-providers,omitempty" json:"package-providers,omitempty" mapstructure:"package-providers"`
}

// DefaultCatalogerConfig create a CatalogerConfig with default options, which includes:
// - setting the default remote proxy if none is provided
// - setting the default no proxy if none is provided
// - setting the default local module cache dir if none is provided
func DefaultCatalogerConfig() CatalogerConfig {
	g := CatalogerConfig{}

	nuget := os.Getenv("NUGET_SEARCH_LOCAL_LICENSES")
	if value, err := strconv.ParseBool(nuget); err == nil {
		g = g.WithSearchLocalLicenses(value)
	}

	remote := os.Getenv("NUGET_SEARCH_REMOTE_LICENSES")
	if value, err := strconv.ParseBool(remote); err == nil {
		g = g.WithSearchRemoteLicenses(value)
	}

	// process the proxy settings (for remote search)
	if len(g.Providers) == 0 {
		nugetProviders := os.Getenv("NUGET_PACKAGE_PROVIDERS")
		if nugetProviders == "" {
			nugetProviders = getDefaultProviders()
		}
		g = g.WithProviders(nugetProviders)
	}

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

type sourceApiResource struct {
	ID      string `json:"@id"`
	Type    string `json:"@type"`
	Comment string `json:"comment,omitempty"`
}

type sourceApiContext struct {
	Vocab   string `json:"@vocab"`
	Comment string `json:"comment,omitempty"`
}

type sourceApi struct {
	Version   string              `json:"version"`
	Resources []sourceApiResource `json:"resources"`
	Context   *sourceApiContext   `json:"@context,omitempty"`
}

func getDefaultProviders() string {
	// Try to find enabled remote nuget package sources
	packageSources := []string{}
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	cmd := exec.CommandContext(ctx, "dotnet", "nuget", "list", "source", "--format", "Short")
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
					if strings.HasPrefix(line, "E ") {
						packageSource := strings.TrimSpace(line[2:])
						if strings.HasPrefix(packageSource, "https://") {
							found := false
							if !found {
								packageSources = append(packageSources, packageSource)
							}
						}
					}
				}
			}
		}
	}
	cancel()
	if len(packageSources) > 0 {
		providers := []string{}
		for _, packageSource := range packageSources {
			if response, err := http.Get(packageSource); err == nil && response.StatusCode == http.StatusOK {
				apiData, err := io.ReadAll(response.Body)
				response.Body.Close()
				if err == nil {
					api := sourceApi{}
					if err = json.Unmarshal(apiData, &api); err == nil {
						for _, apiResource := range api.Resources {
							if strings.HasSuffix(apiResource.ID, "/package") {
								providers = append(providers, apiResource.ID)
							}
						}
					}
				}
			}
		}
		if len(providers) > 0 {
			return strings.Join(providers, ",")
		}
	}

	return defaultProvider
}
