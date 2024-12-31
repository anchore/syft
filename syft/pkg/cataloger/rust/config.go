package rust

import (
	"fmt"
	"net/http"
	"net/url"
	"runtime/debug"
	"time"

	"github.com/anchore/syft/internal/log"
)

type CatalogerConfig struct {
	InsecureSkipTLSVerify bool          `yaml:"insecure-skip-tls-verify" json:"insecure-skip-tls-verify" mapstructure:"insecure-skip-tls-verify"`
	UseCratesEnrichment   bool          `json:"use-crates-enrichment" yaml:"use-crates-enrichment" mapstructure:"use-crates-enrichment"`
	Proxy                 string        `yaml:"proxy,omitempty" json:"proxy,omitempty" mapstructure:"proxy"`
	CratesTimeout         time.Duration `yaml:"crates-timeout" json:"crates-timeout" mapstructure:"crates-timeout"`
	proxyURL              *url.URL
}

// DefaultCatalogerConfig create a CatalogerConfig with default options, which includes:
// SearchCratesLicenses: false
// Proxy: GOPROXY
func DefaultCatalogerConfig() CatalogerConfig {
	return CatalogerConfig{
		InsecureSkipTLSVerify: false,
		UseCratesEnrichment:   false,
		Proxy:                 "",
		CratesTimeout:         10 * time.Second,
	}
}

// WithInsecureSkipTLSVerify configures the rust cataloger to skip verifying the TLS
// certificate when communicating with crates.io.  This is useful when working
// behind a corporate proxy that intercepts traffic.  Note that this option
// is not recommended as it can expose the cataloger to man-in-the-middle attacks.
func (c CatalogerConfig) WithInsecureSkipTLSVerify(input bool) CatalogerConfig {
	c.InsecureSkipTLSVerify = input
	return c
}

// WithUseCratesEnrichment configures the rust cataloger to use crates.io information
// to enrich package metadata.  If set to true, the cataloger will use the crates.io
// API to fetch additional information about packages, such as the package summary,
// homepage, and license.  This may be disabled if network access is not available.
func (c CatalogerConfig) WithUseCratesEnrichment(input bool) CatalogerConfig {
	c.UseCratesEnrichment = input
	return c
}

// WithProxy sets the proxy URL for the rust cataloger to use.
// If an empty string is provided, the proxy will be set to the value of the
// HTTP_PROXY or HTTPS_PROXY environment variable, if set.  If the environment
// variable is not set, the proxy will be set to the default ("direct").
func (c CatalogerConfig) WithProxy(input string) CatalogerConfig {
	if input == "" {
		// test to see if environment variables have been set.
		req, err := http.NewRequest("GET", "https://crates.io/api/v1", nil)
		if err != nil {
			log.Errorf("rust cataloger configuration error: %s", err)
		}
		// ProxyFromEnvironment only runs once, if the proxy changes it will not be updated.
		proxy, err := http.ProxyFromEnvironment(req)
		if err != nil {
			log.Errorf("rust cataloger configuration error: %s", err)
		}
		if proxy != nil {
			c.proxyURL = proxy
			return c
		}
		// keep default no proxy.
		return c
	}
	proxy, err := url.Parse(input)
	fmt.Println(proxy, err)
	if err != nil {
		log.Errorf("rust cataloger configuration includes invalid proxy url: %s", input)
		panic(err)
	}
	c.proxyURL = proxy
	return c
}

func (c CatalogerConfig) WithCratesTimeout(input time.Duration) CatalogerConfig {
	c.CratesTimeout = input
	return c
}

// syftVersion returns the version of the syft codebase if it is a release build.
// If syft is built from source, it returns "(devel)".
func syftVersion() string {
	// logic copied from syft/syft/create_sbom_config.go
	buildInfo, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}

	for _, d := range buildInfo.Deps {
		if d.Path == "github.com/anchore/syft" && d.Version != "(devel)" {
			return d.Version
		}
	}

	return "(devel)"
}
