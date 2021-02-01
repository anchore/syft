package anchore

import (
	"context"
	"fmt"
	"strings"

	"github.com/anchore/client-go/pkg/external"
	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/version"
)

type Configuration struct {
	BasePath  string
	Username  string
	Password  string
	UserAgent string
}

type Client struct {
	config Configuration
	client *external.APIClient
}

func NewClient(cfg Configuration) (*Client, error) {
	if cfg.UserAgent == "" {
		versionInfo := version.FromBuild()
		// format: product / product-version comment
		cfg.UserAgent = fmt.Sprintf("%s / %s %s", internal.ApplicationName, versionInfo.Version, versionInfo.Platform)
	}

	basePath := ensureURLHasScheme(cfg.BasePath) // we can rely on the built-in URL parsing for the scheme, host,
	// port, and path prefix, as long as a scheme is present

	return &Client{
		config: cfg,
		client: external.NewAPIClient(&external.Configuration{
			BasePath:  basePath,
			UserAgent: cfg.UserAgent,
		}),
	}, nil
}

func (c *Client) newRequestContext(parentContext context.Context) context.Context {
	if parentContext == nil {
		parentContext = context.Background()
	}
	return context.WithValue(
		parentContext,
		external.ContextBasicAuth,
		external.BasicAuth{
			UserName: c.config.Username,
			Password: c.config.Password,
		},
	)
}

func hasScheme(url string) bool {
	parts := strings.Split(url, "://")

	return len(parts) > 1
}

func ensureURLHasScheme(url string) string {
	const defaultScheme = "http"

	if !hasScheme(url) {
		return fmt.Sprintf("%s://%s", defaultScheme, url)
	}

	return url
}
