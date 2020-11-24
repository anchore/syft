package anchore

import (
	"context"
	"fmt"

	"github.com/anchore/client-go/pkg/external"
	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/version"
)

type Configuration struct {
	Hostname  string
	Username  string
	Password  string
	UserAgent string
	Scheme    string
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

	if cfg.Scheme == "" {
		cfg.Scheme = "https"
	}

	return &Client{
		config: cfg,
		client: external.NewAPIClient(&external.Configuration{
			Host:      cfg.Hostname,
			UserAgent: cfg.UserAgent,
			Scheme:    cfg.Scheme,
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
