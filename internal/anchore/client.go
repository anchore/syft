package anchore

import (
	"context"
	"fmt"

	"github.com/anchore/client-go/pkg/external"
	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/version"
)

type Option func(*Client) error

type Client struct {
	config    external.Configuration
	username  string
	password  string
	sessionID string
	client    *external.APIClient
}

func NewClient(host string, options ...Option) (*Client, error) {
	// create the client and default configuration object
	theClient := &Client{
		config: external.Configuration{
			Host:      host,
			UserAgent: defaultUserAgent(),
		},
	}

	// apply all given options
	for _, option := range options {
		err := option(theClient)
		if err != nil {
			return nil, err
		}
	}

	// create external client
	theClient.client = external.NewAPIClient(&theClient.config)

	return theClient, nil
}

func WithUserAgent(userAgent string) Option {
	return func(c *Client) error {
		c.config.UserAgent = userAgent
		return nil
	}
}

func WithCredentials(username, password string) Option {
	return func(c *Client) error {
		c.username = username
		c.password = password
		return nil
	}
}

func WithSessionID(sessionID string) Option {
	return func(c *Client) error {
		c.sessionID = sessionID
		return nil
	}
}

func (c *Client) newRequestContext(parentContext context.Context) context.Context {
	if parentContext == nil {
		parentContext = context.Background()
	}
	return context.WithValue(
		parentContext,
		external.ContextBasicAuth,
		external.BasicAuth{
			UserName: c.username,
			Password: c.password,
		},
	)
}

func defaultUserAgent() string {
	// format: product / product-version comment
	versionInfo := version.FromBuild()
	return fmt.Sprintf("%s / %s %s", internal.ApplicationName, versionInfo.Version, versionInfo.Platform)
}
