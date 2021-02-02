package anchore

import (
	"context"
	"errors"
	"fmt"
	"path"
	"strings"
	"unicode"

	"github.com/anchore/client-go/pkg/external"
	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/version"
)

type Configuration struct {
	BaseURL   string
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

	baseURL, err := prepareBaseURLForClient(cfg.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("unable to create client: %w", err)
	}

	return &Client{
		config: cfg,
		client: external.NewAPIClient(&external.Configuration{
			BasePath:  baseURL,
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

var ErrInvalidBaseURLInput = errors.New("invalid base URL input")

func prepareBaseURLForClient(baseURL string) (string, error) {
	if err := checkBaseURLInput(baseURL); err != nil {
		return "", err
	}

	scheme, urlWithoutScheme := splitSchemeFromURL(baseURL)

	if scheme == "" {
		scheme = "http"
	}

	urlWithoutScheme = path.Clean(urlWithoutScheme)

	const requiredSuffix = "v1"
	if path.Base(urlWithoutScheme) != requiredSuffix {
		urlWithoutScheme = path.Join(urlWithoutScheme, requiredSuffix)
	}

	preparedBaseURL := scheme + "://" + urlWithoutScheme
	return preparedBaseURL, nil
}

func checkBaseURLInput(url string) error {
	if url == "" {
		return ErrInvalidBaseURLInput
	}

	firstCharacter := rune(url[0])
	if !(unicode.IsLetter(firstCharacter)) {
		return ErrInvalidBaseURLInput
	}

	return nil
}

func splitSchemeFromURL(url string) (scheme, urlWithoutScheme string) {
	if hasScheme(url) {
		urlParts := strings.SplitN(url, "://", 2)
		scheme = urlParts[0]
		urlWithoutScheme = urlParts[1]
		return
	}

	return "", url
}

func hasScheme(url string) bool {
	parts := strings.Split(url, "://")

	return len(parts) > 1
}
