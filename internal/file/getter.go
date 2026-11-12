package file

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"

	"github.com/wagoodman/go-progress"

	"github.com/anchore/clio"
)

type Getter interface {
	// GetFile downloads the given http or https URL into the given path. The URL must reference a single file.
	GetFile(dst, src string, monitor ...*progress.Manual) error
}

// HTTPGetter downloads files over http and https with net/http.
type HTTPGetter struct {
	client    *http.Client
	userAgent string
}

// NewGetter creates and returns a new Getter. Providing an http.Client is optional; if none is provided,
// http.DefaultClient is used.
func NewGetter(id clio.Identification, httpClient *http.Client) *HTTPGetter {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &HTTPGetter{
		client:    httpClient,
		userAgent: fmt.Sprintf("%v %v", id.Name, id.Version),
	}
}

func (g HTTPGetter) GetFile(dst, src string, monitors ...*progress.Manual) (err error) {
	if len(monitors) > 1 {
		return fmt.Errorf("multiple monitors provided, which is not allowed")
	}

	u, err := url.Parse(src)
	if err != nil {
		return fmt.Errorf("bad URL provided %q: %w", src, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("unsupported URL scheme %q: only http and https are supported", u.Scheme)
	}

	req, err := http.NewRequest(http.MethodGet, src, nil)
	if err != nil {
		return fmt.Errorf("unable to create request for %q: %w", src, err)
	}
	req.Header.Set("User-Agent", g.userAgent)

	resp, err := g.client.Do(req)
	if err != nil {
		return fmt.Errorf("unable to download %q: %w", src, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unable to download %q: bad response status: %s", src, resp.Status)
	}

	if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
		return fmt.Errorf("unable to create destination directory: %w", err)
	}

	f, err := os.Create(dst)
	if err != nil {
		return fmt.Errorf("unable to create destination file: %w", err)
	}
	defer func() {
		if closeErr := f.Close(); err == nil && closeErr != nil {
			err = fmt.Errorf("unable to close destination file: %w", closeErr)
		}
	}()

	var body io.Reader = resp.Body
	if len(monitors) == 1 {
		monitor := monitors[0]
		monitor.SetTotal(resp.ContentLength)
		body = progress.NewProxyReader(resp.Body, monitor)
	}

	if _, err := io.Copy(f, body); err != nil {
		return fmt.Errorf("unable to download %q: %w", src, err)
	}
	return nil
}
