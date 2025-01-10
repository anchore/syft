package rust

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"runtime/debug"

	"github.com/anchore/syft/internal/cache"
	"github.com/anchore/syft/syft/pkg"

	"github.com/anchore/syft/internal/log"
)

type rustCratesResolver struct {
	catalogerName string       // the name of the cataloger that is using the crates resolver.
	client        *http.Client // when instantiating the resolver a http client is created.
	cratesAPI     string       // The full path to the API endpoint for crates.io excluding the package name and version.
	cratesBaseURL string       // the baseURL for crates.io, if the site is mirrored via a different hostname override the default.
	cratesCache   cache.Resolver[pkg.RustCratesEnrichedEntry]
}

// cratesRemoteMetadata represents the remote metadata for a crate
// as fetched from crates.io via an API request.
// This is used for deserialization of the response from crates.io
type cratesRemoteMetadata struct {
	Version struct {
		Checksum      string `json:"checksum"`
		Crate         string `json:"crate"`
		CreatedAt     string `json:"created_at"`
		Description   string `json:"description"`
		DownloadPath  string `json:"dl_path"`
		Documentation string `json:"documentation"`
		Homepage      string `json:"homepage"`
		License       string `json:"license"`
		Num           string `json:"num"`
		PublishedBy   struct {
			Name string `json:"name"`
			URL  string `json:"url"`
		} `json:"published_by"`
		Repository string `json:"repository"`
	} `json:"version"`
}

func newCratesResolver(name string, opts CatalogerConfig) *rustCratesResolver {
	base, err := url.Parse(opts.CratesBaseURL)
	if err != nil {
		log.Errorf("%s failed to parse crates base url: %s with error: %s", name, opts.CratesBaseURL, err)
		return &rustCratesResolver{}
	}
	baseURL := base.JoinPath("api", "v1", "crates")
	return &rustCratesResolver{
		cratesBaseURL: opts.CratesBaseURL,
		cratesAPI:     baseURL.String(),
		catalogerName: name,
		cratesCache:   cache.GetResolverCachingErrors[pkg.RustCratesEnrichedEntry]("crates.io", "v1"),
		client:        newCratesLookupClient(opts),
	}
}

// ResolveCrate returns the enrichment information for a given crate name and version. It
// first checks the cache for the enrichment information, and if not found, it will fetch
// the information from crates.io.
func (cr *rustCratesResolver) ResolveCrate(ctx context.Context, crateName, crateVersion string) (pkg.RustCratesEnrichedEntry, error) {
	return cr.cratesCache.Resolve(fmt.Sprintf("%s/%s", crateName, crateVersion), func() (pkg.RustCratesEnrichedEntry, error) {
		return cr.fetchRemoteCratesInfo(ctx, crateName, crateVersion)
	})
}

// fetchRemoteCratesInfo fetches the enrichment information for a given crate name and version.
// It sets the user agent to the cataloger name and makes a GET request to crates.io.
// It then parses the response and returns the enrichment information.
func (cr *rustCratesResolver) fetchRemoteCratesInfo(ctx context.Context, crateName, crateVersion string) (pkg.RustCratesEnrichedEntry, error) {
	defer func() {
		if r := recover(); r != nil {
			log.Errorf("%s recovered from panic while resolving crates at: %s with error: %s", cr.catalogerName, string(debug.Stack()), r.(error))
		}
	}()

	crateURL := fmt.Sprintf("%s/%s/%s", cr.cratesAPI, crateName, crateVersion)
	req, err := http.NewRequest("GET", crateURL, nil)
	if err != nil {
		return pkg.RustCratesEnrichedEntry{}, err
	}
	req = setHeaders(req)
	resp, err := cr.client.Do(req.WithContext(ctx))
	if err != nil {
		return pkg.RustCratesEnrichedEntry{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return pkg.RustCratesEnrichedEntry{}, fmt.Errorf("unexpected response from %s: %s", cr.cratesBaseURL, resp.Status)
	}
	return cr.parseCratesResponse(resp.Body)
}

// parseCratesResponse parses the response body from crates.io into a RustCratesEnrichedEntry that contains
// the summary, homepage, license, and other information about the crate.
func (cr *rustCratesResolver) parseCratesResponse(body io.Reader) (pkg.RustCratesEnrichedEntry, error) {
	var crateInfo cratesRemoteMetadata

	err := json.NewDecoder(body).Decode(&crateInfo)
	if err != nil {
		return pkg.RustCratesEnrichedEntry{}, err
	}

	return pkg.RustCratesEnrichedEntry{
		Name:             crateInfo.Version.Crate,
		Description:      crateInfo.Version.Description,
		Version:          crateInfo.Version.Num,
		Supplier:         crateInfo.Version.PublishedBy.Name,
		DownloadLocation: fmt.Sprintf("%s%s", cr.cratesBaseURL, crateInfo.Version.DownloadPath),
		Repository:       crateInfo.Version.Repository,
		LicenseInfo:      crateInfo.Version.License,
		ReleaseTime:      crateInfo.Version.CreatedAt,
		Summary:          crateInfo.Version.Description,
		CreatedBy:        crateInfo.Version.PublishedBy.Name,
		Homepage:         crateInfo.Version.Homepage,
	}, nil
}

// newCratesLookupClient creates an HTTP client that can be used to query crates.io. The created client
// will use the provided proxy (if any) and will either verify or not verify the TLS certificate of
// crates.io based on the InsecureSkipTLSVerify option. The client will also timeout after the given
// timeout period when making requests.
func newCratesLookupClient(opts CatalogerConfig) *http.Client {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: opts.InsecureSkipTLSVerify,
		},
		DisableKeepAlives:  false,
		DisableCompression: false,
	}
	if opts.proxyURL != nil {
		tr.Proxy = http.ProxyURL(opts.proxyURL)
	}

	return &http.Client{
		Transport: tr,
		Timeout:   opts.CratesTimeout,
	}
}

// setHeaders sets the Accept and User-Agent headers on the given request
// to the values used when querying crates.io.
func setHeaders(request *http.Request) *http.Request {
	request.Header.Set("Accept", "application/json; charset=utf8")
	return request
}
