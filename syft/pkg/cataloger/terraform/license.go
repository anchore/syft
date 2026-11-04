package terraform

import (
	"archive/zip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/cache"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/tmpdir"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/licenses"
)

const (
	// registryAPITimeout bounds small JSON requests to the registry (service discovery, download lookups).
	registryAPITimeout = 10 * time.Second
	// providerDownloadTimeout bounds the provider archive download, which can be hundreds of megabytes.
	providerDownloadTimeout = 5 * time.Minute
	// maxProviderZipSize caps downloads to prevent disk exhaustion from a malicious registry.
	maxProviderZipSize = 500 * 1024 * 1024
)

type terraformLicenseResolver struct {
	cfg          CatalogerConfig
	licenseCache cache.Resolver[[]pkg.License]
	client       *http.Client
}

func newTerraformLicenseResolver(cfg CatalogerConfig) terraformLicenseResolver {
	return terraformLicenseResolver{
		cfg:          cfg,
		licenseCache: cache.GetResolverCachingErrors[[]pkg.License]("terraform", "v1"),
		client:       &http.Client{},
	}
}

func (r *terraformLicenseResolver) getLicenses(ctx context.Context, resolver file.Resolver, lockFileDir, providerURL, version string) pkg.LicenseSet {
	found := r.findLocalLicenses(ctx, resolver, lockFileDir, providerURL, version)
	if len(found) > 0 {
		return pkg.NewLicenseSet(found...)
	}

	if r.cfg.SearchRemoteLicenses {
		remoteLicenses, err := r.findRemoteLicenses(ctx, providerURL, version)
		if err != nil {
			log.WithFields("error", err, "provider", providerURL, "version", version).Debug("unable to fetch terraform provider licenses from registry")
		}
		if len(remoteLicenses) > 0 {
			return pkg.NewLicenseSet(remoteLicenses...)
		}
	}

	return pkg.NewLicenseSet()
}

func (r *terraformLicenseResolver) findLocalLicenses(ctx context.Context, resolver file.Resolver, lockFileDir, providerURL, version string) []pkg.License {
	glob := path.Join(lockFileDir, ".terraform", "providers", providerURL, version, "*", "*")
	return licenses.FindByGlob(ctx, resolver, glob)
}

func (r *terraformLicenseResolver) findRemoteLicenses(ctx context.Context, providerURL, version string) ([]pkg.License, error) {
	return r.licenseCache.Resolve(fmt.Sprintf("%s/%s", providerURL, version), func() ([]pkg.License, error) {
		return r.downloadAndScanProvider(ctx, providerURL, version)
	})
}

func (r *terraformLicenseResolver) downloadAndScanProvider(ctx context.Context, providerURL, version string) ([]pkg.License, error) {
	host, namespace, providerType, err := parseProviderURL(providerURL)
	if err != nil {
		return nil, err
	}

	providersAPI, err := r.providersAPIBaseURL(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("unable to resolve providers API for registry %q: %w", host, err)
	}

	downloadURL, err := r.getProviderDownloadURL(ctx, providersAPI, namespace, providerType, version)
	if err != nil {
		return nil, fmt.Errorf("unable to get download URL for provider %s@%s: %w", providerURL, version, err)
	}

	td := tmpdir.FromContext(ctx)
	if td == nil {
		return nil, fmt.Errorf("no temp dir factory in context")
	}
	tmpFile, cleanupFile, err := td.NewFile("terraform-provider-*.zip")
	if err != nil {
		return nil, fmt.Errorf("unable to create temp file: %w", err)
	}
	defer cleanupFile()
	defer internal.CloseAndLogError(tmpFile, tmpFile.Name())

	size, err := r.downloadProviderZip(ctx, downloadURL, tmpFile)
	if err != nil {
		return nil, fmt.Errorf("unable to download provider archive for %s@%s: %w", providerURL, version, err)
	}

	zipReader, err := zip.NewReader(tmpFile, size)
	if err != nil {
		return nil, fmt.Errorf("unable to read provider zip: %w", err)
	}

	return findLicensesInFS(ctx, downloadURL+"#", zipReader)
}

// parseProviderURL splits a provider source address like "registry.terraform.io/hashicorp/aws" into its
// registry host, namespace, and type.
func parseProviderURL(providerURL string) (host, namespace, providerType string, err error) {
	parts := strings.Split(providerURL, "/")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return "", "", "", fmt.Errorf("invalid provider URL %q: expected hostname/namespace/type", providerURL)
	}
	return strings.ToLower(parts[0]), parts[1], parts[2], nil
}

// providersAPIBaseURL returns the base URL of the providers API for the registry at the given host. Providers from
// the public Terraform Registry use the configured RegistryBaseURL (which may point at a mirror); providers from any
// other registry (e.g. OpenTofu or a private registry) are resolved via the registry's service discovery document.
func (r *terraformLicenseResolver) providersAPIBaseURL(ctx context.Context, host string) (string, error) {
	if host == defaultRegistryHost {
		return url.JoinPath(r.cfg.RegistryBaseURL, "v1", "providers")
	}

	base := &url.URL{Scheme: "https", Host: host}
	var discovery struct {
		ProvidersV1 string `json:"providers.v1"`
	}
	if err := r.getJSON(ctx, base.JoinPath(".well-known", "terraform.json").String(), &discovery); err != nil {
		return "", fmt.Errorf("service discovery failed: %w", err)
	}
	if discovery.ProvidersV1 == "" {
		return "", fmt.Errorf("registry does not support the providers.v1 protocol")
	}

	ref, err := url.Parse(discovery.ProvidersV1)
	if err != nil {
		return "", fmt.Errorf("invalid providers.v1 URL %q: %w", discovery.ProvidersV1, err)
	}
	return base.ResolveReference(ref).String(), nil
}

func (r *terraformLicenseResolver) getProviderDownloadURL(ctx context.Context, providersAPI, namespace, providerType, version string) (string, error) {
	// license content is platform-independent, so any published platform will do
	reqURL, err := url.JoinPath(providersAPI, namespace, providerType, version, "download", "linux", "amd64")
	if err != nil {
		return "", fmt.Errorf("unable to build registry URL: %w", err)
	}

	log.WithFields("url", reqURL).Info("querying terraform registry for provider download URL")

	var dlResp struct {
		DownloadURL string `json:"download_url"`
	}
	if err := r.getJSON(ctx, reqURL, &dlResp); err != nil {
		return "", err
	}
	if dlResp.DownloadURL == "" {
		return "", fmt.Errorf("terraform registry returned empty download URL for %s/%s@%s", namespace, providerType, version)
	}

	// the download URL may be relative to the registry endpoint
	base, err := url.Parse(reqURL)
	if err != nil {
		return "", err
	}
	ref, err := url.Parse(dlResp.DownloadURL)
	if err != nil {
		return "", fmt.Errorf("invalid download URL %q: %w", dlResp.DownloadURL, err)
	}
	return base.ResolveReference(ref).String(), nil
}

func (r *terraformLicenseResolver) getJSON(ctx context.Context, reqURL string, out any) error {
	ctx, cancel := context.WithTimeout(ctx, registryAPITimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return fmt.Errorf("unable to create request: %w", err)
	}

	resp, err := r.client.Do(req)
	if err != nil {
		return fmt.Errorf("unable to query terraform registry: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("terraform registry returned status %d for %s", resp.StatusCode, reqURL)
	}

	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("unable to decode terraform registry response: %w", err)
	}
	return nil
}

// downloadProviderZip streams the provider archive into dst, returning the number of bytes written.
func (r *terraformLicenseResolver) downloadProviderZip(ctx context.Context, downloadURL string, dst io.WriteSeeker) (int64, error) {
	log.WithFields("url", downloadURL).Info("downloading terraform provider archive")

	ctx, cancel := context.WithTimeout(ctx, providerDownloadTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL, nil)
	if err != nil {
		return 0, fmt.Errorf("unable to create request: %w", err)
	}

	resp, err := r.client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("unable to download provider: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("provider download returned status %d", resp.StatusCode)
	}

	// read one byte past the limit so an archive of exactly maxProviderZipSize is still accepted
	size, err := io.Copy(dst, io.LimitReader(resp.Body, maxProviderZipSize+1))
	if err != nil {
		return 0, fmt.Errorf("unable to download provider zip: %w", err)
	}
	if size > maxProviderZipSize {
		return 0, fmt.Errorf("provider zip exceeds %d byte size limit", maxProviderZipSize)
	}

	if _, err := dst.Seek(0, io.SeekStart); err != nil {
		return 0, fmt.Errorf("unable to seek provider zip: %w", err)
	}
	return size, nil
}

func findLicensesInFS(ctx context.Context, urlPrefix string, fsys fs.FS) ([]pkg.License, error) {
	var out []pkg.License
	err := fs.WalkDir(fsys, ".", func(filePath string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d == nil || d.IsDir() {
			return nil
		}
		if !licenses.IsLicenseFile(d.Name()) {
			return nil
		}
		rdr, err := fsys.Open(filePath)
		if err != nil {
			log.WithFields("error", err, "path", filePath).Debug("unable to open license file in provider archive")
			return nil
		}
		defer internal.CloseAndLogError(rdr, filePath)

		foundLicenses := pkg.NewLicensesFromReadCloserWithContext(ctx, file.NewLocationReadCloser(file.NewLocation(filePath), rdr))
		for _, l := range foundLicenses {
			l.URLs = []string{urlPrefix + filePath}
			l.Locations = file.NewLocationSet()
			out = append(out, l)
		}
		return nil
	})
	return out, err
}
