package terraform

import (
	"archive/zip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
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

type terraformLicenseResolver struct {
	cfg          CatalogerConfig
	licenseCache cache.Resolver[[]pkg.License]
}

func newTerraformLicenseResolver(cfg CatalogerConfig) terraformLicenseResolver {
	return terraformLicenseResolver{
		cfg:          cfg,
		licenseCache: cache.GetResolverCachingErrors[[]pkg.License]("terraform", "v1"),
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

// registryDownloadResponse represents the JSON response from the Terraform Registry provider download endpoint.
type registryDownloadResponse struct {
	DownloadURL string `json:"download_url"`
}

func (r *terraformLicenseResolver) downloadAndScanProvider(ctx context.Context, providerURL, version string) ([]pkg.License, error) {
	namespace, providerType, err := parseProviderURL(providerURL)
	if err != nil {
		return nil, err
	}

	downloadURL, err := r.getProviderDownloadURL(namespace, providerType, version)
	if err != nil {
		return nil, fmt.Errorf("unable to get download URL for provider %s@%s: %w", providerURL, version, err)
	}

	fsys, cleanup, err := downloadProviderZip(ctx, downloadURL)
	if cleanup != nil {
		defer cleanup()
	}
	if err != nil {
		return nil, fmt.Errorf("unable to download provider archive for %s@%s: %w", providerURL, version, err)
	}

	return findLicensesInFS(ctx, downloadURL+"#", fsys)
}

// parseProviderURL extracts namespace and type from a provider URL like "registry.terraform.io/hashicorp/aws".
func parseProviderURL(providerURL string) (namespace, providerType string, err error) {
	parts := strings.Split(providerURL, "/")
	if len(parts) < 3 {
		return "", "", fmt.Errorf("invalid provider URL %q: expected at least 3 segments (registry/namespace/type)", providerURL)
	}
	return parts[len(parts)-2], parts[len(parts)-1], nil
}

func (r *terraformLicenseResolver) getProviderDownloadURL(namespace, providerType, version string) (string, error) {
	reqURL := fmt.Sprintf("%s/v1/providers/%s/%s/%s/download/linux/amd64", r.cfg.RegistryBaseURL, namespace, providerType, version)

	log.WithFields("url", reqURL).Info("querying terraform registry for provider download URL")

	req, err := http.NewRequest(http.MethodGet, reqURL, nil)
	if err != nil {
		return "", fmt.Errorf("unable to create request: %w", err)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("unable to query terraform registry: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.WithFields("error", closeErr).Trace("unable to close response body")
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("terraform registry returned status %d for %s", resp.StatusCode, reqURL)
	}

	var dlResp registryDownloadResponse
	if err := json.NewDecoder(resp.Body).Decode(&dlResp); err != nil {
		return "", fmt.Errorf("unable to decode terraform registry response: %w", err)
	}

	if dlResp.DownloadURL == "" {
		return "", fmt.Errorf("terraform registry returned empty download URL for %s/%s@%s", namespace, providerType, version)
	}

	return dlResp.DownloadURL, nil
}

const maxProviderZipSize = 500 * 1024 * 1024

func downloadProviderZip(ctx context.Context, downloadURL string) (fs.FS, func(), error) {
	log.WithFields("url", downloadURL).Info("downloading terraform provider archive")

	resp, err := http.Get(downloadURL) //nolint:gosec
	if err != nil {
		return nil, nil, fmt.Errorf("unable to download provider: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("provider download returned status %d", resp.StatusCode)
	}

	td := tmpdir.FromContext(ctx)
	if td == nil {
		return nil, nil, fmt.Errorf("no temp dir factory in context")
	}

	tmpFile, cleanupFile, err := td.NewFile("terraform-provider-*.zip")
	if err != nil {
		return nil, nil, fmt.Errorf("unable to create temp file: %w", err)
	}

	cleanup := func() {
		_ = tmpFile.Close()
		cleanupFile()
	}

	size, err := io.Copy(tmpFile, io.LimitReader(resp.Body, maxProviderZipSize))
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("unable to download provider zip: %w", err)
	}
	if size >= maxProviderZipSize {
		cleanup()
		return nil, nil, fmt.Errorf("provider zip exceeds %d byte size limit", maxProviderZipSize)
	}

	if _, err := tmpFile.Seek(0, io.SeekStart); err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("unable to seek provider zip: %w", err)
	}

	zipReader, err := zip.NewReader(tmpFile, size)
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("unable to read provider zip: %w", err)
	}

	return zipReader, cleanup, nil
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
