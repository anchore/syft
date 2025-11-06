package python

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/anchore/syft/internal/cache"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/pkg"
)

type pythonLicenseResolver struct {
	catalogerConfig CatalogerConfig
	licenseCache    cache.Resolver[[]pkg.License]
}

func newPythonLicenseResolver(config CatalogerConfig) pythonLicenseResolver {
	return pythonLicenseResolver{
		licenseCache:    cache.GetResolverCachingErrors[[]pkg.License]("python", "v1"),
		catalogerConfig: config,
	}
}

func (lr *pythonLicenseResolver) getLicenses(ctx context.Context, packageName string, packageVersion string) pkg.LicenseSet {
	var licenseSet pkg.LicenseSet

	if lr.catalogerConfig.SearchRemoteLicenses {
		licenses, err := lr.getLicensesFromRemote(ctx, packageName, packageVersion)
		if err == nil && licenses != nil {
			licenseSet = pkg.NewLicenseSet(licenses...)
		}
		if err != nil {
			log.Debugf("unable to extract licenses from pypi registry for package %s:%s: %+v", packageName, packageVersion, err)
		}
	}
	return licenseSet
}

func (lr *pythonLicenseResolver) getLicensesFromRemote(ctx context.Context, packageName string, packageVersion string) ([]pkg.License, error) {
	return lr.licenseCache.Resolve(fmt.Sprintf("%s/%s", packageName, packageVersion), func() ([]pkg.License, error) {
		license, err := getLicenseFromPypiRegistry(lr.catalogerConfig.PypiBaseURL, packageName, packageVersion)
		if err == nil && license != "" {
			licenses := pkg.NewLicensesFromValuesWithContext(ctx, license)
			return licenses, nil
		}
		if err != nil {
			log.Debugf("unable to extract licenses from pypi registry for package %s:%s: %+v", packageName, packageVersion, err)
		}
		return nil, err
	})
}

func formatPypiRegistryURL(baseURL, packageName, version string) (requestURL string, err error) {
	if packageName == "" {
		return "", fmt.Errorf("unable to format pypi request for a blank package name")
	}

	urlPath := []string{packageName, version, "json"}
	requestURL, err = url.JoinPath(baseURL, urlPath...)
	if err != nil {
		return requestURL, fmt.Errorf("unable to format pypi request for pkg:version %s%s; %w", packageName, version, err)
	}
	return requestURL, nil
}

func getLicenseFromPypiRegistry(baseURL, packageName, version string) (string, error) {
	// "https://pypi.org/pypi/%s/%s/json", packageName, version
	requestURL, err := formatPypiRegistryURL(baseURL, packageName, version)
	if err != nil {
		return "", fmt.Errorf("unable to format pypi request for pkg:version %s%s; %w", packageName, version, err)
	}
	log.WithFields("url", requestURL).Info("downloading python package from pypi")

	pypiRequest, err := http.NewRequest(http.MethodGet, requestURL, nil)
	if err != nil {
		return "", fmt.Errorf("unable to format remote request: %w", err)
	}

	httpClient := &http.Client{
		Timeout: time.Second * 10,
	}

	resp, err := httpClient.Do(pypiRequest)
	if err != nil {
		return "", fmt.Errorf("unable to get package from pypi registry: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Errorf("unable to close body: %+v", err)
		}
	}()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("unable to get package from pypi registry")
	}

	bytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("unable to parse package from pypi registry: %w", err)
	}

	dec := json.NewDecoder(strings.NewReader(string(bytes)))

	// Read "license" from the response
	var pypiResponse struct {
		Info struct {
			License           string `json:"license"`
			LicenseExpression string `json:"license_expression"`
		} `json:"info"`
	}

	if err := dec.Decode(&pypiResponse); err != nil {
		return "", fmt.Errorf("unable to parse license from pypi registry: %w", err)
	}

	var license string
	if pypiResponse.Info.LicenseExpression != "" {
		license = pypiResponse.Info.LicenseExpression
	} else {
		license = pypiResponse.Info.License
	}
	log.Tracef("Retrieved License: %s", license)

	return license, nil
}
