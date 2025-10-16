package python

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

func normalize(name string) string {
	// https://packaging.python.org/en/latest/specifications/name-normalization/
	re := regexp.MustCompile(`[-_.]+`)
	normalized := re.ReplaceAllString(name, "-")
	return strings.ToLower(normalized)
}

func newPackageForIndex(ctx context.Context, cfg CatalogerConfig, name, version string, locations ...file.Location) pkg.Package {
	name = normalize(name)
	licenseSet := enrichLicenseIfConfigured(ctx, cfg, name, version)

	p := pkg.Package{
		Name:      name,
		Version:   version,
		Licenses:  licenseSet,
		Locations: file.NewLocationSet(locations...),
		PURL:      packageURL(name, version, nil),
		Language:  pkg.Python,
		Type:      pkg.PythonPkg,
	}

	p.SetID()

	return p
}

func newPackageForIndexWithMetadata(ctx context.Context, cfg CatalogerConfig, name, version string, metadata interface{}, locations ...file.Location) pkg.Package {
	name = normalize(name)
	licenseSet := enrichLicenseIfConfigured(ctx, cfg, name, version)

	p := pkg.Package{
		Name:      name,
		Version:   version,
		Licenses:  licenseSet,
		Locations: file.NewLocationSet(locations...),
		PURL:      packageURL(name, version, nil),
		Language:  pkg.Python,
		Type:      pkg.PythonPkg,
		Metadata:  metadata,
	}

	p.SetID()

	return p
}

func newPackageForRequirementsWithMetadata(ctx context.Context, cfg CatalogerConfig, name, version string, metadata pkg.PythonRequirementsEntry, locations ...file.Location) pkg.Package {
	name = normalize(name)
	licenseSet := enrichLicenseIfConfigured(ctx, cfg, name, version)

	p := pkg.Package{
		Name:      name,
		Version:   version,
		Licenses:  licenseSet,
		Locations: file.NewLocationSet(locations...),
		PURL:      packageURL(name, version, nil),
		Language:  pkg.Python,
		Type:      pkg.PythonPkg,
		Metadata:  metadata,
	}

	p.SetID()

	return p
}

func newPackageForPackage(m parsedData, licenses pkg.LicenseSet, sources ...file.Location) pkg.Package {
	name := normalize(m.Name)

	p := pkg.Package{
		Name:      name,
		Version:   m.Version,
		PURL:      packageURL(name, m.Version, &m.PythonPackage),
		Locations: file.NewLocationSet(sources...),
		Licenses:  licenses,
		Language:  pkg.Python,
		Type:      pkg.PythonPkg,
		Metadata:  m.PythonPackage,
	}

	p.SetID()

	return p
}

func packageURL(name, version string, m *pkg.PythonPackage) string {
	// generate a purl from the package data
	pURL := packageurl.NewPackageURL(
		packageurl.TypePyPi,
		"",
		name,
		version,
		purlQualifiersForPackage(m),
		"")

	return pURL.ToString()
}

func purlQualifiersForPackage(m *pkg.PythonPackage) packageurl.Qualifiers {
	q := packageurl.Qualifiers{}
	if m == nil {
		return q
	}
	if m.DirectURLOrigin != nil {
		q = append(q, vcsURLQualifierForPackage(m.DirectURLOrigin)...)
	}
	return q
}

func vcsURLQualifierForPackage(p *pkg.PythonDirectURLOriginInfo) packageurl.Qualifiers {
	if p == nil || p.VCS == "" {
		return nil
	}
	// Taken from https://github.com/package-url/purl-spec/blob/master/PURL-SPECIFICATION.rst#known-qualifiers-keyvalue-pairs
	// packageurl-go still doesn't support all qualifier names
	return packageurl.Qualifiers{
		{Key: pkg.PURLQualifierVCSURL, Value: fmt.Sprintf("%s+%s@%s", p.VCS, p.URL, p.CommitID)},
	}
}

func enrichLicenseIfConfigured(ctx context.Context, cfg CatalogerConfig, name string, version string) pkg.LicenseSet {
	var licenseSet pkg.LicenseSet

	if cfg.SearchRemoteLicenses {
		license, err := getLicenseFromPypiRegistry(cfg.PypiBaseURL, name, version)
		if err == nil && license != "" {
			licenses := pkg.NewLicensesFromValuesWithContext(ctx, license)
			licenseSet = pkg.NewLicenseSet(licenses...)
		}
		if err != nil {
			log.Debugf("unable to extract licenses from pypi registry for package %s:%s: %+v", name, version, err)
		}
	}
	return licenseSet
}

func formatPypiRegistryURL(baseURL, packageName, version string) (requestURL string, err error) {
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
