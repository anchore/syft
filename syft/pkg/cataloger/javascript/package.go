package javascript

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

func newPackageJSONPackage(u packageJSON, indexLocation file.Location) pkg.Package {
	licenseCandidates, err := u.licensesFromJSON()
	if err != nil {
		log.Warnf("unable to extract licenses from javascript package.json: %+v", err)
	}

	license := pkg.NewLicensesFromLocation(indexLocation, licenseCandidates...)
	p := pkg.Package{
		Name:      u.Name,
		Version:   u.Version,
		PURL:      packageURL(u.Name, u.Version),
		Locations: file.NewLocationSet(indexLocation),
		Language:  pkg.JavaScript,
		Licenses:  pkg.NewLicenseSet(license...),
		Type:      pkg.NpmPkg,
		Metadata: pkg.NpmPackage{
			Name:        u.Name,
			Version:     u.Version,
			Description: u.Description,
			Author:      u.Author.AuthorString(),
			Homepage:    u.Homepage,
			URL:         u.Repository.URL,
			Private:     u.Private,
		},
	}

	p.SetID()

	return p
}

func newPackageLockV1Package(cfg CatalogerConfig, resolver file.Resolver, location file.Location, name string, u lockDependency) pkg.Package {
	version := u.Version

	const aliasPrefixPackageLockV1 = "npm:"

	// Handles type aliases https://github.com/npm/rfcs/blob/main/implemented/0001-package-aliases.md
	if strings.HasPrefix(version, aliasPrefixPackageLockV1) {
		// this is an alias.
		// `"version": "npm:canonical-name@X.Y.Z"`
		canonicalPackageAndVersion := version[len(aliasPrefixPackageLockV1):]
		versionSeparator := strings.LastIndex(canonicalPackageAndVersion, "@")

		name = canonicalPackageAndVersion[:versionSeparator]
		version = canonicalPackageAndVersion[versionSeparator+1:]
	}

	var licenseSet pkg.LicenseSet

	if cfg.SearchRemoteLicenses {
		license, err := getLicenseFromNpmRegistry(cfg.NPMBaseURL, name, version)
		if err == nil && license != "" {
			licenses := pkg.NewLicensesFromValues(license)
			licenseSet = pkg.NewLicenseSet(licenses...)
		}
		if err != nil {
			log.Warnf("unable to extract licenses from javascript yarn.lock for package %s:%s: %+v", name, version, err)
		}
	}

	return finalizeLockPkg(
		resolver,
		location,
		pkg.Package{
			Name:      name,
			Version:   version,
			Licenses:  licenseSet,
			Locations: file.NewLocationSet(location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation)),
			PURL:      packageURL(name, version),
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata:  pkg.NpmPackageLockEntry{Resolved: u.Resolved, Integrity: u.Integrity},
		},
	)
}

func newPackageLockV2Package(cfg CatalogerConfig, resolver file.Resolver, location file.Location, name string, u lockPackage) pkg.Package {
	var licenseSet pkg.LicenseSet

	if u.License != nil {
		licenseSet = pkg.NewLicenseSet(pkg.NewLicensesFromLocation(location, u.License...)...)
	} else if cfg.SearchRemoteLicenses {
		license, err := getLicenseFromNpmRegistry(cfg.NPMBaseURL, name, u.Version)
		if err == nil && license != "" {
			licenses := pkg.NewLicensesFromValues(license)
			licenseSet = pkg.NewLicenseSet(licenses...)
		}
		if err != nil {
			log.Warnf("unable to extract licenses from javascript yarn.lock for package %s:%s: %+v", name, u.Version, err)
		}
	}

	return finalizeLockPkg(
		resolver,
		location,
		pkg.Package{
			Name:      name,
			Version:   u.Version,
			Locations: file.NewLocationSet(location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation)),
			Licenses:  licenseSet,
			PURL:      packageURL(name, u.Version),
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata:  pkg.NpmPackageLockEntry{Resolved: u.Resolved, Integrity: u.Integrity},
		},
	)
}

func newPnpmPackage(resolver file.Resolver, location file.Location, name, version string) pkg.Package {
	return finalizeLockPkg(
		resolver,
		location,
		pkg.Package{
			Name:      name,
			Version:   version,
			Locations: file.NewLocationSet(location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation)),
			PURL:      packageURL(name, version),
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
		},
	)
}

func newYarnLockPackage(cfg CatalogerConfig, resolver file.Resolver, location file.Location, name, version string, resolved string, integrity string) pkg.Package {
	var licenseSet pkg.LicenseSet

	if cfg.SearchRemoteLicenses {
		license, err := getLicenseFromNpmRegistry(cfg.NPMBaseURL, name, version)
		if err == nil && license != "" {
			licenses := pkg.NewLicensesFromValues(license)
			licenseSet = pkg.NewLicenseSet(licenses...)
		}
		if err != nil {
			log.Warnf("unable to extract licenses from javascript yarn.lock for package %s:%s: %+v", name, version, err)
		}
	}
	return finalizeLockPkg(
		resolver,
		location,
		pkg.Package{
			Name:      name,
			Version:   version,
			Licenses:  licenseSet,
			Locations: file.NewLocationSet(location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation)),
			PURL:      packageURL(name, version),
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata:  pkg.YarnLockEntry{Resolved: resolved, Integrity: integrity},
		},
	)
}

func formatNpmRegistryURL(baseURL, packageName, version string) (requestURL string, err error) {
	urlPath := []string{packageName, version}
	requestURL, err = url.JoinPath(baseURL, urlPath...)
	if err != nil {
		return requestURL, fmt.Errorf("unable to format npm request for pkg:version %s%s; %w", packageName, version, err)
	}
	return requestURL, nil
}

func getLicenseFromNpmRegistry(baseURL, packageName, version string) (string, error) {
	// "https://registry.npmjs.org/%s/%s", packageName, version
	requestURL, err := formatNpmRegistryURL(baseURL, packageName, version)
	if err != nil {
		return "", fmt.Errorf("unable to format npm request for pkg:version %s%s; %w", packageName, version, err)
	}
	log.WithFields("url", requestURL).Info("downloading javascript package from npm")

	npmRequest, err := http.NewRequest(http.MethodGet, requestURL, nil)
	if err != nil {
		return "", fmt.Errorf("unable to format remote request: %w", err)
	}

	httpClient := &http.Client{
		Timeout: time.Second * 10,
	}

	resp, err := httpClient.Do(npmRequest)
	if err != nil {
		return "", fmt.Errorf("unable to get package from npm registry: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Errorf("unable to close body: %+v", err)
		}
	}()

	bytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("unable to parse package from npm registry: %w", err)
	}

	dec := json.NewDecoder(strings.NewReader(string(bytes)))

	// Read "license" from the response
	var license struct {
		License string `json:"license"`
	}

	if err := dec.Decode(&license); err != nil {
		return "", fmt.Errorf("unable to parse license from npm registry: %w", err)
	}

	log.Tracef("Retrieved License: %s", license.License)

	return license.License, nil
}

func finalizeLockPkg(resolver file.Resolver, location file.Location, p pkg.Package) pkg.Package {
	licenseCandidate := addLicenses(p.Name, resolver, location)
	p.Licenses.Add(pkg.NewLicensesFromLocation(location, licenseCandidate...)...)
	p.SetID()
	return p
}

func addLicenses(name string, resolver file.Resolver, location file.Location) (allLicenses []string) {
	if resolver == nil {
		return allLicenses
	}

	dir := path.Dir(location.RealPath)
	pkgPath := []string{dir, "node_modules"}
	pkgPath = append(pkgPath, strings.Split(name, "/")...)
	pkgPath = append(pkgPath, "package.json")
	pkgFile := path.Join(pkgPath...)
	locations, err := resolver.FilesByPath(pkgFile)
	if err != nil {
		log.Debugf("an error occurred attempting to read: %s - %+v", pkgFile, err)
		return allLicenses
	}

	if len(locations) == 0 {
		return allLicenses
	}

	for _, l := range locations {
		licenses, err := parseLicensesFromLocation(l, resolver, pkgFile)
		if err != nil {
			return allLicenses
		}
		allLicenses = append(allLicenses, licenses...)
	}

	return allLicenses
}

func parseLicensesFromLocation(l file.Location, resolver file.Resolver, pkgFile string) ([]string, error) {
	contentReader, err := resolver.FileContentsByLocation(l)
	if err != nil {
		log.Debugf("error getting file content reader for %s: %v", pkgFile, err)
		return nil, err
	}
	defer internal.CloseAndLogError(contentReader, l.RealPath)

	contents, err := io.ReadAll(contentReader)
	if err != nil {
		log.Debugf("error reading file contents for %s: %v", pkgFile, err)
		return nil, err
	}

	var pkgJSON packageJSON
	err = json.Unmarshal(contents, &pkgJSON)
	if err != nil {
		log.Debugf("error parsing %s: %v", pkgFile, err)
		return nil, err
	}

	licenses, err := pkgJSON.licensesFromJSON()
	if err != nil {
		log.Debugf("error getting licenses from %s: %v", pkgFile, err)
		return nil, err
	}
	return licenses, nil
}

// packageURL returns the PURL for the specific NPM package (see https://github.com/package-url/purl-spec)
func packageURL(name, version string) string {
	var namespace string

	fields := strings.SplitN(name, "/", 2)
	if len(fields) > 1 {
		namespace = fields[0]
		name = fields[1]
	}

	return packageurl.NewPackageURL(
		packageurl.TypeNPM,
		namespace,
		name,
		version,
		nil,
		"",
	).ToString()
}
