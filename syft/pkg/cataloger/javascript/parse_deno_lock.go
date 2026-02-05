package javascript

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/internal/unknown"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/dependency"
)

type denoLock struct {
	Version string                    `json:"version"`
	Jsr     map[string]denoJsrPackage `json:"jsr"`
	Npm     map[string]denoNpmPackage `json:"npm"`
	Remote  map[string]string         `json:"remote"`
}

type denoJsrPackage struct {
	Integrity    string   `json:"integrity"`
	Dependencies []string `json:"dependencies"`
}

type denoNpmPackage struct {
	Integrity    string   `json:"integrity"`
	Dependencies []string `json:"dependencies"`
}

type genericDenoLockAdapter struct {
	cfg CatalogerConfig
}

func newGenericDenoLockAdapter(cfg CatalogerConfig) genericDenoLockAdapter {
	return genericDenoLockAdapter{
		cfg: cfg,
	}
}

func (a genericDenoLockAdapter) parseDenoLock(_ context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	var pkgs []pkg.Package
	dec := json.NewDecoder(reader)

	var lock denoLock
	for {
		if err := dec.Decode(&lock); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, nil, fmt.Errorf("failed to parse deno.lock file: %w", err)
		}
	}

	for nameVersion, pkgMeta := range lock.Jsr {
		name, version := parseDenoJsrNameVersion(nameVersion)
		if name == "" || version == "" {
			continue
		}
		pkgs = append(pkgs, newDenoJsrPackage(reader.Location, name, version, pkgMeta))
	}

	for nameVersion, pkgMeta := range lock.Npm {
		name, version := parseDenoNpmNameVersion(nameVersion)
		if name == "" || version == "" {
			continue
		}
		pkgs = append(pkgs, newDenoNpmPackage(reader.Location, name, version, pkgMeta))
	}

	for rawURL, integrity := range lock.Remote {
		name, version := parseDenoRemoteURL(rawURL)
		if name == "" {
			continue
		}
		pkgs = append(pkgs, newDenoRemotePackage(reader.Location, name, version, rawURL, integrity))
	}

	pkg.Sort(pkgs)

	return pkgs, dependency.Resolve(denoLockDependencySpecifier, pkgs), unknown.IfEmptyf(pkgs, "unable to determine packages")
}

func parseDenoJsrNameVersion(nameVersion string) (name, version string) {
	idx := strings.LastIndex(nameVersion, "@")
	if idx <= 0 {
		return "", ""
	}
	return nameVersion[:idx], nameVersion[idx+1:]
}

func parseDenoNpmNameVersion(nameVersion string) (name, version string) {
	if strings.HasPrefix(nameVersion, "@") {
		rest := nameVersion[1:]
		idx := strings.LastIndex(rest, "@")
		if idx <= 0 {
			return "", ""
		}
		return nameVersion[:idx+1], rest[idx+1:]
	}
	idx := strings.LastIndex(nameVersion, "@")
	if idx <= 0 {
		return "", ""
	}
	return nameVersion[:idx], nameVersion[idx+1:]
}

func newDenoJsrPackage(location file.Location, name, version string, meta denoJsrPackage) pkg.Package {
	p := pkg.Package{
		Name:      name,
		Version:   version,
		Locations: file.NewLocationSet(location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation)),
		PURL:      denoJsrPackageURL(name, version),
		Language:  pkg.JavaScript,
		Type:      pkg.NpmPkg,
		Metadata: pkg.DenoLockEntry{
			Integrity:    meta.Integrity,
			Dependencies: meta.Dependencies,
		},
	}
	p.SetID()
	return p
}

func newDenoNpmPackage(location file.Location, name, version string, meta denoNpmPackage) pkg.Package {
	p := pkg.Package{
		Name:      name,
		Version:   version,
		Locations: file.NewLocationSet(location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation)),
		PURL:      denoNpmPackageURL(name, version),
		Language:  pkg.JavaScript,
		Type:      pkg.NpmPkg,
		Metadata: pkg.NpmPackageLockEntry{
			Integrity: meta.Integrity,
		},
	}
	p.SetID()
	return p
}

func newDenoRemotePackage(location file.Location, name, version, rawURL, integrity string) pkg.Package {
	p := pkg.Package{
		Name:      name,
		Version:   version,
		Locations: file.NewLocationSet(location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation)),
		PURL:      denoRemotePackageURL(name, version, rawURL),
		Language:  pkg.JavaScript,
		Type:      pkg.NpmPkg,
		Metadata: pkg.DenoRemoteLockEntry{
			URL:       rawURL,
			Integrity: integrity,
		},
	}
	p.SetID()
	return p
}

func parseDenoRemoteURL(rawURL string) (name, version string) {
	rawURL = strings.TrimPrefix(rawURL, "https://")
	rawURL = strings.TrimPrefix(rawURL, "http://")

	atIdx := strings.Index(rawURL, "@")
	if atIdx == -1 {
		slashIdx := strings.Index(rawURL, "/")
		if slashIdx == -1 {
			return rawURL, ""
		}
		return rawURL[:slashIdx], ""
	}

	name = rawURL[:atIdx]

	rest := rawURL[atIdx+1:]
	slashIdx := strings.Index(rest, "/")
	if slashIdx == -1 {
		version = rest
	} else {
		version = rest[:slashIdx]
	}

	return name, version
}

func extractRepositoryBase(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%s://%s", u.Scheme, u.Host)
}

func denoRemotePackageURL(name, version, rawURL string) string {
	repositoryURL := extractRepositoryBase(rawURL)
	var qualifiers packageurl.Qualifiers
	if repositoryURL != "" {
		qualifiers = packageurl.Qualifiers{{Key: "repository_url", Value: repositoryURL}}
	}

	return packageurl.NewPackageURL(
		packageurl.TypeNPM,
		"",
		name,
		version,
		qualifiers,
		"",
	).ToString()
}

func denoJsrPackageURL(name, version string) string {
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
		packageurl.Qualifiers{{Key: "repository_url", Value: "https://jsr.io"}},
		"",
	).ToString()
}

func denoNpmPackageURL(name, version string) string {
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

func denoLockDependencySpecifier(p pkg.Package) dependency.Specification {
	meta, ok := p.Metadata.(pkg.DenoLockEntry)
	if !ok {
		return dependency.Specification{}
	}

	provides := []string{p.Name}
	var requires []string

	for _, dep := range meta.Dependencies {
		name := parseDenoDependencyName(dep)
		if name != "" {
			requires = append(requires, name)
		}
	}

	return dependency.Specification{
		ProvidesRequires: dependency.ProvidesRequires{
			Provides: provides,
			Requires: requires,
		},
	}
}

func parseDenoDependencyName(dep string) string {
	if strings.HasPrefix(dep, "jsr:") {
		dep = strings.TrimPrefix(dep, "jsr:")
	} else if strings.HasPrefix(dep, "npm:") {
		dep = strings.TrimPrefix(dep, "npm:")
	}

	if strings.HasPrefix(dep, "@") {
		rest := dep[1:]
		atIdx := strings.Index(rest, "@")
		if atIdx > 0 {
			return dep[:atIdx+1]
		}
		return dep
	}

	idx := strings.Index(dep, "@")
	if idx > 0 {
		return dep[:idx]
	}
	return dep
}
