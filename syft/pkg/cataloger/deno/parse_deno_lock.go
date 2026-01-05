package deno

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/internal/unknown"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

type denoLock struct {
	Version string                `json:"version"`
	Jsr     map[string]jsrPackage `json:"jsr"`
	Npm     map[string]npmPackage `json:"npm"`
	Remote  map[string]string     `json:"remote"`
}

type jsrPackage struct {
	Integrity    string   `json:"integrity"`
	Dependencies []string `json:"dependencies"`
}

type npmPackage struct {
	Integrity    string   `json:"integrity"`
	Dependencies []string `json:"dependencies"`
}

func parseDenoLock(_ context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
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
		name, version := parseJsrNameVersion(nameVersion)
		if name == "" || version == "" {
			continue
		}
		pkgs = append(pkgs, newJsrPackage(reader.Location, name, version, pkgMeta))
	}

	for nameVersion, pkgMeta := range lock.Npm {
		name, version := parseNpmNameVersion(nameVersion)
		if name == "" || version == "" {
			continue
		}
		pkgs = append(pkgs, newNpmPackage(reader.Location, name, version, pkgMeta))
	}

	for url, integrity := range lock.Remote {
		name, version := parseRemoteURL(url)
		if name == "" {
			continue
		}
		pkgs = append(pkgs, newRemotePackage(reader.Location, name, version, url, integrity))
	}

	pkg.Sort(pkgs)

	return pkgs, nil, unknown.IfEmptyf(pkgs, "unable to determine packages")
}

func parseJsrNameVersion(nameVersion string) (name, version string) {
	idx := strings.LastIndex(nameVersion, "@")
	if idx <= 0 {
		return "", ""
	}
	return nameVersion[:idx], nameVersion[idx+1:]
}

func parseNpmNameVersion(nameVersion string) (name, version string) {
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

func newJsrPackage(location file.Location, name, version string, meta jsrPackage) pkg.Package {
	p := pkg.Package{
		Name:      name,
		Version:   version,
		Locations: file.NewLocationSet(location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation)),
		PURL:      jsrPackageURL(name, version),
		Language:  pkg.JavaScript,
		Type:      pkg.JsrPkg,
		Metadata: pkg.DenoLockEntry{
			Integrity:    meta.Integrity,
			Dependencies: meta.Dependencies,
		},
	}
	p.SetID()
	return p
}

func newNpmPackage(location file.Location, name, version string, meta npmPackage) pkg.Package {
	p := pkg.Package{
		Name:      name,
		Version:   version,
		Locations: file.NewLocationSet(location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation)),
		PURL:      npmPackageURL(name, version),
		Language:  pkg.JavaScript,
		Type:      pkg.NpmPkg,
		Metadata: pkg.NpmPackageLockEntry{
			Integrity: meta.Integrity,
		},
	}
	p.SetID()
	return p
}

func newRemotePackage(location file.Location, name, version, url, integrity string) pkg.Package {
	p := pkg.Package{
		Name:      name,
		Version:   version,
		Locations: file.NewLocationSet(location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation)),
		PURL:      remotePackageURL(name, version),
		Language:  pkg.JavaScript,
		Type:      pkg.JsrPkg,
		Metadata: pkg.DenoRemoteLockEntry{
			URL:       url,
			Integrity: integrity,
		},
	}
	p.SetID()
	return p
}

func parseRemoteURL(rawURL string) (name, version string) {
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

func remotePackageURL(name, version string) string {
	return packageurl.NewPackageURL(
		"deno",
		"",
		name,
		version,
		nil,
		"",
	).ToString()
}

func jsrPackageURL(name, version string) string {
	var namespace string
	fields := strings.SplitN(name, "/", 2)
	if len(fields) > 1 {
		namespace = fields[0]
		name = fields[1]
	}

	return packageurl.NewPackageURL(
		"jsr",
		namespace,
		name,
		version,
		nil,
		"",
	).ToString()
}

func npmPackageURL(name, version string) string {
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
