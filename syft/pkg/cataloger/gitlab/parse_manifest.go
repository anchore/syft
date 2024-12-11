package gitlab

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

type versionManifest struct {
	ManifestFormat   int                        `json:"manifest_format"`
	Software         map[string]manifestPackage `json:"software"`
	BuildVersion     string                     `json:"build_version"`
	BuildGitRevision string                     `json:"build_git_revision"`
	License          string                     `json:"license"`
}

type manifestPackage struct {
	LockedVersion    *string       `json:"locked_version"`
	LockedSource     *lockedSource `json:"locked_source"`
	SourceType       *string       `json:"url"`
	DescribedVersion *string       `json:"described_version"`
	DisplayVersion   *string       `json:"display_version"`
	Vendor           *string       `json:"vendor"`
	License          *string       `json:"license"`
}

type lockedSource struct {
	Git    string `json:"git"`
	URL    string `json:"url"`
	Sha256 string `json:"sha256"`
}

func parseVersionManifest(_ context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	bytes, err := io.ReadAll(reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load version-manifest.json file: %w", err)
	}

	var pkgs []pkg.Package
	var manifest versionManifest
	err = json.Unmarshal(bytes, &manifest)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse version-manifest.json file: %w", err)
	}

	for pkgName, pkgData := range manifest.Software {
		p := pkg.Package{
			Name:      pkgName,
			Locations: file.NewLocationSet(reader.Location),
		}

		if pkgData.DisplayVersion != nil {
			p.Version = *pkgData.DisplayVersion
		}
		if pkgData.License != nil {
			p.Licenses = pkg.NewLicenseSet(pkg.NewLicense(*pkgData.License))
		}
		if pkgData.LockedSource != nil && (*pkgData.SourceType == "git" || *pkgData.SourceType == "url") {
			var purl packageurl.PackageURL
			if *pkgData.SourceType == "git" {
				purl.Type = "gitlab"
				gitUrlComponents := strings.Split(pkgData.LockedSource.Git, "/")
				// Namespace is the user or organization
				purl.Namespace = strings.Split(gitUrlComponents[0], ":")[1]
				// Name is the repository name (with .git sliced out)
				purl.Name = gitUrlComponents[1][:len(gitUrlComponents[1])-4]
			} else {
				purl.Type = "generic"
				purl.Qualifiers = append(
					purl.Qualifiers,
					packageurl.Qualifier{
						Key:   "download_url",
						Value: pkgData.LockedSource.URL,
					},
					packageurl.Qualifier{
						Key:   "checksum",
						Value: pkgData.LockedSource.Sha256,
					})
			}
		}

		pkgs = append(pkgs, p)
	}

	pkg.Sort(pkgs)

	return pkgs, nil, nil
}
