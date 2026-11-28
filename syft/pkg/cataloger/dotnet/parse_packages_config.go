package dotnet

import (
	"context"
	"encoding/xml"
	"fmt"
	"strings"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

var _ generic.Parser = parseDotnetPackagesConfig

type dotnetPackagesConfig struct {
	XMLName  xml.Name                    `xml:"packages"`
	Packages []dotnetPackagesConfigEntry `xml:"package"`
}

type dotnetPackagesConfigEntry struct {
	ID      string `xml:"id,attr"`
	Version string `xml:"version,attr"`
}

func parseDotnetPackagesConfig(_ context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	var config dotnetPackagesConfig
	if err := xml.NewDecoder(reader).Decode(&config); err != nil {
		return nil, nil, fmt.Errorf("failed to parse packages.config file: %w", err)
	}
	var packages []pkg.Package
	for _, entry := range config.Packages {
		if strings.TrimSpace(entry.ID) == "" || strings.TrimSpace(entry.Version) == "" {
			continue
		}
		// packages.config lists installed versions, including transitive dependencies.
		// allowedVersions constrains updates, not the installed version. Likewise,
		// developmentDependency controls NuGet packing and is not a runtime/dev scope.
		p := pkg.Package{
			Name:      entry.ID,
			Version:   entry.Version,
			Type:      pkg.DotnetPkg,
			Language:  pkg.Dotnet,
			Locations: file.NewLocationSet(reader.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation)),
			PURL:      packageurl.NewPackageURL(packageurl.TypeNuget, "", entry.ID, entry.Version, nil, "").ToString(),
		}
		p.SetID()
		packages = append(packages, p)
	}
	// The flat manifest does not identify direct dependencies or dependency edges.
	return packages, nil, nil
}
