package terraform

import (
	"context"
	"fmt"
	"io"

	"github.com/hashicorp/hcl/v2/hclsimple"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

type terraformLockFile struct {
	Providers []pkg.TerraformLockEntry `hcl:"provider,block"`
}

func parseTerraformLock(_ context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	var lockFile terraformLockFile

	contents, err := io.ReadAll(reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read terraform lock file: %w", err)
	}

	err = hclsimple.Decode(reader.RealPath, contents, nil, &lockFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode terraform lock file: %w", err)
	}

	pkgs := make([]pkg.Package, 0, len(lockFile.Providers))

	for _, provider := range lockFile.Providers {
		p := pkg.Package{
			Name:      provider.URL,
			Version:   provider.Version,
			Locations: file.NewLocationSet(reader.Location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation)),
			Licenses:  pkg.NewLicenseSet(), // TODO: license could be found in .terraform/providers/${name}/${version}/${arch}/LICENSE.txt
			Language:  pkg.Go,
			Type:      pkg.TerraformPkg,
			PURL:      packageurl.NewPackageURL(packageurl.TypeTerraform, "", provider.URL, provider.Version, nil, "").String(),
			Metadata:  provider,
		}
		p.SetID()

		pkgs = append(pkgs, p)
	}

	return pkgs, nil, nil
}
