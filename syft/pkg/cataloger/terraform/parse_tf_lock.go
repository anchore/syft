package terraform

import (
	"context"
	"fmt"
	"io"
	"path"

	"github.com/hashicorp/hcl/v2/hclsimple"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

type terraformLockFile struct {
	Providers []pkg.TerraformLockProviderEntry `hcl:"provider,block"`
}

func (r *terraformLicenseResolver) parseTerraformLock(ctx context.Context, resolver file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	var lockFile terraformLockFile

	contents, err := io.ReadAll(reader) //nolint:gocritic // hclsimple.Decode requires []byte
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read terraform lock file: %w", err)
	}

	err = hclsimple.Decode(reader.RealPath, contents, nil, &lockFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode terraform lock file: %w", err)
	}

	lockFileDir := path.Dir(reader.Location.AccessPath)
	pkgs := make([]pkg.Package, 0, len(lockFile.Providers))

	for _, provider := range lockFile.Providers {
		licenseSet := r.getLicenses(ctx, resolver, lockFileDir, provider.URL, provider.Version)

		p := pkg.Package{
			Name:      provider.URL,
			Version:   provider.Version,
			Locations: file.NewLocationSet(reader.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation)),
			Licenses:  licenseSet,
			Language:  pkg.Go,
			Type:      pkg.TerraformPkg,
			Metadata:  provider,
			// TODO: PURL omitted from package creation until the following issue resolved
			// https://github.com/package-url/purl-spec/issues/369
		}
		p.SetID()

		pkgs = append(pkgs, p)
	}

	return pkgs, nil, nil
}
