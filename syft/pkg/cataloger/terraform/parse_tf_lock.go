package terraform

import (
	"context"
	"fmt"
	"io"

	"github.com/anchore/packageurl-go"
	"github.com/hashicorp/hcl/v2/hclsimple"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

type lockFile struct {
	Providers []struct {
		URL         string   `hcl:",label"`
		Constraints string   `hcl:"constraints"`
		Version     string   `hcl:"version"`
		Hashes      []string `hcl:"hashes"`
	} `hcl:"provider,block"`
}

func parseTerraformLock(_ context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	var lockFile lockFile

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
		pkg := pkg.Package{
			Name:      provider.URL,
			Version:   provider.Version,
			FoundBy:   "terraform-cataloger",
			Locations: file.NewLocationSet(reader.Location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation)),
			//Licenses:  nil,
			//Language:  nil,
			Type: pkg.TerraformPkg,
			//CPEs: nil,
			PURL: packageurl.NewPackageURL(packageurl.TypeTerraform, "", provider.URL, provider.Version, nil, "").String(),
			Metadata: []pkg.KeyValue{
				{
					Key:   "constraints",
					Value: provider.Constraints,
				},
			},
		}
		pkg.SetID()

		pkgs = append(pkgs, pkg)
	}

	return pkgs, nil, nil
}
