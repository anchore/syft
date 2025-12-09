package asdf

import (
	"context"
	"strings"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/common/cpe"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/licenses"
)

const asdfCataloger = "asdf"
const asdfInstallGlob = "**/.asdf/installs/*/*/bin/*"

// parseAsdfInstallations parses asdf version manager installations
func parseAsdfInstallations(ctx context.Context, resolver file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	name := ""
	version := ""

	root := -1
	parts := strings.Split(reader.AccessPath, "/")
	for i, part := range parts {
		if part == "installs" {
			root = i
			break
		}
	}

	if root < 0 {
		return nil, nil, nil
	}

	if len(parts) > root+2 {
		name = parts[root+1]
		version = parts[root+2]
	}

	if name == "" || version == "" {
		log.Debug("no name or version found at %v", reader.AccessPath)
		return nil, nil, nil
	}

	p := pkg.Package{
		Name:      name,
		Version:   version,
		FoundBy:   asdfCataloger,
		Locations: file.NewLocationSet(reader.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation)),
		Licenses:  pkg.NewLicenseSet(licenses.FindRelativeToLocations(ctx, resolver, reader.Location)...),
		Language:  "",
		Type:      pkg.BinaryPkg,
		CPEs:      nil,
		PURL:      "",
		Metadata:  nil,
	}

	p.CPEs = cpe.Generate(p)
	p.SetID()

	return []pkg.Package{p}, nil, nil
}
