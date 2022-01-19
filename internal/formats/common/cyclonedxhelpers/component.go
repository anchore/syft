package cyclonedxhelpers

import (
	"github.com/CycloneDX/cyclonedx-go"
	"github.com/anchore/syft/syft/pkg"
)

func Component(p pkg.Package) cyclonedx.Component {
	return cyclonedx.Component{
		Type:               cyclonedx.ComponentTypeLibrary,
		Name:               p.Name,
		Version:            p.Version,
		PackageURL:         p.PURL,
		Licenses:           Licenses(p),
		CPE:                CPE(p),
		Author:             Author(p),
		Publisher:          Publisher(p),
		Description:        Description(p),
		ExternalReferences: ExternalReferences(p),
		Properties:         Properties(p),
	}
}

func hasMetadata(p pkg.Package) bool {
	return p.Metadata != nil
}
