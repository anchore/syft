package cyclonedxhelpers

import (
	"github.com/CycloneDX/cyclonedx-go"
	"github.com/anchore/syft/syft/pkg"
)

func Licenses(p pkg.Package) *cyclonedx.Licenses {
	if len(p.Licenses) == 0 {
		return nil
	}

	lc := make(cyclonedx.Licenses, len(p.Licenses))
	for i, licenseName := range p.Licenses {
		lc[i] = cyclonedx.LicenseChoice{
			License: &cyclonedx.License{
				Name: licenseName,
			},
		}
	}

	return &lc
}
