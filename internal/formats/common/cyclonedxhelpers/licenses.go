package cyclonedxhelpers

import (
	"github.com/CycloneDX/cyclonedx-go"
	"github.com/anchore/syft/internal/spdxlicense"
	"github.com/anchore/syft/syft/pkg"
)

func encodeLicenses(p pkg.Package) *cyclonedx.Licenses {
	lc := cyclonedx.Licenses{}
	for _, licenseName := range p.Licenses {
		if value, exists := spdxlicense.ID(licenseName); exists {
			lc = append(lc, cyclonedx.LicenseChoice{
				License: &cyclonedx.License{
					ID: value,
				},
			})
		}
	}
	if len(lc) > 0 {
		return &lc
	}
	return nil
}

func decodeLicenses(c *cyclonedx.Component) (out []string) {
	if c.Licenses != nil {
		for _, l := range *c.Licenses {
			if l.License != nil {
				out = append(out, l.License.ID)
			}
		}
	}
	return
}
