package cyclonedxhelpers

import (
	"github.com/CycloneDX/cyclonedx-go"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/spdxlicense"
	"github.com/anchore/syft/syft/pkg"
)

func encodeLicenses(p pkg.Package) *cyclonedx.Licenses {
	lc := cyclonedx.Licenses{}
	for _, licenseName := range p.Licenses.Elements() {
		if value, other, exists := spdxlicense.ID(licenseName); exists {
			lc = append(lc, cyclonedx.LicenseChoice{
				License: &cyclonedx.License{
					ID:   value,
					Name: other,
				},
			})
		}
	}
	if len(lc) > 0 {
		return &lc
	}
	return nil
}

func decodeLicenses(c *cyclonedx.Component) (ls internal.LogicalStrings) {
	var out []string
	if c.Licenses != nil {
		for _, l := range *c.Licenses {
			if l.License != nil {
				var lic string
				switch {
				case l.License.ID != "":
					lic = l.License.ID
				case l.License.Name != "":
					lic = l.License.Name
				default:
					continue
				}
				out = append(out, lic)
			}
		}
		ls.Simple = out
		ls.Joiner = internal.AND
	}
	return
}
