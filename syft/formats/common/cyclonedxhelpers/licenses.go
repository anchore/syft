package cyclonedxhelpers

import (
	"github.com/CycloneDX/cyclonedx-go"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

// This should be a function that just surfaces licenses already validated in the package struct
func encodeLicenses(p pkg.Package) *cyclonedx.Licenses {
	lc := cyclonedx.Licenses{}
	for _, l := range p.Licenses {
		if l.SPDXExpression != "" {
			lc = append(lc, cyclonedx.LicenseChoice{
				License: &cyclonedx.License{
					ID: l.SPDXExpression,
				},
				Expression: l.SPDXExpression,
			})
		} else {
			// not found so append the licenseName as is
			lc = append(lc, cyclonedx.LicenseChoice{
				License: &cyclonedx.License{
					Name: l.Value,
				},
			})
		}
	}

	if len(lc) > 0 {
		return &lc
	}
	return nil
}

func decodeLicenses(c *cyclonedx.Component) []pkg.License {
	licenses := make([]pkg.License, 0)
	if c.Licenses != nil {
		for _, l := range *c.Licenses {
			licenseValue := l.License.ID
			if l.Expression != "" {
				licenseValue = l.Expression
			}

			if licenseValue == "" {
				licenseValue = l.License.Name
			}

			var licenseLocation *source.Location
			licenses = append(licenses, pkg.NewLicense(licenseValue, l.License.URL, licenseLocation))
		}
	}
	return licenses
}
