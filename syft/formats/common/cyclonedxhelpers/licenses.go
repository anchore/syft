package cyclonedxhelpers

import (
	"github.com/CycloneDX/cyclonedx-go"

	"github.com/anchore/syft/syft/pkg"
)

// This should be a function that just surfaces licenses already validated in the package struct
func encodeLicenses(p pkg.Package) *cyclonedx.Licenses {
	lc := cyclonedx.Licenses{}
	for _, l := range p.Licenses {
		// not found so append the licenseName as is
		lc = append(lc, cyclonedx.LicenseChoice{
			License: &cyclonedx.License{
				Name: l.Value,
				URL:  l.URL,
			},
		})
	}

	if len(lc) > 0 {
		return &lc
	}
	return nil
}

func decodeLicenses(c *cyclonedx.Component) []pkg.License {
	licenses := make([]pkg.License, 0)
	if c == nil || c.Licenses == nil {
		return licenses
	}

	for _, l := range *c.Licenses {
		var url string
		// priority: Expression -> ID -> Name
		licenseValue := l.Expression
		if l.License != nil {
			url = l.License.URL
			switch {
			case l.License.ID != "":
				licenseValue = l.License.ID
			case l.License.Name != "":
				licenseValue = l.License.Name
			}
		}

		if licenseValue == "" {
			continue
		}

		licenses = append(licenses, pkg.NewLicenseFromURL(licenseValue, url))
	}

	return licenses
}
