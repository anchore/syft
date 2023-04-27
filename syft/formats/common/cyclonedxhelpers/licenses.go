package cyclonedxhelpers

import (
	"github.com/CycloneDX/cyclonedx-go"

	"github.com/anchore/syft/internal/spdxlicense"
	"github.com/anchore/syft/syft/pkg"
)

// This should be a function that just surfaces licenses already validated in the package struct
func encodeLicenses(p pkg.Package) *cyclonedx.Licenses {
	// TODO: if all licenses are SPDX expressions, then we can combine them into a single SPDX expression
	// and use that rather than individual licenses
	lc := cyclonedx.Licenses{}
	for _, l := range p.Licenses {
		var id string
		if value, exists := spdxlicense.ID(l.SPDXExpression); exists {
			id = value
		}

		lc = append(lc, cyclonedx.LicenseChoice{
			License: &cyclonedx.License{
				ID:   id,
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
		if l.License == nil {
			continue
		}
		licenses = append(licenses, pkg.NewLicenseFromURL(l.License.Name, l.License.URL))
	}

	return licenses
}
