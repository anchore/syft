package cyclonedxhelpers

import (
	"github.com/CycloneDX/cyclonedx-go"

	"github.com/anchore/syft/syft/pkg"
)

// TODO: update this to only return valid cyclonedx expression types
// This should be a function that just surfaces licenses already validated in the package struct
func encodeLicenses(p pkg.Package) *cyclonedx.Licenses {
	lc := cyclonedx.Licenses{}
	for _, l := range p.Licenses {
		if l.SPDXExpression != "" {
			lc = append(lc, cyclonedx.LicenseChoice{
				License: &cyclonedx.License{
					ID: l.SPDXExpression,
				},
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

func decodeLicenses(_ *cyclonedx.Component) []pkg.License {
	// if c.Licenses != nil {
	//	for range *c.Licenses {
	//		// TODO: switch on if it's a license or expression
	//	}
	//}
	return nil
}
