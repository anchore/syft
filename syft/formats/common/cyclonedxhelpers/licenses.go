package cyclonedxhelpers

import (
	"github.com/CycloneDX/cyclonedx-go"

	"github.com/anchore/syft/syft/pkg"
)

// TODO: update this to only return valid cyclonedx expression types
// This should be a function that just surfaces licenses already validated in the package struct
func encodeLicenses(_ pkg.Package) *cyclonedx.Licenses {
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
