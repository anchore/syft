package helpers

import (
	"github.com/CycloneDX/cyclonedx-go"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/pkg"
)

func encodeSingleCPE(p pkg.Package) string {
	// Since the CPEs in a package are sorted by specificity
	// we can extract the first CPE as the one to output in cyclonedx
	if len(p.CPEs) > 0 {
		return p.CPEs[0].Attributes.String()
	}
	return ""
}

func encodeCPEs(p pkg.Package) (out []cyclonedx.Property) {
	for i, c := range p.CPEs {
		// first CPE is "most specific" and already encoded as the component CPE
		if i == 0 {
			continue
		}
		out = append(out, cyclonedx.Property{
			Name:  "syft:cpe23",
			Value: c.Attributes.String(),
		})
	}
	return
}

func decodeCPEs(c *cyclonedx.Component) (out []cpe.CPE) {
	if c.CPE != "" {
		cp, err := cpe.New(c.CPE, cpe.DeclaredSource)
		if err != nil {
			log.Warnf("invalid CPE: %s", c.CPE)
		} else {
			out = append(out, cp)
		}
	}

	if c.Properties != nil {
		for _, p := range *c.Properties {
			if p.Name == "syft:cpe23" {
				cp, err := cpe.New(p.Value, cpe.DeclaredSource)
				if err != nil {
					log.Warnf("invalid CPE: %s", p.Value)
				} else {
					out = append(out, cp)
				}
			}
		}
	}

	return
}
