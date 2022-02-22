package cyclonedxhelpers

import (
	"github.com/CycloneDX/cyclonedx-go"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/pkg"
)

func encodeCPE(p pkg.Package) string {
	// Since the CPEs in a package are sorted by specificity
	// we can extract the first CPE as the one to output in cyclonedx
	if len(p.CPEs) > 0 {
		return pkg.CPEString(p.CPEs[0])
	}
	return ""
}

func decodeCPEs(c *cyclonedx.Component) []pkg.CPE {
	// FIXME we not encoding all the CPEs (see above), so here we just use the single provided one
	if c.CPE != "" {
		cp, err := pkg.NewCPE(c.CPE)
		if err != nil {
			log.Warnf("invalid CPE: %s", c.CPE)
		} else {
			return []pkg.CPE{cp}
		}
	}

	return []pkg.CPE{}
}
