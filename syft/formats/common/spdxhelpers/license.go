package spdxhelpers

import (
	"strings"

	"github.com/anchore/syft/internal/spdxlicense"
	"github.com/anchore/syft/syft/license"
	"github.com/anchore/syft/syft/pkg"
)

func License(p pkg.Package) (concluded, declared string) {
	// source: https://spdx.github.io/spdx-spec/3-package-information/#313-concluded-license
	// The options to populate this field are limited to:
	// A valid SPDX License Expression as defined in Appendix IV;
	// NONE, if the SPDX file creator concludes there is no license available for this package; or
	// NOASSERTION if:
	//   (i) the SPDX file creator has attempted to but cannot reach a reasonable objective determination;
	//   (ii) the SPDX file creator has made no attempt to determine this field; or
	//   (iii) the SPDX file creator has intentionally provided no information (no meaning should be implied by doing so).

	if len(p.Licenses) == 0 {
		return NOASSERTION, NOASSERTION
	}

	// take all licenses and assume an AND expression;
	// for information about license expressions see:
	// https://spdx.github.io/spdx-spec/v2.3/SPDX-license-expressions/
	pc, pd := parseLicenses(p.Licenses)

	for i, v := range pc {
		if strings.HasPrefix(v, spdxlicense.LicenseRefPrefix) {
			pc[i] = SanitizeElementID(v)
		}
	}

	for i, v := range pd {
		if strings.HasPrefix(v, spdxlicense.LicenseRefPrefix) {
			pd[i] = SanitizeElementID(v)
		}
	}

	if len(pc) != 0 {
		concluded = strings.Join(pc, " AND ")
	} else {
		concluded = NOASSERTION
	}

	if len(pd) != 0 {
		declared = strings.Join(pd, " AND ")
	} else {
		declared = NOASSERTION
	}

	return concluded, declared
}

func parseLicenses(raw []pkg.License) (concluded, declared []string) {
	c := make([]string, 0)
	d := make([]string, 0)
	for _, l := range raw {
		var candidate string
		if l.SPDXExpression != "" {
			candidate = l.SPDXExpression
		} else {
			// we did not find a valid SPDX license ID so treat as separate license
			candidate = spdxlicense.LicenseRefPrefix + l.Value
		}

		switch l.Type {
		case license.Concluded:
			c = append(c, candidate)
		case license.Declared:
			d = append(d, candidate)
		}
	}
	return c, d
}
