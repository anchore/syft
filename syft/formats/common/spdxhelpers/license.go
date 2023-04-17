package spdxhelpers

import (
	"strings"

	"github.com/anchore/syft/internal/spdxlicense"
	"github.com/anchore/syft/syft/pkg"
)

func License(p pkg.Package) string {
	// source: https://spdx.github.io/spdx-spec/3-package-information/#313-concluded-license
	// The options to populate this field are limited to:
	// A valid SPDX License Expression as defined in Appendix IV;
	// NONE, if the SPDX file creator concludes there is no license available for this package; or
	// NOASSERTION if:
	//   (i) the SPDX file creator has attempted to but cannot reach a reasonable objective determination;
	//   (ii) the SPDX file creator has made no attempt to determine this field; or
	//   (iii) the SPDX file creator has intentionally provided no information (no meaning should be implied by doing so).

	if len(p.Licenses) == 0 {
		return NONE
	}

	// take all licenses and assume an AND expression; for information about license expressions see https://spdx.github.io/spdx-spec/appendix-IV-SPDX-license-expressions/
	parsedLicenses := parseLicenses(p.Licenses)

	for i, v := range parsedLicenses {
		if strings.HasPrefix(v, spdxlicense.LicenseRefPrefix) {
			parsedLicenses[i] = SanitizeElementID(v)
		}
	}

	if len(parsedLicenses) == 0 {
		return NOASSERTION
	}

	return strings.Join(parsedLicenses, " AND ")
}

func parseLicenses(raw []pkg.License) (parsedLicenses []string) {
	for _, l := range raw {
		if l.SPDXExpression != "" {
			parsedLicenses = append(parsedLicenses, l.SPDXExpression)
		} else {
			// we did not find a valid SPDX license ID so treat as separate license
			otherLicense := spdxlicense.LicenseRefPrefix + l.Value
			parsedLicenses = append(parsedLicenses, otherLicense)
		}
	}
	return
}
