package spdxhelpers

import (
	"crypto/sha256"
	"fmt"
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

	if p.Licenses.Empty() {
		return NOASSERTION, NOASSERTION
	}

	// take all licenses and assume an AND expression;
	// for information about license expressions see:
	// https://spdx.github.io/spdx-spec/v2.3/SPDX-license-expressions/
	pc, pd := parseLicenses(p.Licenses.ToSlice())

	return joinLicenses(pc), joinLicenses(pd)
}

func joinLicenses(licenses []spdxLicense) string {
	if len(licenses) == 0 {
		return NOASSERTION
	}

	var newLicenses []string

	for _, l := range licenses {
		v := l.id
		// check if license does not start or end with parens
		if !strings.HasPrefix(v, "(") && !strings.HasSuffix(v, ")") {
			// if license contains AND, OR, or WITH, then wrap in parens
			if strings.Contains(v, " AND ") ||
				strings.Contains(v, " OR ") ||
				strings.Contains(v, " WITH ") {
				newLicenses = append(newLicenses, "("+v+")")
				continue
			}
		}
		newLicenses = append(newLicenses, v)
	}

	return strings.Join(newLicenses, " AND ")
}

type spdxLicense struct {
	id    string
	value string
}

func parseLicenses(raw []pkg.License) (concluded, declared []spdxLicense) {
	for _, l := range raw {
		if l.Value == "" {
			continue
		}

		candidate := spdxLicense{}
		if l.SPDXExpression != "" {
			candidate.id = l.SPDXExpression
		} else {
			// we did not find a valid SPDX license ID so treat as separate license
			if len(l.Value) <= 64 {
				// if the license text is less than the size of the hash,
				// just use it directly so the id is more readable
				candidate.id = spdxlicense.LicenseRefPrefix + SanitizeElementID(l.Value)
			} else {
				hash := sha256.Sum256([]byte(l.Value))
				candidate.id = fmt.Sprintf("%s%x", spdxlicense.LicenseRefPrefix, hash)
			}
			candidate.value = l.Value
		}

		switch l.Type {
		case license.Concluded:
			concluded = append(concluded, candidate)
		case license.Declared:
			declared = append(declared, candidate)
		}
	}

	return concluded, declared
}
