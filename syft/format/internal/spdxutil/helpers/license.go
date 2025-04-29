package helpers

import (
	"crypto/sha256"
	"fmt"
	"strings"

	"github.com/anchore/syft/internal/licenses"
	"github.com/anchore/syft/internal/spdxlicense"
	"github.com/anchore/syft/syft/license"
	"github.com/anchore/syft/syft/pkg"
)

func License(p pkg.Package) (concluded, declared string) {
	// source: https://spdx.github.io/spdx-spec/v2.3/package-information/#713-concluded-license-field
	// The options to populate this field are limited to:
	// A valid SPDX License Expression as defined in Annex D;
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
	pc, pd := ParseLicenses(p.Licenses.ToSlice())

	return joinLicenses(pc), joinLicenses(pd)
}

func joinLicenses(licenses []SPDXLicense) string {
	if len(licenses) == 0 {
		return NOASSERTION
	}

	var newLicenses []string

	for _, l := range licenses {
		v := l.ID
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

type SPDXLicense struct {
	ID       string
	Value    string
	FullText string
}

func ParseLicenses(raw []pkg.License) (concluded, declared []SPDXLicense) {
	for _, l := range raw {
		if l.Value == "" {
			continue
		}

		candidate := createSPDXLicense(l)
		switch l.Type {
		case license.Concluded:
			concluded = append(concluded, candidate)
		case license.Declared:
			declared = append(declared, candidate)
		}
	}

	return concluded, declared
}

func createSPDXLicense(l pkg.License) SPDXLicense {
	candidate := SPDXLicense{Value: l.Value}
	if isValidSPDXExpression(l.SPDXExpression) {
		candidate.ID = spdxlicense.LicenseRefPrefix + SanitizeElementID(l.SPDXExpression)
		candidate.FullText = getFullText(l)
	} else {
		candidate.ID = generateLicenseID(l)
		candidate.FullText = getFullText(l)
	}

	return candidate
}

func isValidSPDXExpression(expr string) bool {
	return expr != "" && !strings.HasPrefix(expr, licenses.UnknownLicensePrefix)
}

func getFullText(l pkg.License) string {
	if len(l.Contents) > 0 {
		return l.Contents
	}
	return l.FullText
}

func generateLicenseID(l pkg.License) string {
	if l.Value == pkg.FullTextValue {
		if len(l.FullText) <= 64 {
			return spdxlicense.LicenseRefPrefix + SanitizeElementID(l.FullText)
		}
		hash := sha256.Sum256([]byte(l.FullText))
		return fmt.Sprintf("%s%x", spdxlicense.LicenseRefPrefix, hash)
	}
	return spdxlicense.LicenseRefPrefix + SanitizeElementID(l.Value)
}
