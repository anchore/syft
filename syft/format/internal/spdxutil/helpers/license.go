package helpers

import (
	"strings"

	"github.com/spdx/tools-golang/spdx"

	"github.com/anchore/syft/syft/license"
	"github.com/anchore/syft/syft/pkg"
)

func License(p pkg.Package) (concluded, declared string, otherLicenses []spdx.OtherLicense) {
	// source: https://spdx.github.io/spdx-spec/v2.3/package-information/#713-concluded-license-field
	// The options to populate this field are limited to:
	// A valid SPDX License Expression as defined in Annex D;
	// NONE, if the SPDX file creator concludes there is no license available for this package; or
	// NOASSERTION if:
	//   (i) the SPDX file creator has attempted to but cannot reach a reasonable objective determination;
	//   (ii) the SPDX file creator has made no attempt to determine this field; or
	//   (iii) the SPDX file creator has intentionally provided no information (no meaning should be implied by doing so).

	if p.Licenses.Empty() {
		return NOASSERTION, NOASSERTION, nil
	}

	// take all licenses and assume an AND expression;
	// for information about license expressions see:
	// https://spdx.github.io/spdx-spec/v2.3/SPDX-license-expressions/
	pc, pd, ol := ParseLicenses(p.Licenses.ToSlice())

	return joinLicenses(pc), joinLicenses(pd), ol
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
	// Valid SPDX ID OR License Value (should have LicenseRef- prefix and be sanitized)
	// OR combination of the above as a valid SPDX License Expression as defined in Annex D.
	// https://spdx.github.io/spdx-spec/v2.3/SPDX-license-expressions/
	ID string
	// If the SPDX license is not on the SPDX License List
	LicenseName string
	FullText    string // 0..1 (Mandatory, one) if there is a License Identifier assigned (LicenseRef).
}

func ParseLicenses(raw []pkg.License) (concluded, declared []SPDXLicense, otherLicenses []spdx.OtherLicense) {
	for _, l := range raw {
		candidate := createSPDXLicense(l)

		// only add an OtherLicense if the raw license didn't present a valid SPDX license expression
		if l.SPDXExpression == "" && strings.Contains(candidate.ID, "LicenseRef-") {
			otherLicenses = append(otherLicenses, spdx.OtherLicense{
				LicenseIdentifier: candidate.ID,
				ExtractedText:     candidate.FullText,
				LicenseName:       candidate.LicenseName,
			})
		}
		switch l.Type {
		case license.Concluded:
			concluded = append(concluded, candidate)
		case license.Declared:
			declared = append(declared, candidate)
		}
	}

	return concluded, declared, otherLicenses
}

func createSPDXLicense(l pkg.License) SPDXLicense {
	var candidate SPDXLicense
	candidate.ID = generateLicenseID(l)
	if strings.Contains(candidate.ID, "LicenseRef-") {
		candidate.LicenseName = l.Value
		candidate.FullText = "UNKNOWN" // we need to populate this field with the license text if we have a license ref
		// TODO: does this need to be configured with the new SBOMBuilder contents switch?
		if l.Contents != "" {
			candidate.FullText = l.Contents
		}
	}
	return candidate
}

func generateLicenseID(l pkg.License) string {
	if l.SPDXExpression != "" {
		return l.SPDXExpression
	}

	id := strings.ReplaceAll(l.Value, "sha256:", "")
	if !strings.HasPrefix(id, "LicenseRef-") {
		id = "LicenseRef-" + id
	}
	return SanitizeElementID(id)
}

type SPDXOtherLicenseSet struct {
	set map[string]spdx.OtherLicense
}

func NewSPDXOtherLicenseSet() *SPDXOtherLicenseSet {
	return &SPDXOtherLicenseSet{
		set: make(map[string]spdx.OtherLicense),
	}
}

func (s *SPDXOtherLicenseSet) Add(licenses ...spdx.OtherLicense) {
	for _, l := range licenses {
		s.set[l.LicenseIdentifier] = l
	}
}

func (s *SPDXOtherLicenseSet) ToSlice() []spdx.OtherLicense {
	values := make([]spdx.OtherLicense, 0, len(s.set))
	for _, v := range s.set {
		values = append(values, v)
	}
	return values
}
