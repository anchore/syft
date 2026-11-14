package helpers

import (
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/spdx/tools-golang/spdx"

	"github.com/anchore/syft/internal/spdxlicense"
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
	URLs        []string
}

func ParseLicenses(raw []pkg.License) (concluded, declared []SPDXLicense, otherLicenses []spdx.OtherLicense) {
	for _, l := range raw {
		candidate := createSPDXLicense(l)

		// this determines if the candidate falls under https://spdx.github.io/spdx-spec/v2.3/other-licensing-information-detected/#
		// of the SPDX spec, where:
		// - we should not have a complex SPDX expression
		// - if a single license, it should not be a known license (on the SPDX license list)
		if l.SPDXExpression == "" && strings.Contains(candidate.ID, spdxlicense.LicenseRefPrefix) {
			otherLicenses = append(otherLicenses, spdx.OtherLicense{
				LicenseIdentifier:      candidate.ID,
				ExtractedText:          candidate.FullText,
				LicenseName:            candidate.LicenseName,
				LicenseCrossReferences: candidate.URLs,
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
	// source: https://spdx.github.io/spdx-spec/v2.3/other-licensing-information-detected/#102-extracted-text-field
	// we need to populate this field in the spdx document if we have a license ref
	// 0..1 (Mandatory, one) if there is a License Identifier assigned (LicenseRef).
	ft := NOASSERTION
	if l.Contents != "" {
		ft = l.Contents
	}

	return SPDXLicense{
		ID:          generateLicenseID(l),
		LicenseName: l.Value,
		FullText:    ft,
		URLs:        l.URLs,
	}
}

// generateLicenseID generates a license ID for the given license, which is either the license value or the SPDX expression.
func generateLicenseID(l pkg.License) string {
	if l.SPDXExpression != "" {
		return l.SPDXExpression
	}

	// syft format includes the algo for the sha in the values
	// we can strip this and just make LicenseRef-<sum> for spdx consumption
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

// DeduplicateIDs makes sure no two license identifiers in the set differ only by case. SPDX license identifiers
// are matched case-insensitively, so such identifiers would name the same license and make the document invalid.
// Licenses with the same extracted text and a name that differs only by case are merged into a single entry,
// any other clash gets a numeric suffix. The returned map holds each identifier that was replaced and the
// identifier that replaces it, so that license expressions referring to it can be updated (see ReplaceLicenseIDs).
func (s *SPDXOtherLicenseSet) DeduplicateIDs() map[string]string {
	renamed := make(map[string]string)

	ids := make([]string, 0, len(s.set))
	taken := make(map[string]bool, len(s.set))
	for id := range s.set {
		ids = append(ids, id)
		taken[strings.ToLower(id)] = true
	}
	// sort so that the identifier kept for a group of clashing identifiers is stable
	sort.Strings(ids)

	kept := make(map[string]spdx.OtherLicense)
	for _, id := range ids {
		key := strings.ToLower(id)
		existing, ok := kept[key]
		if !ok {
			kept[key] = s.set[id]
			continue
		}

		l := s.set[id]
		delete(s.set, id)

		if l.ExtractedText == existing.ExtractedText && strings.EqualFold(l.LicenseName, existing.LicenseName) {
			renamed[id] = existing.LicenseIdentifier
			continue
		}

		newID := id + "-2"
		for i := 3; taken[strings.ToLower(newID)]; i++ {
			newID = id + "-" + strconv.Itoa(i)
		}
		taken[strings.ToLower(newID)] = true

		l.LicenseIdentifier = newID
		s.set[newID] = l
		renamed[id] = newID
	}

	return renamed
}

var licenseExpressionTermPattern = regexp.MustCompile(`[^\s()]+`)

// ReplaceLicenseIDs replaces the license identifiers in the given SPDX license expression that are keys of the
// renamed map with their mapped values.
func ReplaceLicenseIDs(expression string, renamed map[string]string) string {
	if len(renamed) == 0 {
		return expression
	}
	return licenseExpressionTermPattern.ReplaceAllStringFunc(expression, func(term string) string {
		if id, ok := renamed[term]; ok {
			return id
		}
		return term
	})
}

type ByLicenseIdentifier []spdx.OtherLicense

func (o ByLicenseIdentifier) Len() int      { return len(o) }
func (o ByLicenseIdentifier) Swap(i, j int) { o[i], o[j] = o[j], o[i] }
func (o ByLicenseIdentifier) Less(i, j int) bool {
	return o[i].LicenseIdentifier < o[j].LicenseIdentifier
}

func (s *SPDXOtherLicenseSet) ToSlice() []spdx.OtherLicense {
	values := make([]spdx.OtherLicense, 0, len(s.set))
	for _, v := range s.set {
		values = append(values, v)
	}
	sort.Sort(ByLicenseIdentifier(values))
	return values
}
