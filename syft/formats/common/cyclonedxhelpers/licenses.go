package cyclonedxhelpers

import (
	"fmt"
	"strings"

	"github.com/CycloneDX/cyclonedx-go"

	"github.com/anchore/syft/internal/spdxlicense"
	"github.com/anchore/syft/syft/pkg"
)

// This should be a function that just surfaces licenses already validated in the package struct
func encodeLicenses(p pkg.Package) *cyclonedx.Licenses {
	spdxc, otherc, ex := separateLicenses(p)
	if len(otherc) > 0 {
		// found non spdx related licenses
		// build individual license choices for each
		// complex expressions are not combined and set as NAME fields
		for _, e := range ex {
			otherc = append(otherc, cyclonedx.LicenseChoice{
				License: &cyclonedx.License{
					Name: e,
				},
			})
		}
		otherc = append(otherc, spdxc...)
		return &otherc
	}

	if len(spdxc) > 0 {
		for _, l := range ex {
			spdxc = append(spdxc, cyclonedx.LicenseChoice{
				License: &cyclonedx.License{
					Name: l,
				},
			})
		}
		return &spdxc
	}

	if len(ex) > 0 {
		// only expressions found
		var expressions cyclonedx.Licenses
		expressions = append(expressions, cyclonedx.LicenseChoice{
			Expression: mergeSPDX(ex),
		})
		return &expressions
	}

	return nil
}

func decodeLicenses(c *cyclonedx.Component) []pkg.License {
	licenses := make([]pkg.License, 0)
	if c == nil || c.Licenses == nil {
		return licenses
	}

	for _, l := range *c.Licenses {
		if l.License == nil {
			continue
		}
		// these fields are mutually exclusive in the spec
		switch {
		case l.License.ID != "":
			licenses = append(licenses, pkg.NewLicenseFromURLs(l.License.ID, l.License.URL))
		case l.License.Name != "":
			licenses = append(licenses, pkg.NewLicenseFromURLs(l.License.Name, l.License.URL))
		case l.Expression != "":
			licenses = append(licenses, pkg.NewLicenseFromURLs(l.Expression, l.License.URL))
		default:
		}
	}

	return licenses
}

// nolint:funlen
func separateLicenses(p pkg.Package) (spdx, other cyclonedx.Licenses, expressions []string) {
	ex := make([]string, 0)
	spdxc := cyclonedx.Licenses{}
	otherc := cyclonedx.Licenses{}
	/*
			pkg.License can be a couple of things: see above declarations
			- Complex SPDX expression
			- Some other Valid license ID
			- Some non-standard non spdx license

			To determine if an expression is a singular ID we first run it against the SPDX license list.

		The weird case we run into is if there is a package with a license that is not a valid SPDX expression
			and a license that is a valid complex expression. In this case we will surface the valid complex expression
			as a license choice and the invalid expression as a license string.

	*/
	seen := make(map[string]bool)
	for _, l := range p.Licenses.ToSlice() {
		// singular expression case
		// only ID field here since we guarantee that the license is valid
		if value, exists := spdxlicense.ID(l.SPDXExpression); exists {
			if !l.URLs.Empty() {
				processLicenseURLs(l, value, &spdxc)
				continue
			}

			if _, exists := seen[value]; exists {
				continue
			}
			// try making set of license choices to avoid duplicates
			// only update if the license has more information
			spdxc = append(spdxc, cyclonedx.LicenseChoice{
				License: &cyclonedx.License{
					ID: value,
				},
			})
			seen[value] = true
			// we have added the license to the SPDX license list check next license
			continue
		}

		if l.SPDXExpression != "" {
			// COMPLEX EXPRESSION CASE
			ex = append(ex, l.SPDXExpression)
			continue
		}

		// license string that are not valid spdx expressions or ids
		// we only use license Name here since we cannot guarantee that the license is a valid SPDX expression
		if !l.URLs.Empty() {
			processLicenseURLs(l, "", &otherc)
			continue
		}
		otherc = append(otherc, cyclonedx.LicenseChoice{
			License: &cyclonedx.License{
				Name: l.Value,
			},
		})
	}
	return spdxc, otherc, ex
}

func processLicenseURLs(l pkg.License, spdxID string, populate *cyclonedx.Licenses) {
	for _, url := range l.URLs.ToSlice() {
		if spdxID == "" {
			*populate = append(*populate, cyclonedx.LicenseChoice{
				License: &cyclonedx.License{
					URL:  url,
					Name: l.Value,
				},
			})
		} else {
			*populate = append(*populate, cyclonedx.LicenseChoice{
				License: &cyclonedx.License{
					ID:  spdxID,
					URL: url,
				},
			})
		}
	}
}

func mergeSPDX(ex []string) string {
	var candidate []string
	for _, e := range ex {
		// if the expression does not have balanced parens add them
		if !strings.HasPrefix(e, "(") && !strings.HasSuffix(e, ")") {
			e = "(" + e + ")"
			candidate = append(candidate, e)
		}
	}

	if len(candidate) == 1 {
		return reduceOuter(strings.Join(candidate, " AND "))
	}

	return strings.Join(candidate, " AND ")
}

func reduceOuter(expression string) string {
	var (
		sb        strings.Builder
		openCount int
	)

	for _, c := range expression {
		if string(c) == "(" && openCount > 0 {
			fmt.Fprintf(&sb, "%c", c)
		}
		if string(c) == "(" {
			openCount++
			continue
		}
		if string(c) == ")" && openCount > 1 {
			fmt.Fprintf(&sb, "%c", c)
		}
		if string(c) == ")" {
			openCount--
			continue
		}
		fmt.Fprintf(&sb, "%c", c)
	}

	return sb.String()
}
