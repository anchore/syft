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

	if len(ex) > 0 {
		return &cyclonedx.Licenses{
			cyclonedx.LicenseChoice{
				Expression: mergeSPDX(ex, spdxc),
			},
		}
	}

	if len(spdxc) > 0 {
		return &spdxc
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
			licenses = append(licenses, pkg.NewLicenseFromURL(l.License.ID, l.License.URL))
		case l.License.Name != "":
			licenses = append(licenses, pkg.NewLicenseFromURL(l.License.Name, l.License.URL))
		case l.Expression != "":
			licenses = append(licenses, pkg.NewLicenseFromURL(l.Expression, l.License.URL))
		default:
		}
	}

	return licenses
}

func separateLicenses(p pkg.Package) (spdx, other cyclonedx.Licenses, expressions []string) {
	spdxc := cyclonedx.Licenses{}
	otherc := cyclonedx.Licenses{}
	ex := make([]string, 0)
	/*
			pkg.License can be a couple of things:
			- Complex SPDX expression
			- Some other Valid license ID
			- Some non standard non spdx license

			To determine if an expression is a singular ID we first run it against the SPDX license list.

		The weird case we run into is if there is a package with a license that is not a valid SPDX expression
			and a license that is a valid complex expression. In this case we will surface the valid complex expression
			as a license choice and the invalid expression as a license string.

	*/
	for _, l := range p.Licenses {
		// singular expression case
		if value, exists := spdxlicense.ID(l.SPDXExpression); exists {
			spdxc = append(spdxc, cyclonedx.LicenseChoice{
				License: &cyclonedx.License{
					ID:  value,
					URL: l.URL,
				},
			})
			continue
		}
		if l.SPDXExpression != "" {
			// COMPLEX EXPRESSION CASE: do we instead break the spdx expression out
			// into individual licenses OR combine singular licenses into a single expression?
			ex = append(ex, l.SPDXExpression)
			continue
		}

		// license string that are not valid spdx expressions or ids
		otherc = append(otherc, cyclonedx.LicenseChoice{
			License: &cyclonedx.License{
				Name: l.Value,
				URL:  l.URL,
			},
		})
	}
	return spdxc, otherc, ex
}

func mergeSPDX(ex []string, spdxc cyclonedx.Licenses) string {
	var candidate []string
	for _, e := range ex {
		// if the expression does not have balanced parens add them
		if !strings.HasPrefix(e, "(") && !strings.HasSuffix(e, ")") {
			e = "(" + e + ")"
			candidate = append(candidate, e)
		}
	}

	for _, l := range spdxc {
		candidate = append(candidate, l.License.ID)
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
