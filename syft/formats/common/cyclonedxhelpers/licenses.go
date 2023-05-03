package cyclonedxhelpers

import (
	"fmt"
	"sort"
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
		// complex expressions are combined and set as NAME fields
		for _, e := range ex {
			otherc = append(otherc, cyclonedx.LicenseChoice{
				License: &cyclonedx.License{
					Name: e,
				},
			})
		}
		otherc = append(otherc, spdxc...)
		sort.Slice(otherc, func(i, j int) bool {
			ilicese := otherc[i].License.ID
			jlicese := otherc[j].License.ID
			if ilicese == "" {
				ilicese = otherc[i].License.Name
			}
			if jlicese == "" {
				jlicese = otherc[j].License.Name
			}
			return strings.Compare(ilicese, jlicese) < 0
		})
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

func decodeLicenses(c *cyclonedx.Component) pkg.LicenseSet {
	licenses := pkg.NewLicenseSet()
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
			licenses.Add(pkg.NewLicenseFromURL(l.License.ID, l.License.URL))
		case l.License.Name != "":
			licenses.Add(pkg.NewLicenseFromURL(l.License.Name, l.License.URL))
		case l.Expression != "":
			licenses.Add(pkg.NewLicenseFromURL(l.Expression, l.License.URL))
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
	cdxLSet := map[cyclonedx.License]struct{}{}
	for _, l := range p.Licenses.ToSlice() {
		// check if the license is a singular ID; valid expression case
		if spdxID, exists := spdxlicense.ID(l.SPDXExpression); exists {
			// we've already seen this ID
			// we have not seen the ID
			// add a license for each URL
			// no url found
			if len(l.URL.ToSlice()) > 0 {
				for _, u := range l.URL.ToSlice() {
					license := cyclonedx.License{
						ID:  spdxID,
						URL: u,
					}
					cdxLSet[license] = struct{}{}
				}
				continue
			}
			license := cyclonedx.License{
				ID: spdxID,
			}
			cdxLSet[license] = struct{}{}
			continue
		}

		if l.SPDXExpression != "" {
			// COMPLEX EXPRESSION CASE: do we instead break the spdx expression out
			// into individual licenses OR combine singular licenses into a single expression?
			ex = append(ex, l.SPDXExpression)
			continue
		}

		urls := l.URL.ToSlice()
		if len(urls) > 0 {
			for _, url := range urls {
				otherc = append(otherc, cyclonedx.LicenseChoice{
					License: &cyclonedx.License{
						Name: l.Value,
						URL:  url,
					},
				})
			}
			continue
		}
		otherc = append(otherc, cyclonedx.LicenseChoice{
			License: &cyclonedx.License{
				Name: l.Value,
			},
		})
	}

	for key, _ := range cdxLSet {
		key := key
		spdxc = append(spdxc, cyclonedx.LicenseChoice{
			License: &key,
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
