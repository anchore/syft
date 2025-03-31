package cpegenerate

import (
	"strings"

	"github.com/anchore/syft/syft/pkg"
)

func candidateProductsForDotnet(p pkg.Package) fieldCandidateSet {
	products := newFieldCandidateSet()

	switch m := p.Metadata.(type) {
	case pkg.DotnetDepsEntry:
		products.add(dotnetProductVariants(m.Name)...)
		for _, pe := range m.Executables {
			if pe.ProductName == "" {
				continue
			}
			products.add(dotnetProductVariants(pe.ProductName)...)
		}
	case pkg.DotnetPortableExecutableEntry:
		if m.ProductName != "" {
			products.add(dotnetProductVariants(m.ProductName)...)
		}
	case pkg.DotnetPackagesLockEntry:
		products.add(dotnetProductVariants(m.Name)...)
	}

	return products
}

func dotnetProductVariants(names ...string) []fieldCandidate {
	var variants []fieldCandidate
	for _, suff := range []string{"", "_.net"} {
		for _, name := range names {
			if name == "" {
				continue
			}
			if suff != "" && strings.HasSuffix(name, suff) {
				continue
			}
			variants = append(variants, fieldCandidate{
				value:                       normalizeDotnetReference(name) + suff,
				disallowSubSelections:       true,
				disallowDelimiterVariations: true,
			})
		}
	}
	return variants
}

func normalizeDotnetReference(name string) string {
	name = strings.TrimSpace(strings.ToLower(name))
	name = strings.TrimSuffix(name, ".dll")
	name = strings.ReplaceAll(name, "-", "_")
	name = strings.ReplaceAll(name, " ", "_")
	name = strings.ReplaceAll(name, ".", "_")
	return name
}

func candidateVendorsForDotnet(p pkg.Package) fieldCandidateSet {
	vendors := newFieldCandidateSet()

	switch m := p.Metadata.(type) {
	case pkg.DotnetDepsEntry:
		vendors.add(fieldCandidate{
			value:                       normalizeDotnetReference(m.Name),
			disallowSubSelections:       true,
			disallowDelimiterVariations: true,
		})
		for _, pe := range m.Executables {
			if pe.CompanyName == "" {
				continue
			}
			vendors.add(fieldCandidate{
				value:                       normalizeDotnetReference(pe.CompanyName),
				disallowSubSelections:       true,
				disallowDelimiterVariations: true,
			})
		}
	case pkg.DotnetPortableExecutableEntry:
		if m.CompanyName != "" {
			vendors.add(fieldCandidate{
				value:                       normalizeDotnetReference(m.CompanyName),
				disallowSubSelections:       true,
				disallowDelimiterVariations: true,
			})
		}
	case pkg.DotnetPackagesLockEntry:
		vendors.add(fieldCandidate{
			value:                       normalizeDotnetReference(m.Name),
			disallowSubSelections:       true,
			disallowDelimiterVariations: true,
		})
	}

	return vendors
}
