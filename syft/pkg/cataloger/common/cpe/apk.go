package cpe

import (
	"strings"

	"github.com/anchore/syft/syft/pkg"
)

var (
	pythonPrefixes = []string{"py-", "py2-", "py3-"}
	rubyPrefixes   = []string{"ruby-"}
)

func pythonCandidateVendorsFromName(v string) fieldCandidateSet {
	vendors := newFieldCandidateSet()
	vendors.add(fieldCandidate{
		value:                       v,
		disallowSubSelections:       true,
		disallowDelimiterVariations: true,
	})

	vendors.addValue(findAdditionalVendors(defaultCandidateAdditions, pkg.PythonPkg, v, v)...)
	vendors.removeByValue(findVendorsToRemove(defaultCandidateRemovals, pkg.PythonPkg, v)...)

	for _, av := range additionalVendorsForPython(v) {
		vendors.add(fieldCandidate{
			value:                       av,
			disallowSubSelections:       true,
			disallowDelimiterVariations: true,
		})
		vendors.addValue(findAdditionalVendors(defaultCandidateAdditions, pkg.PythonPkg, av, av)...)
		vendors.removeByValue(findVendorsToRemove(defaultCandidateRemovals, pkg.PythonPkg, av)...)
	}

	return vendors
}

func pythonCandidateVendorsFromAPK(m pkg.ApkMetadata) fieldCandidateSet {
	vendors := newFieldCandidateSet()

	for _, p := range pythonPrefixes {
		if strings.HasPrefix(m.Package, p) {
			t := strings.ToLower(strings.TrimPrefix(m.Package, p))
			vendors.union(pythonCandidateVendorsFromName(t))
		}

		if m.OriginPackage != m.Package && strings.HasPrefix(m.OriginPackage, p) {
			t := strings.ToLower(strings.TrimPrefix(m.OriginPackage, p))
			vendors.union(pythonCandidateVendorsFromName(t))
		}
	}

	return vendors
}

func pythonCandidateProductsFromName(p string) fieldCandidateSet {
	products := newFieldCandidateSet()
	products.add(fieldCandidate{
		value:                       p,
		disallowSubSelections:       true,
		disallowDelimiterVariations: true,
	})

	products.addValue(findAdditionalProducts(defaultCandidateAdditions, pkg.PythonPkg, p)...)
	products.removeByValue(findProductsToRemove(defaultCandidateRemovals, pkg.PythonPkg, p)...)
	return products
}

func pythonCandidateProductsFromAPK(m pkg.ApkMetadata) fieldCandidateSet {
	products := newFieldCandidateSet()

	for _, p := range pythonPrefixes {
		if strings.HasPrefix(m.Package, p) {
			t := strings.ToLower(strings.TrimPrefix(m.Package, p))
			products.union(pythonCandidateProductsFromName(t))
		}

		if m.OriginPackage != m.Package && strings.HasPrefix(m.OriginPackage, p) {
			t := strings.ToLower(strings.TrimPrefix(m.OriginPackage, p))
			products.union(pythonCandidateProductsFromName(t))
		}
	}

	return products
}

func rubyCandidateVendorsFromName(v string) fieldCandidateSet {
	vendors := newFieldCandidateSet()
	vendors.add(fieldCandidate{
		value:                       v,
		disallowSubSelections:       true,
		disallowDelimiterVariations: true,
	})

	vendors.addValue(findAdditionalVendors(defaultCandidateAdditions, pkg.GemPkg, v, v)...)
	vendors.removeByValue(findVendorsToRemove(defaultCandidateRemovals, pkg.GemPkg, v)...)
	return vendors
}

func rubyCandidateVendorsFromAPK(m pkg.ApkMetadata) fieldCandidateSet {
	vendors := newFieldCandidateSet()

	for _, p := range rubyPrefixes {
		if strings.HasPrefix(m.Package, p) {
			t := strings.ToLower(strings.TrimPrefix(m.Package, p))
			vendors.union(rubyCandidateVendorsFromName(t))
		}

		if m.OriginPackage != m.Package && strings.HasPrefix(m.OriginPackage, p) {
			t := strings.ToLower(strings.TrimPrefix(m.OriginPackage, p))
			vendors.union(rubyCandidateVendorsFromName(t))
		}
	}

	return vendors
}

func rubyCandidateProductsFromName(p string) fieldCandidateSet {
	products := newFieldCandidateSet()
	products.add(fieldCandidate{
		value:                       p,
		disallowSubSelections:       true,
		disallowDelimiterVariations: true,
	})

	products.addValue(findAdditionalProducts(defaultCandidateAdditions, pkg.GemPkg, p)...)
	products.removeByValue(findProductsToRemove(defaultCandidateRemovals, pkg.GemPkg, p)...)
	return products
}

func rubyCandidateProductsFromAPK(m pkg.ApkMetadata) fieldCandidateSet {
	products := newFieldCandidateSet()

	for _, p := range rubyPrefixes {
		if strings.HasPrefix(m.Package, p) {
			t := strings.ToLower(strings.TrimPrefix(m.Package, p))
			products.union(rubyCandidateProductsFromName(t))
		}

		if m.OriginPackage != m.Package && strings.HasPrefix(m.OriginPackage, p) {
			t := strings.ToLower(strings.TrimPrefix(m.OriginPackage, p))
			products.union(rubyCandidateProductsFromName(t))
		}
	}

	return products
}

func candidateVendorsForAPK(p pkg.Package) fieldCandidateSet {
	metadata, ok := p.Metadata.(pkg.ApkMetadata)
	if !ok {
		return nil
	}

	vendors := newFieldCandidateSet()
	vendors.union(pythonCandidateVendorsFromAPK(metadata))
	vendors.union(rubyCandidateVendorsFromAPK(metadata))

	return vendors
}

func candidateProductsForAPK(p pkg.Package) fieldCandidateSet {
	metadata, ok := p.Metadata.(pkg.ApkMetadata)
	if !ok {
		return nil
	}

	products := newFieldCandidateSet()
	products.union(pythonCandidateProductsFromAPK(metadata))
	products.union(rubyCandidateProductsFromAPK(metadata))

	return products
}
