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
	vendors.addValue(v)
	vendors.addValue(findAdditionalVendors(defaultCandidateAdditions, pkg.PythonPkg, v, v)...)
	vendors.removeByValue(findVendorsToRemove(defaultCandidateRemovals, pkg.PythonPkg, v)...)

	for _, av := range additionalVendorsForPython(v) {
		vendors.addValue(av)
		vendors.addValue(findAdditionalVendors(defaultCandidateAdditions, pkg.PythonPkg, av, av)...)
		vendors.removeByValue(findVendorsToRemove(defaultCandidateRemovals, pkg.PythonPkg, av)...)
	}

	return vendors
}

func pythonCandidateVendorsFromAPK(m pkg.ApkMetadata) fieldCandidateSet {
	vendors := newFieldCandidateSet()
	upstream := m.Upstream()

	for _, p := range pythonPrefixes {
		if strings.HasPrefix(m.Package, p) {
			t := strings.ToLower(strings.TrimPrefix(m.Package, p))
			vendors.union(pythonCandidateVendorsFromName(t))
		}

		if upstream != m.Package && strings.HasPrefix(upstream, p) {
			t := strings.ToLower(strings.TrimPrefix(upstream, p))
			vendors.union(pythonCandidateVendorsFromName(t))
		}
	}

	return vendors
}

func pythonCandidateProductsFromName(p string) fieldCandidateSet {
	products := newFieldCandidateSet()
	products.addValue(p)
	products.addValue(findAdditionalProducts(defaultCandidateAdditions, pkg.PythonPkg, p)...)
	products.removeByValue(findProductsToRemove(defaultCandidateRemovals, pkg.PythonPkg, p)...)
	return products
}

func pythonCandidateProductsFromAPK(m pkg.ApkMetadata) fieldCandidateSet {
	products := newFieldCandidateSet()
	upstream := m.Upstream()

	for _, p := range pythonPrefixes {
		if strings.HasPrefix(m.Package, p) {
			t := strings.ToLower(strings.TrimPrefix(m.Package, p))
			products.union(pythonCandidateProductsFromName(t))
		}

		if upstream != m.Package && strings.HasPrefix(upstream, p) {
			t := strings.ToLower(strings.TrimPrefix(upstream, p))
			products.union(pythonCandidateProductsFromName(t))
		}
	}

	return products
}

func rubyCandidateVendorsFromName(v string) fieldCandidateSet {
	vendors := newFieldCandidateSet()
	vendors.addValue(v)
	vendors.addValue(findAdditionalVendors(defaultCandidateAdditions, pkg.GemPkg, v, v)...)
	vendors.removeByValue(findVendorsToRemove(defaultCandidateRemovals, pkg.GemPkg, v)...)
	return vendors
}

func rubyCandidateVendorsFromAPK(m pkg.ApkMetadata) fieldCandidateSet {
	vendors := newFieldCandidateSet()
	upstream := m.Upstream()

	if upstream != "ruby" {
		for _, p := range rubyPrefixes {
			if strings.HasPrefix(m.Package, p) {
				t := strings.ToLower(strings.TrimPrefix(m.Package, p))
				vendors.union(rubyCandidateVendorsFromName(t))
			}

			if upstream != "" && upstream != m.Package && strings.HasPrefix(upstream, p) {
				t := strings.ToLower(strings.TrimPrefix(upstream, p))
				vendors.union(rubyCandidateVendorsFromName(t))
			}
		}
	}

	return vendors
}

func rubyCandidateProductsFromName(p string) fieldCandidateSet {
	products := newFieldCandidateSet()
	products.addValue(p)
	products.addValue(findAdditionalProducts(defaultCandidateAdditions, pkg.GemPkg, p)...)
	products.removeByValue(findProductsToRemove(defaultCandidateRemovals, pkg.GemPkg, p)...)
	return products
}

func rubyCandidateProductsFromAPK(m pkg.ApkMetadata) fieldCandidateSet {
	products := newFieldCandidateSet()
	upstream := m.Upstream()

	if upstream != "ruby" {
		for _, p := range rubyPrefixes {
			if strings.HasPrefix(m.Package, p) {
				t := strings.ToLower(strings.TrimPrefix(m.Package, p))
				products.union(rubyCandidateProductsFromName(t))
			}

			if upstream != "" && upstream != m.Package && strings.HasPrefix(upstream, p) {
				t := strings.ToLower(strings.TrimPrefix(upstream, p))
				products.union(rubyCandidateProductsFromName(t))
			}
		}
	}

	return products
}

func candidateVendorsFromAPKUpstream(m pkg.ApkMetadata) fieldCandidateSet {
	vendors := newFieldCandidateSet()
	upstream := m.Upstream()
	if upstream != "" && upstream != m.Package {
		vendors.addValue(upstream)
		vendors.addValue(findAdditionalVendors(defaultCandidateAdditions, pkg.ApkPkg, upstream, upstream)...)
		vendors.removeByValue(findVendorsToRemove(defaultCandidateRemovals, pkg.ApkPkg, upstream)...)
	}

	return vendors
}

func candidateProductsFromAPKUpstream(m pkg.ApkMetadata) fieldCandidateSet {
	products := newFieldCandidateSet()
	upstream := m.Upstream()
	if upstream != "" {
		products.addValue(upstream)
		products.addValue(findAdditionalProducts(defaultCandidateAdditions, pkg.ApkPkg, upstream)...)
		products.removeByValue(findProductsToRemove(defaultCandidateRemovals, pkg.ApkPkg, upstream)...)
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
	vendors.union(candidateVendorsFromAPKUpstream(metadata))
	vendors.union(candidateVendorsFromURL(metadata.URL))

	for v := range vendors {
		v.disallowDelimiterVariations = true
		v.disallowSubSelections = true
	}

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
	products.union(candidateProductsFromAPKUpstream(metadata))

	for p := range products {
		p.disallowDelimiterVariations = true
		p.disallowSubSelections = true
	}

	return products
}
