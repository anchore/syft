package cpe

import (
	"github.com/anchore/syft/syft/pkg"
)

func candidateVendorsForAPK(p pkg.Package) fieldCandidateSet {
	metadata, ok := p.Metadata.(pkg.ApkMetadata)
	if !ok {
		return nil
	}

	vendors := newFieldCandidateSet()
	candidates := metadata.UpstreamCandidates()

	for _, c := range candidates {
		switch c.Type {
		case pkg.UnknownPkg:
			vendors.addValue(c.Name)
			vendors.addValue(findAdditionalVendors(defaultCandidateAdditions, pkg.ApkPkg, c.Name, c.Name)...)
			vendors.removeByValue(findVendorsToRemove(defaultCandidateRemovals, pkg.ApkPkg, c.Name)...)
		case pkg.PythonPkg:
			vendors.addValue(c.Name)
			vendors.addValue(findAdditionalVendors(defaultCandidateAdditions, c.Type, c.Name, c.Name)...)
			vendors.removeByValue(findVendorsToRemove(defaultCandidateRemovals, c.Type, c.Name)...)
			for _, av := range additionalVendorsForPython(c.Name) {
				vendors.addValue(av)
				vendors.addValue(findAdditionalVendors(defaultCandidateAdditions, pkg.PythonPkg, av, av)...)
				vendors.removeByValue(findVendorsToRemove(defaultCandidateRemovals, pkg.PythonPkg, av)...)
			}
		default:
			vendors.addValue(c.Name)
			vendors.addValue(findAdditionalVendors(defaultCandidateAdditions, c.Type, c.Name, c.Name)...)
			vendors.removeByValue(findVendorsToRemove(defaultCandidateRemovals, c.Type, c.Name)...)
		}
	}

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
	candidates := metadata.UpstreamCandidates()

	for _, c := range candidates {
		switch c.Type {
		case pkg.UnknownPkg:
			products.addValue(c.Name)
			products.addValue(findAdditionalProducts(defaultCandidateAdditions, pkg.ApkPkg, c.Name)...)
			products.removeByValue(findProductsToRemove(defaultCandidateRemovals, pkg.ApkPkg, c.Name)...)
		default:
			products.addValue(c.Name)
			products.addValue(findAdditionalProducts(defaultCandidateAdditions, c.Type, c.Name)...)
			products.removeByValue(findProductsToRemove(defaultCandidateRemovals, c.Type, c.Name)...)
		}
	}

	for p := range products {
		p.disallowDelimiterVariations = true
		p.disallowSubSelections = true
	}

	return products
}
