package cpe

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/syft/pkg"
)

var (
	prefixesToPackageType = map[string]pkg.Type{
		"py-":   pkg.PythonPkg,
		"ruby-": pkg.GemPkg,
	}
	streamVersionPkgNamePattern = regexp.MustCompile(`^(?P<stream>[a-zA-Z][\w-]*?)(?P<streamVersion>\-?\d[\d\.]*?)($|-(?P<subPackage>[a-zA-Z][\w-]*?)?)$`)
)

type upstreamCandidate struct {
	Name string
	Type pkg.Type
}

func upstreamCandidates(m pkg.ApkMetadata) (candidates []upstreamCandidate) {
	// Do not consider OriginPackage variations when generating CPE candidates for the child package
	// because doing so will result in false positives when matching to vulnerabilities in Grype since
	// it won't know to lookup apk fix entries using the OriginPackage name.

	name := m.Package
	groups := internal.MatchNamedCaptureGroups(streamVersionPkgNamePattern, m.Package)
	stream, ok := groups["stream"]

	if ok && stream != "" {
		sub, ok := groups["subPackage"]

		if ok && sub != "" {
			name = fmt.Sprintf("%s-%s", stream, sub)
		} else {
			name = stream
		}
	}

	for prefix, typ := range prefixesToPackageType {
		if strings.HasPrefix(name, prefix) {
			t := strings.TrimPrefix(name, prefix)
			if t != "" {
				candidates = append(candidates, upstreamCandidate{Name: t, Type: typ})
				return candidates
			}
		}
	}

	if name != "" {
		candidates = append(candidates, upstreamCandidate{Name: name, Type: pkg.UnknownPkg})
		return candidates
	}

	return candidates
}

func candidateVendorsForAPK(p pkg.Package) fieldCandidateSet {
	metadata, ok := p.Metadata.(pkg.ApkMetadata)
	if !ok {
		return nil
	}

	vendors := newFieldCandidateSet()
	candidates := upstreamCandidates(metadata)

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
	candidates := upstreamCandidates(metadata)

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
