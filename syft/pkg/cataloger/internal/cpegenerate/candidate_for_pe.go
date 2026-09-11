package cpegenerate

import (
	"strings"

	"github.com/anchore/syft/syft/pkg"
)

// isMicrosoftEdgePE returns true if the PE metadata resembles a Microsoft Edge binary (e.g. msedge.exe).
func isMicrosoftEdgePE(product, fileDesc string) bool {
	return product == "microsoft edge" || fileDesc == "microsoft edge"
}

// candidateVendorsForPE adds vendor candidates for PE (BinaryPkg) packages based on common metadata hints,
// mutating the given set in place. Specifically, normalize Ghostscript binaries to vendor "artifex" when detected.
// Unlike sibling candidateXForY helpers in this package, this mutates the caller's set directly (rather than
// returning a new one to union in) because the Microsoft Edge case below needs to clear() the caller's existing
// (incorrect) candidates, not just add to them.
func candidateVendorsForPE(p pkg.Package, vendors fieldCandidateSet) {
	meta, ok := p.Metadata.(pkg.PEBinary)
	if !ok {
		return
	}

	var company, product, fileDesc string
	for _, kv := range meta.VersionResources {
		switch strings.ToLower(kv.Key) {
		case "companyname":
			company = strings.ToLower(kv.Value)
		case "productname":
			product = strings.ToLower(kv.Value)
		case "filedescription":
			fileDesc = strings.ToLower(kv.Value)
		}
	}

	if strings.Contains(product, "ghostscript") || strings.Contains(fileDesc, "ghostscript") || strings.Contains(company, "artifex") {
		vendors.addValue("artifex")
	}

	if product == "git" || fileDesc == "git setup" || company == "the git development community" {
		vendors.addValue("git_for_windows_project")
		vendors.addValue("gitforwindows")
	}

	if isMicrosoftEdgePE(product, fileDesc) {
		// the raised package name ("Microsoft Edge") is otherwise used verbatim as the vendor guess, which
		// does not match the NVD CPE dictionary entry (vendor: microsoft); replace it outright so the
		// mismatched candidate doesn't win on specificity and get selected as the primary CPE. Delimiter
		// variations are disallowed so this exact, known-correct value isn't out-ranked by a hyphenated form.
		vendors.clear()
		vendors.add(fieldCandidate{value: "microsoft", disallowSubSelections: true, disallowDelimiterVariations: true})
	}
}

// candidateProductsForPE adds product candidates for PE (BinaryPkg) packages based on common metadata hints,
// mutating the given set in place. Specifically, normalize Ghostscript binaries to product "ghostscript" when detected.
func candidateProductsForPE(p pkg.Package, products fieldCandidateSet) {
	meta, ok := p.Metadata.(pkg.PEBinary)
	if !ok {
		return
	}

	var product, fileDesc string
	for _, kv := range meta.VersionResources {
		switch strings.ToLower(kv.Key) {
		case "productname":
			product = strings.ToLower(kv.Value)
		case "filedescription":
			fileDesc = strings.ToLower(kv.Value)
		}
	}

	if strings.Contains(product, "ghostscript") || strings.Contains(fileDesc, "ghostscript") {
		products.addValue("ghostscript")
	}

	if product == "git" || fileDesc == "git setup" {
		products.addValue("git_for_windows")
		products.addValue("git")
	}

	if isMicrosoftEdgePE(product, fileDesc) {
		// the raised package name ("Microsoft Edge") is otherwise used verbatim as the product guess, which
		// does not match the NVD CPE dictionary entry (product: edge_chromium); replace it outright so the
		// mismatched candidate doesn't win on specificity and get selected as the primary CPE. Delimiter
		// variations are disallowed so this exact, known-correct value isn't out-ranked by a hyphenated form.
		products.clear()
		products.add(fieldCandidate{value: "edge_chromium", disallowSubSelections: true, disallowDelimiterVariations: true})
	}
}
