package cpegenerate

import (
	"strings"

	"github.com/anchore/syft/syft/pkg"
)

// candidateVendorsForPE returns vendor candidates for PE (BinaryPkg) packages based on common metadata hints.
// Specifically, normalize Ghostscript binaries to vendor "artifex" when detected.
func candidateVendorsForPE(p pkg.Package) fieldCandidateSet {
	candidates := newFieldCandidateSet()

	meta, ok := p.Metadata.(pkg.PEBinary)
	if !ok {
		return candidates
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
		candidates.addValue("artifex")
	}

	if product == "git" || fileDesc == "git setup" || company == "the git development community" {
		candidates.addValue("git_for_windows_project")
		candidates.addValue("gitforwindows")
	}

	if isMicrosoftEdge(company, product) {
		candidates.addValue("microsoft")
	}

	return candidates
}

// candidateProductsForPE returns product candidates for PE (BinaryPkg) packages based on common metadata hints.
// Specifically, normalize Ghostscript binaries to product "ghostscript" when detected.
func candidateProductsForPE(p pkg.Package) fieldCandidateSet {
	candidates := newFieldCandidateSet()

	meta, ok := p.Metadata.(pkg.PEBinary)
	if !ok {
		return candidates
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

	if strings.Contains(product, "ghostscript") || strings.Contains(fileDesc, "ghostscript") {
		candidates.addValue("ghostscript")
	}

	if product == "git" || fileDesc == "git setup" {
		candidates.addValue("git_for_windows")
		candidates.addValue("git")
	}

	if isMicrosoftEdge(company, product) {
		candidates.addValue("edge_chromium")
	}

	return candidates
}

// isMicrosoftEdge reports whether the (lowercased) version resource values describe the Chromium-based Microsoft Edge
// browser, which NVD tracks as microsoft:edge_chromium.
func isMicrosoftEdge(company, product string) bool {
	return strings.HasPrefix(company, "microsoft") && product == "microsoft edge"
}
