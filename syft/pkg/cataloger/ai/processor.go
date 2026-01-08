package ai

import (
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
)

// ggufMergeProcessor consolidates multiple GGUF packages into a single package
// representing the AI model. When scanning OCI images with multiple layers,
// each layer may produce a separate package. This processor finds the package
// with a name and merges metadata from nameless packages into its GGUFFileHeaders field.
// Only packages with a non-empty name are returned in the final result.
// Empty headers (GGUFVersion == 0) are filtered out, and duplicates are removed
// based on MetadataKeyValuesHash.
func ggufMergeProcessor(pkgs []pkg.Package, rels []artifact.Relationship, err error) ([]pkg.Package, []artifact.Relationship, error) {
	if err != nil {
		return pkgs, rels, err
	}

	if len(pkgs) == 0 {
		return pkgs, rels, err
	}

	// Separate packages with names from those without
	var namedPkgs []pkg.Package
	var namelessHeaders []pkg.GGUFFileHeader

	for _, p := range pkgs {
		if p.Name != "" {
			namedPkgs = append(namedPkgs, p)
		} else {
			// Extract the GGUFFileHeader from nameless packages (handle both pointer and value types)
			switch header := p.Metadata.(type) {
			case pkg.GGUFFileHeader:
				// We do not want a kv hash for nameless headers
				header.MetadataKeyValuesHash = ""
				namelessHeaders = append(namelessHeaders, header)
			default:
				continue
			}
		}
	}

	// If there are no named packages, return nothing
	if len(namedPkgs) == 0 {
		return nil, rels, err
	}

	// If there's exactly one named package, merge nameless headers into it.
	// If there are multiple named packages, return them all without merging.
	if len(namedPkgs) == 1 && len(namelessHeaders) > 0 {
		winner := &namedPkgs[0]
		// Handle both pointer and value types for metadata
		switch header := winner.Metadata.(type) {
		case pkg.GGUFFileHeader:
			header.GGUFFileHeaders = namelessHeaders
			winner.Metadata = header
		}
	}

	return namedPkgs, rels, err
}