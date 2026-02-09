package ai

import (
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
)

// ggufMergeProcessor consolidates multiple GGUF packages into a single package
// representing the AI model. When scanning OCI images with multiple layers,
// each layer may produce a separate package. This processor finds the package
// with a name and merges metadata from nameless packages into its GGUFFileParts field.
// Only packages with a non-empty name are returned in the final result.
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
			if header, ok := p.Metadata.(pkg.GGUFFileHeader); ok {
				// We do not want a kv hash for nameless headers
				header.MetadataKeyValuesHash = ""
				namelessHeaders = append(namelessHeaders, header)
			}
		}
	}

	// If there are no named packages, return nothing
	if len(namedPkgs) == 0 {
		return nil, rels, err
	}

	// merge nameless headers into a single named package;
	// if there are multiple named packages, return them without trying to merge headers.
	// we cannot determine which nameless headers belong to which package
	// this is because the order we receive the gguf headers in is not guaranteed
	// to match the layer order in the original oci image
	if len(namedPkgs) == 1 && len(namelessHeaders) > 0 {
		winner := &namedPkgs[0]
		if header, ok := winner.Metadata.(pkg.GGUFFileHeader); ok {
			header.Parts = namelessHeaders
			winner.Metadata = header
		}
	}

	// Largest number of key value

	return namedPkgs, rels, err
}
