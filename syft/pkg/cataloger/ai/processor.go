package ai

import (
	"sort"

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

// safeTensorsMergeProcessor mirrors ggufMergeProcessor for SafeTensors packages.
// When scanning an OCI AI artifact, the model-config blob produces one named
// package and each safetensors weight layer produces a nameless package. The
// nameless packages are absorbed into the named one's Parts slice.
//
// MetadataHash is intentionally preserved on absorbed parts: it is derived
// purely from the on-disk safetensors header (see SafeTensorsModelInfo doc),
// so it acts as the cross-source content fingerprint. For a single-shard
// model we also copy it up to the named package's top-level MetadataHash so
// that an OCI scan and a directory scan of the same single .safetensors file
// expose the hash at the same field — `md.MetadataHash` — without callers
// having to inspect Parts.
func safeTensorsMergeProcessor(pkgs []pkg.Package, rels []artifact.Relationship, err error) ([]pkg.Package, []artifact.Relationship, error) {
	if err != nil {
		return pkgs, rels, err
	}
	if len(pkgs) == 0 {
		return pkgs, rels, err
	}

	var namedPkgs []pkg.Package
	var namelessParts []pkg.SafeTensorsModelInfo
	for _, p := range pkgs {
		if p.Name != "" {
			namedPkgs = append(namedPkgs, p)
			continue
		}
		if md, ok := p.Metadata.(pkg.SafeTensorsModelInfo); ok {
			namelessParts = append(namelessParts, md)
		}
	}

	if len(namedPkgs) == 0 {
		return nil, rels, err
	}

	if len(namedPkgs) == 1 && len(namelessParts) > 0 {
		// Sort by MetadataHash so OCI layer order (map iteration) doesn't leak
		// into the SBOM output.
		sort.Slice(namelessParts, func(i, j int) bool {
			return namelessParts[i].MetadataHash < namelessParts[j].MetadataHash
		})
		winner := &namedPkgs[0]
		if md, ok := winner.Metadata.(pkg.SafeTensorsModelInfo); ok {
			md.Parts = namelessParts
			// Trust per-shard headers over the producer-declared shard count.
			md.ShardCount = len(namelessParts)
			// Single-shard: lift the part's content fingerprint to the top
			// level so the field placement matches a dir-scan single file.
			// Only lift when the named package has no hash of its own (the
			// OCI config-blob parser never sets one; dir-scan paths never
			// produce nameless parts, so they don't reach this branch).
			if len(namelessParts) == 1 && md.MetadataHash == "" {
				md.MetadataHash = namelessParts[0].MetadataHash
			}
			winner.Metadata = md
		}
	}

	return namedPkgs, rels, err
}
