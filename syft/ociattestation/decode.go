package ociattestation

import (
	"bytes"
	"fmt"

	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/sbom"
)

// DecodedSBOM retains the OCI artifact provenance alongside the imported
// document. Content-digest validation must not be confused with signature
// verification. Keep this metadata and verified state until an output representation can
// express signing provenance without ambiguity.
type DecodedSBOM struct {
	Document          *sbom.SBOM
	ImageDigest       string
	ArtifactDigest    string
	PredicateType     string
	SignatureVerified bool
}

// DecodeSBOMs converts discovered documents using Syft's native CycloneDX
// and SPDX decoders. This deliberately does not merge package catalogs:
// callers must apply an explicit merge policy to preserve relationships,
// source attribution and the distinction between scanned and attested data.
func DecodeSBOMs(results []Result) ([]DecodedSBOM, error) {
	out := make([]DecodedSBOM, 0, len(results))
	for i, result := range results {
		if result.Format != "cyclonedx-json" && result.Format != "spdx-json" {
			return nil, fmt.Errorf("attested SBOM %d has unsupported format %q", i, result.Format)
		}
		doc, formatID, _, err := format.Decode(bytes.NewReader(result.Document))
		if err != nil {
			return nil, fmt.Errorf("decode attested SBOM %d: %w", i, err)
		}
		if doc == nil || string(formatID) != result.Format {
			return nil, fmt.Errorf("attested SBOM %d format mismatch: expected %s, got %s", i, result.Format, formatID)
		}
		if doc.Artifacts.Packages == nil {
			return nil, fmt.Errorf("attested SBOM %d has no package collection", i)
		}
		out = append(out, DecodedSBOM{
			Document:          doc,
			ImageDigest:       result.ImageDigest,
			ArtifactDigest:    result.ArtifactDigest,
			PredicateType:     result.PredicateType,
			SignatureVerified: result.SignatureVerified,
		})
	}
	return out, nil
}
