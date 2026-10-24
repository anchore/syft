package ociattestation

import (
	"context"
	"errors"
	"fmt"

	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

// Mode controls whether attested packages are added to an independently
// cataloged image or replace them. Every mode is explicitly opt-in.
type Mode string

const (
	AdditiveMode    Mode = "additive"
	ReplacementMode Mode = "replacement"
)

// Import discovers and decodes OCI-attested SBOMs bound to Syft's resolved
// image digest, preserving provenance for the subsequent merge step.
func Import(ctx context.Context, reference string, description source.Description, registryOptions *image.RegistryOptions, verifiers ...BundleVerifier) ([]DecodedSBOM, error) {
	client, digest, err := NewClientForImage(ctx, reference, description, registryOptions)
	if err != nil {
		return nil, err
	}
	if len(verifiers) > 1 {
		return nil, errors.New("at most one Sigstore verifier may be configured")
	}
	if len(verifiers) == 1 {
		if verifiers[0] == nil {
			return nil, errors.New("sigstore verifier must not be nil")
		}
		client.BundleVerifier = verifiers[0]
	}
	attestations, err := client.Discover(ctx, digest)
	if err != nil {
		return nil, fmt.Errorf("discover attested SBOMs: %w", err)
	}
	if client.BundleVerifier != nil && len(attestations) == 0 {
		return nil, errors.New("no verified OCI-attested SBOM was found for the requested image")
	}
	return DecodeSBOMs(attestations)
}

// Combine merges decoded attestations with the catalog or
// constructs a replacement catalog. Identical packages already discovered
// by a local scan are not relabeled, so unverified claims cannot replace the
// stronger, independently observed provenance.
//
// Verification is performed at download time by an explicitly configured
// BundleVerifier. Otherwise, imported packages are marked unverified.
func Combine(base *sbom.SBOM, docs []DecodedSBOM, mode Mode) (*sbom.SBOM, error) {
	if base == nil || base.Artifacts.Packages == nil {
		return nil, errors.New("image SBOM has no package collection")
	}
	if mode != AdditiveMode && mode != ReplacementMode {
		return nil, fmt.Errorf("unknown attested SBOM mode %q", mode)
	}
	if mode == ReplacementMode && len(docs) == 0 {
		return nil, errors.New("replacement requested, but no usable attested SBOM was found")
	}
	output := cloneImageInventory(base, mode)
	seen := existingRelationships(output.Relationships)
	for i, doc := range docs {
		if err := validateAttestedInventory(base, doc, i); err != nil {
			return nil, err
		}
		introduced, err := appendAttestedPackages(&output, doc, i)
		if err != nil {
			return nil, err
		}
		appendAttestedRelationships(&output, doc.Document.Relationships, introduced, seen)
	}
	return &output, nil
}

func cloneImageInventory(base *sbom.SBOM, mode Mode) sbom.SBOM {
	output := *base
	output.Relationships = append([]artifact.Relationship(nil), base.Relationships...)
	if mode == ReplacementMode {
		output.Artifacts = sbom.Artifacts{Packages: pkg.NewCollection()}
		output.Relationships = nil
		return output
	}
	// Do not mutate packages in the caller's independently scanned inventory.
	output.Artifacts.Packages = pkg.NewCollection()
	for scanned := range base.Artifacts.Packages.Enumerate() {
		output.Artifacts.Packages.Add(scanned)
	}
	return output
}

func validateAttestedInventory(base *sbom.SBOM, doc DecodedSBOM, index int) error {
	if doc.Document == nil || doc.Document.Artifacts.Packages == nil {
		return fmt.Errorf("attested SBOM %d has no packages", index)
	}
	if doc.Document.Artifacts.Packages.PackageCount() > 100000 {
		return fmt.Errorf("attested SBOM %d exceeds the 100000 package safety limit", index)
	}
	imageDigest := expectedImageDigest(base.Source.Metadata)
	if imageDigest != "" && doc.ImageDigest != imageDigest {
		return fmt.Errorf("attested SBOM %d is for image %s, expected %s", index, doc.ImageDigest, imageDigest)
	}
	return nil
}

func expectedImageDigest(metadata any) string {
	switch v := metadata.(type) {
	case source.ImageMetadata:
		return v.ManifestDigest
	case *source.ImageMetadata:
		if v != nil {
			return v.ManifestDigest
		}
	}
	return ""
}

func appendAttestedPackages(output *sbom.SBOM, doc DecodedSBOM, index int) (map[artifact.ID]struct{}, error) {
	introduced := make(map[artifact.ID]struct{})
	trustState := "unverified"
	if doc.SignatureVerified {
		trustState = "verified"
	}
	label := "oci-attested-sbom-" + trustState + ":" + doc.ArtifactDigest
	for p := range doc.Document.Artifacts.Packages.Enumerate() {
		if !pkg.IsValid(&p) {
			return nil, fmt.Errorf("attested SBOM %d contains package with no name", index)
		}
		if output.Artifacts.Packages.Package(p.ID()) != nil {
			// Independently scanned packages retain their original provenance.
			continue
		}
		p.FoundBy = label
		output.Artifacts.Packages.Add(p)
		introduced[p.ID()] = struct{}{}
	}
	return introduced, nil
}

func existingRelationships(relationships []artifact.Relationship) map[string]bool {
	seen := make(map[string]bool, len(relationships))
	for _, rel := range relationships {
		if rel.From != nil && rel.To != nil {
			seen[relationshipKey(rel)] = true
		}
	}
	return seen
}

func appendAttestedRelationships(output *sbom.SBOM, relationships []artifact.Relationship, introduced map[artifact.ID]struct{}, seen map[string]bool) {
	for _, rel := range relationships {
		if rel.From == nil || rel.To == nil {
			continue
		}
		if _, ok := introduced[rel.From.ID()]; !ok {
			continue
		}
		if _, ok := introduced[rel.To.ID()]; !ok {
			continue
		}
		from := output.Artifacts.Packages.Package(rel.From.ID())
		to := output.Artifacts.Packages.Package(rel.To.ID())
		if from == nil || to == nil {
			continue
		}
		key := relationshipKey(rel)
		if seen[key] {
			continue
		}
		seen[key] = true
		output.Relationships = append(output.Relationships, artifact.Relationship{
			From: *from, To: *to, Type: rel.Type, Data: rel.Data,
		})
	}
}

func relationshipKey(r artifact.Relationship) string {
	return string(r.From.ID()) + "\x00" + string(r.To.ID()) + "\x00" + string(r.Type)
}
