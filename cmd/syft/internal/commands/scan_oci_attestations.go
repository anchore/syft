package commands

import (
	"context"
	"fmt"
	"slices"

	"github.com/anchore/clio"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/ociattestation"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

// produceScanSBOM keeps ordinary scans unchanged unless the operator
// explicitly opts in to importing unverified OCI-attested SBOMs.
func produceScanSBOM(ctx context.Context, id clio.Identification, src source.Source, opts *scanOptions, userInput string, selectedSources ...string) (*sbom.SBOM, error) {
	mode := opts.AttestedSBOM
	if mode == "" || mode == "off" {
		if opts.AttestedSBOMVerify || opts.AttestedSBOMIssuer != "" || opts.AttestedSBOMIdentity != "" {
			return nil, fmt.Errorf("sigstore verification options require --attested-sbom=additive or replacement")
		}
		return generateSBOM(ctx, id, src, &opts.Catalog)
	}
	if mode != string(ociattestation.AdditiveMode) && mode != string(ociattestation.ReplacementMode) {
		return nil, fmt.Errorf("invalid --attested-sbom mode %q: choose off, additive or replacement", mode)
	}
	// A local Docker/Podman image can have a different manifest digest than
	// the image currently tagged at a remote registry. Never silently fetch
	// OCI attestations for a local image with the same mutable tag.
	if !slices.Contains(selectedSources, "registry") {
		return nil, fmt.Errorf("--attested-sbom requires an explicit registry source (registry:IMAGE or --from registry)")
	}
	verifier, err := makeAttestationVerifier(opts)
	if err != nil {
		return nil, err
	}
	var base *sbom.SBOM
	if mode == string(ociattestation.ReplacementMode) {
		// Avoid cataloging the image if the operator explicitly requested
		// replacement. Preserve the resolved image identity and scan descriptor.
		base = &sbom.SBOM{
			Source:     src.Describe(),
			Descriptor: sbom.Descriptor{Name: id.Name, Version: id.Version},
			Artifacts:  sbom.Artifacts{Packages: pkg.NewCollection()},
		}
	} else {
		base, err = generateSBOM(ctx, id, src, &opts.Catalog)
		if err != nil {
			return nil, err
		}
	}
	// The resolver already selected this image digest. Discovery must not
	// resolve a mutable tag a second time, even when registry tags move.
	var documents []ociattestation.DecodedSBOM
	if verifier != nil {
		documents, err = ociattestation.Import(ctx, userInput, src.Describe(), opts.Registry.ToOptions(), verifier)
	} else {
		documents, err = ociattestation.Import(ctx, userInput, src.Describe(), opts.Registry.ToOptions())
	}
	if err != nil {
		return nil, fmt.Errorf("unable to import OCI-attested SBOM: %w", err)
	}
	if len(documents) > 0 {
		if verifier != nil {
			log.Infof("importing %d Sigstore-verified OCI SBOM(s), signer identity %q", len(documents), opts.AttestedSBOMIdentity)
		} else {
			log.Warnf("importing %d OCI-attested SBOM(s): OCI content integrity checked but cryptographic signatures NOT verified", len(documents))
		}
	}
	return ociattestation.Combine(base, documents, ociattestation.Mode(mode))
}

func makeAttestationVerifier(opts *scanOptions) (ociattestation.BundleVerifier, error) {
	if !opts.AttestedSBOMVerify {
		if opts.AttestedSBOMIssuer != "" || opts.AttestedSBOMIdentity != "" {
			return nil, fmt.Errorf("--attested-sbom-issuer and --attested-sbom-identity require --attested-sbom-verify")
		}
		return nil, nil
	}
	if opts.AttestedSBOMIssuer == "" || opts.AttestedSBOMIdentity == "" {
		return nil, fmt.Errorf("--attested-sbom-verify requires both --attested-sbom-issuer and --attested-sbom-identity")
	}
	return ociattestation.NewSigstoreVerifier(opts.AttestedSBOMIssuer, opts.AttestedSBOMIdentity)
}
