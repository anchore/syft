package ociattestation

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	sigstorebundle "github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

// BundleVerifier verifies the cryptographic signature and the provenance of
// a Sigstore bundle, bound to the resolved image manifest digest.
// Implementations MUST fail closed and must not trust bundle-supplied identity.
type BundleVerifier interface {
	VerifyBundle(bundleJSON []byte, imageDigest string) error
}

// SigstoreVerifier verifies an OCI-attached DSSE bundle against the Sigstore
// Public Good trust root and an exact expected Fulcio certificate identity.
// Verification requires SCT, Rekor inclusion proof and a trusted timestamp.
type SigstoreVerifier struct {
	verifier *verify.Verifier
	identity verify.CertificateIdentity
}

// NewSigstoreVerifier constructs a strict keyless Sigstore verifier.
//
// Both issuer and subject alternative name MUST be supplied by the operator.
// The bundle is not allowed to choose its own policy. Trust roots are fetched
// from Sigstore TUF; a failure to establish trust is a hard error, never a
// reason to silently import an unverified attestation.
func NewSigstoreVerifier(issuer, certificateIdentity string) (*SigstoreVerifier, error) {
	if issuer == "" || certificateIdentity == "" || strings.TrimSpace(issuer) != issuer ||
		strings.TrimSpace(certificateIdentity) != certificateIdentity {
		return nil, errors.New("sigstore verification requires an exact certificate issuer and identity")
	}
	expectedIdentity, err := verify.NewShortCertificateIdentity(issuer, "", certificateIdentity, "")
	if err != nil {
		return nil, fmt.Errorf("invalid Sigstore signing identity: %w", err)
	}
	trustedRoot, err := root.FetchTrustedRoot()
	if err != nil {
		return nil, fmt.Errorf("establish Sigstore TUF trusted root: %w", err)
	}
	verifier, err := verify.NewVerifier(trustedRoot,
		verify.WithSignedCertificateTimestamps(1),
		verify.WithTransparencyLog(1),
		verify.WithObserverTimestamps(1),
	)
	if err != nil {
		return nil, fmt.Errorf("configure Sigstore bundle verifier: %w", err)
	}
	return &SigstoreVerifier{verifier: verifier, identity: expectedIdentity}, nil
}

// VerifyBundle fails unless the DSSE signature, Fulcio signing certificate,
// expected identity, Rekor transparency evidence, timestamps and in-toto
// subject's SHA-256 all validate. OCI content digests alone are insufficient.
func (v *SigstoreVerifier) VerifyBundle(bundleJSON []byte, imageDigest string) error {
	if v == nil || v.verifier == nil {
		return errors.New("sigstore verification is not configured")
	}
	if !sha256Digest.MatchString(imageDigest) {
		return fmt.Errorf("invalid image digest %q", imageDigest)
	}
	digestBytes, err := hex.DecodeString(strings.TrimPrefix(imageDigest, "sha256:"))
	if err != nil {
		return fmt.Errorf("decode image digest: %w", err)
	}
	var sigstoreBundle sigstorebundle.Bundle
	if err := sigstoreBundle.UnmarshalJSON(bundleJSON); err != nil {
		return fmt.Errorf("invalid Sigstore verification bundle: %w", err)
	}
	if _, err := v.verifier.Verify(&sigstoreBundle, verify.NewPolicy(
		verify.WithArtifactDigest("sha256", digestBytes),
		verify.WithCertificateIdentity(v.identity),
	)); err != nil {
		return fmt.Errorf("sigstore attestation signature or identity verification failed: %w", err)
	}
	return nil
}
