package ociattestation

import (
	"strings"
	"testing"
)

func TestNewSigstoreVerifierRejectsMissingTrustPolicy(t *testing.T) {
	for _, tc := range []struct {
		name     string
		issuer   string
		identity string
	}{
		{"empty", "", ""},
		{"empty identity", "https://token.actions.githubusercontent.com", ""},
		{"empty issuer", "", "https://github.com/example/org/.github/workflows/build.yml@refs/heads/main"},
		{"whitespace issuer", " https://token.actions.githubusercontent.com ", "example"},
		{"whitespace identity", "https://token.actions.githubusercontent.com", " example "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewSigstoreVerifier(tc.issuer, tc.identity); err == nil {
				t.Fatal("accepted missing or malformed Sigstore identity policy")
			}
		})
	}
}

func TestSigstoreVerifierRejectsUnconfiguredVerifier(t *testing.T) {
	var verifier *SigstoreVerifier
	if err := verifier.VerifyBundle([]byte("{}"), testImageSHA); err == nil {
		t.Fatal("nil verifier accepted untrusted SBOM")
	}
	verifier = &SigstoreVerifier{}
	if err := verifier.VerifyBundle([]byte("{}"), testImageSHA); err == nil {
		t.Fatal("unconfigured verifier accepted untrusted SBOM")
	}
}

func TestSigstoreVerifierRejectsMalformedInputBeforeTrust(t *testing.T) {
	var verifier SigstoreVerifier
	err := verifier.VerifyBundle([]byte("invalid"), "sha256:bad")
	if err == nil || !strings.Contains(err.Error(), "not configured") {
		t.Fatalf("unconfigured verifier should fail closed: %v", err)
	}
}
