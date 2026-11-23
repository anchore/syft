# OCI-attested SBOM ingestion (experimental)

> **Security notice:** OCI SHA-256 integrity and subject binding alone are
> not signature verification. Use `--attested-sbom-verify` with a trusted
> exact signer identity to require Sigstore cryptographic authentication.
> Unsigned or unverified assertions must not be treated as trusted evidence.

## CLI

Ordinary Syft scans remain unchanged. Attested imports deliberately require the explicit registry source; a local Docker daemon image must not be confused with a remote tag that can change.

~~~sh
syft scan registry:ghcr.io/example/app:1.0 -o syft-json
~~~

To combine scanned software inventory with attested SBOM packages:

~~~sh
syft scan registry:ghcr.io/example/app:1.0 \
  --attested-sbom=additive -o syft-json
~~~

To use only the attached inventory, explicitly and with an error if none is found:

~~~sh
syft scan registry:ghcr.io/example/app:1.0 \
  --attested-sbom=replacement -o syft-json
~~~

Replacement mode ingests unverified assertions, rather than independently
examining filesystem contents. Do not rely on it alone for security gates.
Imported packages carry a FoundBy provenance label containing the OCI artifact
digest and the word unverified. If independently scanned and attested packages
have the same ID, scanned provenance is retained.

## Scope

- OCI 1.1 referrers discovery plus referrers-tag fallback for older registries.
- Sigstore bundle v0.3 JSON OCI layers containing DSSE in-toto Statement v1.
- CycloneDX JSON and SPDX JSON predicates decoded via Syft native decoders.
- Registry credentials and default Docker keychain through challenge-aware auth.
- Binding to the image digest resolved by Syft, without re-fetching a mutable tag.
- Resource ceilings: 64 referrer descriptors, 8 layers/manifest, index 2 MiB,
  manifest 512 KiB, blob 16 MiB and total download budget 64 MiB.
- Reject digest, size and subject mismatches, malformed relevant artifacts,
  invalid JSON, unsupported image sources, or unknown scan modes.
- Missing attestation: original scan unchanged in additive mode; explicit
  error in replacement mode.


## Cryptographically verified Sigstore bundles

Syft can **require cryptographic authentication** in addition to OCI content
integrity and in-toto image subject matching. Enable this explicitly, and
supply both the **exact OIDC issuer** and the **exact Fulcio certificate
identity (SAN)** expected for the trusted signing workflow:

~~~sh
syft scan registry:ghcr.io/brawer/sbom-attestation-test:latest \
  --attested-sbom=additive \
  --attested-sbom-verify \
  --attested-sbom-issuer=https://token.actions.githubusercontent.com \
  --attested-sbom-identity=https://github.com/brawer/sbom-attestation-test/.github/workflows/build-container.yml@refs/heads/main \
  -o syft-json
~~~

When verification is enabled, every imported SBOM must pass **all** checks:

- Sigstore DSSE signature validated against the signed in-toto statement.
- Fulcio certificate trust, signed certificate timestamp and expected exact
  OIDC issuer and certificate identity.
- Rekor transparency log inclusion and trusted observer timestamp.
- The signed statement's SHA-256 subject digest matches the image's already
  resolved manifest digest.
- The OCI manifest and bundle blob digests and sizes match the descriptors.

Trust is bootstrapped using **Sigstore Public Good's TUF trusted root**. The
first verification may need network access to fetch or refresh TUF metadata.
If the trust root cannot be loaded or any verification fails, Syft rejects
the attestation and returns a nonzero exit status: **no fallback to an
unverified SBOM**. Syft never automatically trusts a certificate identity
taken from the untrusted bundle or from the OCI registry annotations.

In verified mode imported packages carry a provenance label beginning
`oci-attested-sbom-verified:`, instead of `oci-attested-sbom-unverified:`.
All independently scanned packages keep their own cataloger provenance.
Verification checks **who signed the statement** and **which image digest
was attested**, but does *not* prove that the package inventory asserted by
that trusted signer is complete or accurate.

If the verification switches are omitted, imports retain the existing
explicitly opt-in **unverified** behavior with a security warning. This is
intentional backwards compatibility for additive scanning, not a claim that
unverified attestations are trustworthy.

This verification mode currently supports **certificate-based, keyless
Sigstore Public Good bundles**. Custom/private Sigstore roots and public
key-based verification require separate explicit trust configuration and
are not silently accepted.

## Validation

~~~sh
go test ./syft/ociattestation -count=1
go test -race ./syft/ociattestation -count=1
go test ./cmd/syft/internal/commands -run TestProduceScanSBOM -count=1
go vet ./syft/ociattestation ./cmd/syft/internal/commands
~~~

Known limitations requiring maintainer discussion:
- Verified mode requires an exact signing identity and the Sigstore Public
  Good trust root; self-hosted Sigstore deployments are not yet configurable.
- Cryptographic verification establishes signer identity and subject binding,
  not the factual accuracy or completeness of the SBOM.
- Cross-document relationship and provenance encoding across all export formats
  requires maintainer review.
- Multi-architecture images whose attestations target an index digest instead
  of the resolved platform manifest require validation.
- The fork-only development workflow and temporary dependency-resolution commits
  must not be included in a final upstream submission.

See https://github.com/anchore/grype/issues/3604 for project background.
