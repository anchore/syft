package rekor

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/fulcioroots"
)

// verifyCert verifies that the certificate chains up to the fulcio root.
//
// Precondition: rekorClient and cert are not nil
func verifyCert(rekorClient *client.Rekor, cert *x509.Certificate) error {
	rootCerts, err := fulcioroots.Get()
	if err != nil {
		return fmt.Errorf("error getting fulcio roots: %w", err)
	}

	intCerts, err := fulcioroots.GetIntermediates()
	if err != nil {
		return fmt.Errorf("error getting fulcio intermediate certs: %w", err)
	}

	certCheckOpts := &cosign.CheckOpts{
		RekorClient:       rekorClient,
		RootCerts:         rootCerts,
		IntermediateCerts: intCerts,
	}

	_, err = cosign.ValidateAndUnpackCert(cert, certCheckOpts)
	return err
}

// verifyEntryTimestamp returns an error if the log entry timestamp is not within the certificate valid time range.
//
// Precondition: entry and entry.IntegratedTime is not nil
func verifyEntryTimestamp(cert *x509.Certificate, entry *models.LogEntryAnon) error {
	time := time.Unix(*entry.IntegratedTime, 0)
	return cosign.CheckExpiry(cert, time)
}

// verifyAttestationHash returns an error if the hash of the attestation we have is not equal to the payloadHash in the entry body
//
// **** Note that this does NOT verify the signature over the attestation. We trust Rekor for this. ****
func verifyAttestationHash(encounteredAttestation string, intotoV001 *models.IntotoV001Schema) error {
	if intotoV001 == nil || intotoV001.Content == nil || intotoV001.Content.PayloadHash == nil || intotoV001.Content.PayloadHash.Algorithm == nil {
		return errors.New("IntotoV001Schema value is missing fields")
	}

	if alg := *intotoV001.Content.PayloadHash.Algorithm; alg != "sha256" {
		return errors.New("hash algorithm is not sha256")
	}
	expectedHash := *intotoV001.Content.PayloadHash.Value

	attBytes := []byte(encounteredAttestation)
	hash := sha256.Sum256(attBytes)
	encounteredHash := hex.EncodeToString(hash[:])

	if encounteredHash != expectedHash {
		return fmt.Errorf("%v does not equal %v", encounteredHash, expectedHash)
	}
	return nil
}

// Verify verifies that the certificate is valid, the log entry timestamp is valid, and the attestation hash is correct.
//
// Precondition: entry and rekorClient are not nil
func verify(rekorClient *client.Rekor, entry *models.LogEntryAnon) error {
	intotoV001, err := parseEntry(entry)
	if err != nil {
		return fmt.Errorf("log entry body could not be parsed: %w", err)
	}

	certString := intotoV001.PublicKey
	if certString == nil {
		return errors.New("entry does not contain a certificate")
	}
	pemBytes := []byte(string(*certString))
	certs, err := cryptoutils.UnmarshalCertificatesFromPEMLimited(pemBytes, 1)
	if err != nil {
		return fmt.Errorf("certificate could not be parsed: %w", err)
	}
	cert := certs[0]
	if cert == nil {
		return fmt.Errorf("certificate could not be parsed: %w", err)
	}

	if err = verifyCert(rekorClient, cert); err != nil {
		return fmt.Errorf("certificate could not be verified: %w", err)
	}

	if err = verifyEntryTimestamp(cert, entry); err != nil {
		return fmt.Errorf("certificate timestamp could not be verified: %w", err)
	}

	if err = verifyAttestationHash(string(entry.Attestation.Data), intotoV001); err != nil {
		return fmt.Errorf("the attestation hash could not be verified: %w", err)
	}

	return nil
}

// VerifySbomHash verifies that the hash of the first SBOM in the attestation is equal to the hash of sbomBytes
func verifySbomHash(att *InTotoAttestation, sbomBytes *[]byte) error {
	if att == nil {
		return errors.New("attestation is nil")
	}
	if len(att.Predicate.Sboms) == 0 {
		return errors.New("attestation has no sboms")
	}
	// take entry at index 0 because we currently do not handle multiple sboms within one attestation
	expectedHash := att.Predicate.Sboms[0].Digest.Sha256

	hash := sha256.Sum256(*sbomBytes)
	decodedHash := hex.EncodeToString(hash[:])

	if decodedHash != expectedHash {
		return fmt.Errorf("%v is not equal to %v", decodedHash, expectedHash)
	}
	return nil
}
