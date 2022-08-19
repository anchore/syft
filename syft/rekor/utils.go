package rekor

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"

	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/spdx/tools-golang/spdx"
	"github.com/spdx/tools-golang/tvloader"
)

var (
	GoogleSbomPredicateType string = "google.com/sbom"
	sha256Check                    = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)
)

type digest struct {
	Sha256 string
}

type sbomEntry struct {
	Format string
	Digest digest
	URI    string
}

type buildMetadata struct {
	ArtifactSourceRepo             string `json:"artifact-source-repo,omitempty"`
	ArtifactSourceRepoCommit       string `json:"artifact-source-repo-commit omitempty"`
	AttestationGeneratorRepo       string `json:"attestation-generator-repo,omitempty"`
	AttestationGeneratorRepoCommit string `json:"attestation-generator-repo-commit,omitempty"`
}

// corresponds to predicate type = "google.com/sbom"
type GoogleSbomPredicate struct {
	Sboms         []sbomEntry
	BuildMetadata buildMetadata `json:"build-metadata,omitempty"`
}

type InTotoAttestation struct {
	in_toto.StatementHeader
	Predicate GoogleSbomPredicate `json:"predicate,omitempty"`
}

type sbomWithMetadata struct {
	executableSha256 string
	sha1             string
	rekorEntry       string // uuid used to retrieve the sbom
	spdx             *spdx.Document2_2
}

// parseEntry parses the entry body to a struct
//
// Precondition: entry is not nil
func parseEntry(entry *models.LogEntryAnon) (*models.IntotoV001Schema, error) {
	if entry.Body == nil {
		return nil, errors.New("entry body is nil")
	}
	bodyEncoded, ok := entry.Body.(string)
	if !ok {
		return nil, errors.New("attempted to parse entry body as string, but failed")
	}

	bodyDecoded, err := base64.StdEncoding.DecodeString(bodyEncoded)
	if err != nil {
		return nil, fmt.Errorf("error base64 decoding body: %w", err)
	}

	intoto := &models.Intoto{}
	if err = intoto.UnmarshalBinary(bodyDecoded); err != nil {
		return nil, fmt.Errorf("error unmarshaling json entry body to intoto: %w", err)
	}

	if intoto.APIVersion == nil || *intoto.APIVersion != "0.0.1" {
		return nil, fmt.Errorf("intoto schema version %v not supported", *intoto.APIVersion)
	}

	specBytes, err := json.Marshal(intoto.Spec)
	if err != nil {
		return nil, fmt.Errorf("error marshaling intoto spec to json: %w", err)
	}

	intotoV001 := &models.IntotoV001Schema{}
	if err = intotoV001.UnmarshalBinary(specBytes); err != nil {
		return nil, fmt.Errorf("error unmarshaling intoto spec to intotoV001 schema: %w", err)
	}

	return intotoV001, nil
}

// validateAttestation does some checks that the attestation contains the necessary fields to proceed
//
// Precondition: att is not nil
func validateAttestation(att *InTotoAttestation) error {
	// even if predicate type is not GoogleSbomPredicateType, attempt to proceed
	invalidPredType := false
	if att.PredicateType != GoogleSbomPredicateType {
		invalidPredType = true
	}
	var err error
	if len(att.Subject) == 0 {
		err = errors.New("subject of attestation found on rekor is nil. Ignoring log entry")
	} else if len(att.Subject) > 1 {
		err = errors.New("attestation found on rekor contains multiple subjects, which is not supported. Ignoring log entry")
	} else if _, ok := att.Subject[0].Digest["sha256"]; !ok {
		err = errors.New("attestation subject does not contain a sha256")
	} else if len(att.Predicate.Sboms) == 0 {
		err = errors.New("attestation predicate found on rekor does not contain any sboms")
	}

	if err != nil {
		if invalidPredType {
			return fmt.Errorf("the attestation predicate type (%v) is not the accepted type (%v)", att.PredicateType, GoogleSbomPredicateType)
		}
		return err
	}
	return nil
}

// parseAndValidateAttestation parses the entry's attestation to an attestation struct and validates the attestation predicate
//
// Precondition: entry is not nil
func parseAndValidateAttestation(entry *models.LogEntryAnon) (*InTotoAttestation, error) {
	attAnon := entry.Attestation
	if attAnon == nil {
		return nil, errors.New("attestation is nil")
	}

	attDecoded := string(attAnon.Data)
	att := &InTotoAttestation{}

	if err := json.Unmarshal([]byte(attDecoded), att); err != nil {
		return nil, fmt.Errorf("error unmarshaling attestation to inTotoAttestation type: %w", err)
	}
	if err := validateAttestation(att); err != nil {
		return nil, err
	}

	return att, nil
}

func parseSbom(spdxBytes *[]byte) (*spdx.Document2_2, error) {
	// remove all SHA512 hashes because spdx/tools-golang does not support
	// PR fix is filed but not merged: https://github.com/spdx/tools-golang/pull/139

	regex := regexp.MustCompile("\n.*SHA512.*")

	modifiedSpdxBytes := regex.ReplaceAll(*spdxBytes, nil)
	sbom, err := tvloader.Load2_2(bytes.NewReader(modifiedSpdxBytes))
	if err != nil {
		return nil, fmt.Errorf("error loading sbomBytes into spdx.Document2_2 type: %w", err)
	}

	return sbom, nil
}
