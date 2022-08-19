package rekor

import (
	"context"
	"crypto/sha1" //nolint:gosec // sha1 needed for checksums in spdx format
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/source"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/generated/client/index"
	"github.com/sigstore/rekor/pkg/generated/models"
)

// getSbom attempts to retrieve the SBOM from the URI.
//
// Precondition: client is not nil and validateAttestation has been called on att
//
// Postcondition: if no error, the returned byte list is not empty
func getSbom(att *InTotoAttestation, client *http.Client) (*[]byte, error) {
	if len(att.Predicate.Sboms) > 1 {
		log.Info("attestation found on Rekor with multiple SBOMS, which is not currently supported. Proceeding with the first SBOM.")
	}
	uri := att.Predicate.Sboms[0].URI
	if uri == "" {
		return nil, errors.New("uri of sbom is empty")
	}

	resp, err := client.Get(uri)
	if err != nil {
		return nil, fmt.Errorf("error making http request: %w", err)
	}

	bytes, err := io.ReadAll(resp.Body)
	defer resp.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("error reading http response: %w", err)
	}

	if len(bytes) == 0 {
		return nil, fmt.Errorf("retrieved sbom is empty")
	}
	return &bytes, nil
}

// getUuids returns the uuids of the Rekor entries associated with an sha hash
//
// Precondition: client is not nil
func getUuids(sha string, client *client.Rekor) ([]string, error) {
	if !sha256Check.MatchString(sha) {
		return nil, fmt.Errorf("invalid sha256 hash %v", sha)
	}

	query := &models.SearchIndex{Hash: sha}
	params := index.NewSearchIndexParams().WithQuery(query)

	res, err := client.Index.SearchIndex(params)
	if err != nil {
		return nil, err
	}
	return res.Payload, nil
}

// Precondition: client is not nil
//
// Postcondition: Rekor's signature over the entry is valid and the inclusion proof that Rekor provides us is valid
func getAndVerifyRekorEntry(uuid string, client *client.Rekor) (*models.LogEntryAnon, error) {
	params := entries.NewGetLogEntryByUUIDParams().WithEntryUUID(uuid)
	res, err := client.Entries.GetLogEntryByUUID(params)
	if err != nil {
		return nil, err
	}

	logEntry := res.Payload
	if len(logEntry) == 0 {
		return nil, fmt.Errorf("retrieved rekor entry has no logEntryAnons")
	}
	if len(logEntry) > 1 {
		return nil, fmt.Errorf("retrieved rekor entry has more than one logEntry")
	}

	// logEntry is a map from uuids to logEntryAnons
	var logEntryAnon *models.LogEntryAnon
	for _, val := range logEntry {
		logEntryAnon = &val
	}

	if logEntryAnon.LogIndex == nil {
		return nil, fmt.Errorf("retrieved rekor entry has no log index")
	}
	logIndex := *logEntryAnon.LogIndex
	log.Debugf("rekor entry %v was retrieved", logIndex)

	ctx := context.Background()
	if err = cosign.VerifyTLogEntry(ctx, client, logEntryAnon); err != nil {
		return nil, fmt.Errorf("could not prove that the log entry is on rekor: %w", err)
	}

	return logEntryAnon, nil
}

// Precondition: client and its fields are not nil.
//
// Postcondition: if no error is returned, the returned struct and its fields are not nil
func getAndVerifySbomFromUUID(uuid string, client *Client) (*sbomWithMetadata, error) {
	logEntryAnon, err := getAndVerifyRekorEntry(uuid, client.rekorClient)
	if err != nil {
		return nil, fmt.Errorf("error retrieving rekor entry by uuid %v: \n\t\t%w", uuid, err)
	}

	logIndex := *logEntryAnon.LogIndex

	if err = verify(client.rekorClient, logEntryAnon); err != nil {
		return nil, fmt.Errorf("rekor log entry %v could not be verified: \n\t\t%w", logIndex, err)
	}

	log.Debugf("verification of rekor entry %v complete", logIndex)

	att, err := parseAndValidateAttestation(logEntryAnon)
	if err != nil {
		return nil, fmt.Errorf("error parsing or validating attestation associated with rekor entry %v: %w", logIndex, err)
	}

	sbomBytes, err := getSbom(att, client.httpClient)
	if err != nil {
		return nil, fmt.Errorf("error retrieving sbom from rekor entry %v: %w", logIndex, err)
	}

	log.Debugf("SBOM (%v bytes) retrieved", len(*sbomBytes))

	if err = verifySbomHash(att, sbomBytes); err != nil {
		return nil, fmt.Errorf("could not verify retrieved sbom (from rekor entry %v): %w", logIndex, err)
	}

	sbomSha1 := sha1.Sum(*sbomBytes) //nolint:gosec // sha1 needed for checksums in spdx format
	decodedHash := hex.EncodeToString(sbomSha1[:])

	sbom, err := parseSbom(sbomBytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing sbom from rekor entry %v: %w", logIndex, err)
	}

	sbomWrapped := &sbomWithMetadata{
		executableSha256: att.Subject[0].Digest["sha256"],
		sha1:             decodedHash,
		rekorEntry:       uuid,
		spdx:             sbom,
	}

	return sbomWrapped, nil
}

// GetAndVerifySboms retrieves Rekor entries associated with an sha256 hash and verifies the entries and the sboms
//
// Precondition: client and its fields are not nil
func getAndVerifySbomsFromHash(sha string, client *Client) ([]*sbomWithMetadata, error) {
	uuids, err := getUuids(sha, client.rekorClient)
	if err != nil {
		return nil, fmt.Errorf("error getting uuids on rekor associated with hash \"%v\": %w", sha, err)
	}

	var sboms []*sbomWithMetadata
	for _, uuid := range uuids {
		sbom, err := getAndVerifySbomFromUUID(uuid, client)
		//nolint:gocritic //for rewrite to switch statement
		if err != nil {
			log.Debug(err)
		} else if sha != sbom.executableSha256 {
			log.Warnf("rekor returned a different entry than was asked for")
		} else {
			sboms = append(sboms, sbom)
		}
	}

	return sboms, nil
}

func getAndVerifySbomsFromResolver(resolver source.FileResolver, location source.Location, client *Client) ([]*sbomWithMetadata, error) {
	closer, err := resolver.FileContentsByLocation(location)
	if err != nil {
		return nil, fmt.Errorf("error getting reader from resolver: %w", err)
	}

	bytes, err := io.ReadAll(closer)
	if err != nil {
		return nil, fmt.Errorf("error reading bytes from file reader: %w", err)
	}

	sha256 := sha256.Sum256(bytes)
	decodedHash := hex.EncodeToString(sha256[:])

	log.Debugf("rekor is being queried for location %v and SHA256: %v", location.RealPath, decodedHash)

	sboms, err := getAndVerifySbomsFromHash(decodedHash, client)
	if err != nil {
		return nil, fmt.Errorf("error searching rekor in location %v: %w", location.RealPath, err)
	}

	return sboms, nil
}
