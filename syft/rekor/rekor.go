package rekor

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/source"
	"github.com/sigstore/cosign/cmd/cosign/cli/rekor"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/spdx/tools-golang/spdx"
)

const (
	DefaultRekorAddr = "https://rekor.sigstore.dev"
	InfoForUser      = `
			[EXPERIMENTAL FEATURE: Rekor-cataloger] 
			
			This SBOM contains a relationship that references an external document. This 
			document is not present in the cataloged image or directory; rather it has 
			been found by searching the Rekor transparency log (https://www.sigstore.dev/).  
			
			Trusting this external document relationship requires trusting several entities: 
				- the user or CI/CD action that uploaded an entry to Rekor
				- Rekor transparency log
				- Fulcio CA

			The Rekor entry(s) that were used to create the external document relationship(s)
			are listed below by UUID. See https://github.com/sigstore/rekor for 
			information on how to query Rekor. 
			`
)

type Client struct {
	rekorClient *client.Rekor
	httpClient  *http.Client
}

type ExternalRef struct {
	SpdxRef spdx.ExternalDocumentRef2_2
}

// NewClient returns a client to use the rekor library
func NewClient() (*Client, error) {
	rekorClient, err := rekor.NewClient(DefaultRekorAddr)
	if err != nil {
		return nil, errors.New("error creating rekor client")
	}

	return &Client{
		rekorClient: rekorClient,
		httpClient:  &http.Client{},
	}, nil
}

func (r ExternalRef) ID() artifact.ID {
	id, err := artifact.IDByHash(r.SpdxRef.Checksum)
	if err != nil {
		// TODO: what to do in this case?
		log.Warnf("unable to get fingerprint of ExternalRef %+v: %+v", r, err)
		return ""
	}
	return id
}

func NewExternalRef(docRef string, uri string, alg spdx.ChecksumAlgorithm, hash string) ExternalRef {
	return ExternalRef{
		SpdxRef: spdx.ExternalDocumentRef2_2{
			DocumentRefID: docRef, // docRef is how to identify this ref internally within the SBOM
			URI:           uri,
			Alg:           string(alg),
			Checksum:      hash, // hash of the external document
		},
	}
}

func warnInfoForUser(uuids []string) {
	s := fmt.Sprintf("%s\t%v\n", InfoForUser, uuids)
	log.Warn(s)
}

// CreateRekorSbomRels searches Rekor by the hash of the file in the given location and creates external reference relationships
// for any sboms that are found and verified
func CreateRekorSbomRels(resolver source.FileResolver, location source.Location, client *Client) ([]artifact.Relationship, error) {
	sboms, err := getAndVerifySbomsFromResolver(resolver, location, client)
	if err != nil {
		return nil, err
	}

	var usedRekorEntries []string
	var rels []artifact.Relationship
	for _, sbomWithDigest := range sboms {
		sbom := sbomWithDigest.spdx
		if sbom.CreationInfo == nil {
			log.Warnf("SPDX SBOM found on rekor for file in location %v, but its Creation Info section is empty. Ignoring SBOM", location.RealPath)
			continue
		}
		namespace := sbom.CreationInfo.DocumentNamespace
		docRef := sbom.CreationInfo.DocumentName
		if namespace == "" {
			log.Warnf("SPDX SBOM found on rekor for file in location %v, but its namespace is empty. Ignoring SBOM.", location.RealPath)
			continue
		}

		externalRef := NewExternalRef(docRef, namespace, spdx.SHA1, sbomWithDigest.sha1)
		rel := &artifact.Relationship{
			From: location.Coordinates,
			To:   externalRef,
			Type: artifact.DescribedByRelationship,
		}
		rels = append(rels, *rel)
		usedRekorEntries = append(usedRekorEntries, sbomWithDigest.rekorEntry)
		log.Debug("relationship created for SBOM found on rekor")
	}
	if len(rels) > 0 {
		warnInfoForUser(usedRekorEntries)
	}

	return rels, nil
}
