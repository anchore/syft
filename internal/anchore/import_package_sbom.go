package anchore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/anchore/client-go/pkg/external"
	"github.com/anchore/syft/internal/formats/syftjson"
	syftjsonModel "github.com/anchore/syft/internal/formats/syftjson/model"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/sbom"
	"github.com/wagoodman/go-progress"
)

type packageSBOMImportAPI interface {
	ImportImagePackages(context.Context, string, external.ImagePackageManifest) (external.ImageImportContentResponse, *http.Response, error)
}

// importSBOM mirrors all elements found on the syftjson model format object relative to the anchore engine import schema.
type importSBOM struct {
	Artifacts             []syftjsonModel.Package      `json:"artifacts"` // Artifacts is the list of packages discovered and placed into the catalog
	ArtifactRelationships []syftjsonModel.Relationship `json:"artifactRelationships"`
	Files                 []syftjsonModel.File         `json:"files,omitempty"`   // note: must have omitempty
	Secrets               []syftjsonModel.Secrets      `json:"secrets,omitempty"` // note: must have omitempty
	Source                syftjsonModel.Source         `json:"source"`            // Source represents the original object that was cataloged
	Distro                external.ImportDistribution  `json:"distro"`            // Distro represents the Linux distribution that was detected from the source
	Descriptor            syftjsonModel.Descriptor     `json:"descriptor"`        // Descriptor is a block containing self-describing information about syft
	Schema                syftjsonModel.Schema         `json:"schema"`            // Schema is a block reserved for defining the version for the shape of this JSON document and where to find the schema document to validate the shape
}

// toImportSBOMModel transforms the current sbom shape into what is needed for the current anchore import api shape.
func toImportSBOMModel(s sbom.SBOM) importSBOM {
	m := syftjson.ToFormatModel(s)

	var idLike string
	if len(m.Distro.IDLike) > 0 {
		idLike = m.Distro.IDLike[0]
	}

	var version = m.Distro.VersionID // note: version is intentionally not used as the default
	if version == "" {
		version = m.Distro.Version
	}

	var name = m.Distro.ID // note: name is intentionally not used as the default
	if name == "" {
		name = m.Distro.Name
	}

	return importSBOM{
		Artifacts:             m.Artifacts,
		ArtifactRelationships: m.ArtifactRelationships,
		Files:                 m.Files,
		Secrets:               m.Secrets,
		Source:                m.Source,
		Distro: external.ImportDistribution{
			Name:    name,
			Version: version,
			IdLike:  idLike,
		},
		Descriptor: m.Descriptor,
		Schema:     m.Schema,
	}
}

func packageSbomModel(s sbom.SBOM) (*external.ImagePackageManifest, error) {
	var buf bytes.Buffer

	doc := toImportSBOMModel(s)

	enc := json.NewEncoder(&buf)
	// prevent > and < from being escaped in the payload
	enc.SetEscapeHTML(false)
	enc.SetIndent("", " ")

	if err := enc.Encode(&doc); err != nil {
		return nil, fmt.Errorf("unable to encode import JSON model: %w", err)
	}

	// the model is 1:1 the JSON output of today. As the schema changes, this will need to be converted into individual mappings.
	var model external.ImagePackageManifest
	if err := json.Unmarshal(buf.Bytes(), &model); err != nil {
		return nil, fmt.Errorf("unable to convert JSON output to import model: %w", err)
	}

	return &model, nil
}

func importPackageSBOM(ctx context.Context, api packageSBOMImportAPI, sessionID string, s sbom.SBOM, stage *progress.Stage) (string, error) {
	log.Debug("importing package SBOM")
	stage.Current = "package SBOM"

	model, err := packageSbomModel(s)
	if err != nil {
		return "", fmt.Errorf("unable to create PackageSBOM model: %w", err)
	}

	response, httpResponse, err := api.ImportImagePackages(ctx, sessionID, *model)
	if err != nil {
		var openAPIErr external.GenericOpenAPIError
		if errors.As(err, &openAPIErr) {
			log.Errorf("api response: %+v", string(openAPIErr.Body()))
		}
		return "", fmt.Errorf("unable to import PackageSBOM: %w", err)
	}

	defer httpResponse.Body.Close()

	if httpResponse.StatusCode != 200 {
		return "", fmt.Errorf("unable to import PackageSBOM: %s", httpResponse.Status)
	}

	return response.Digest, nil
}
