package anchore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/anchore/syft/syft/sbom"

	"github.com/anchore/syft/internal/formats/syftjson"

	"github.com/wagoodman/go-progress"

	"github.com/anchore/client-go/pkg/external"
	"github.com/anchore/syft/internal/log"
)

type packageSBOMImportAPI interface {
	ImportImagePackages(context.Context, string, external.ImagePackageManifest) (external.ImageImportContentResponse, *http.Response, error)
}

func packageSbomModel(s sbom.SBOM) (*external.ImagePackageManifest, error) {
	var buf bytes.Buffer

	err := syftjson.Format().Encode(&buf, s)
	if err != nil {
		return nil, fmt.Errorf("unable to serialize results: %w", err)
	}

	// the model is 1:1 the JSON output of today. As the schema changes, this will need to be converted into individual mappings.
	var model external.ImagePackageManifest
	if err = json.Unmarshal(buf.Bytes(), &model); err != nil {
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
