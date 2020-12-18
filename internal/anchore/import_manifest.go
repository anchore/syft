// nolint: dupl
package anchore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/wagoodman/go-progress"

	"github.com/anchore/client-go/pkg/external"
	"github.com/anchore/syft/internal/log"
)

type manifestImportAPI interface {
	ImportImageManifest(ctx context.Context, sessionID string, contents interface{}) (external.ImageImportContentResponse, *http.Response, error)
}

func importManifest(ctx context.Context, api manifestImportAPI, sessionID string, manifest []byte, stage *progress.Stage) (string, error) {
	if len(manifest) > 0 {
		log.Debug("importing image manifest")
		stage.Current = "image manifest"

		// API requires an object, but we do not verify the shape of this object locally
		var sender map[string]interface{}
		if err := json.Unmarshal(manifest, &sender); err != nil {
			return "", err
		}

		response, httpResponse, err := api.ImportImageManifest(ctx, sessionID, sender)
		if err != nil {
			var openAPIErr external.GenericOpenAPIError
			if errors.As(err, &openAPIErr) {
				log.Errorf("api response: %+v", string(openAPIErr.Body()))
			}
			return "", fmt.Errorf("unable to import Manifest: %w", err)
		}

		defer httpResponse.Body.Close()

		if httpResponse.StatusCode != 200 {
			return "", fmt.Errorf("unable to import Manifest: %s", httpResponse.Status)
		}

		return response.Digest, nil
	}
	return "", nil
}
