// nolint: dupl
package anchore

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/wagoodman/go-progress"

	"github.com/anchore/client-go/pkg/external"
	"github.com/anchore/syft/internal/log"
)

type manifestImportAPI interface {
	ImportImageManifest(ctx context.Context, sessionID string, contents string) (external.ImageImportContentResponse, *http.Response, error)
}

func importManifest(ctx context.Context, api manifestImportAPI, sessionID string, manifest []byte, stage *progress.Stage) (string, error) {
	if len(manifest) > 0 {
		log.Debug("importing image manifest")
		stage.Current = "image manifest"

		response, httpResponse, err := api.ImportImageManifest(ctx, sessionID, string(manifest))
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
