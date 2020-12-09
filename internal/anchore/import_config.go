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

type configImportAPI interface {
	ImportImageConfig(ctx context.Context, sessionID string, contents string) (external.ImageImportContentResponse, *http.Response, error)
}

func importConfig(ctx context.Context, api configImportAPI, sessionID string, manifest []byte, stage *progress.Stage) (string, error) {
	if len(manifest) > 0 {
		log.Debug("importing image config")
		stage.Current = "image config"

		response, httpResponse, err := api.ImportImageConfig(ctx, sessionID, string(manifest))
		if err != nil {
			var openApiErr external.GenericOpenAPIError
			if errors.As(err, &openApiErr) {
				log.Errorf("api response: %+v", string(openApiErr.Body()))
			}
			return "", fmt.Errorf("unable to import Config: %w", err)
		}

		defer httpResponse.Body.Close()

		if httpResponse.StatusCode != 200 {
			return "", fmt.Errorf("unable to import Config: %s", httpResponse.Status)
		}

		return response.Digest, nil
	}
	return "", nil
}
