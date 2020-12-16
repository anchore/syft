package anchore

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/wagoodman/go-progress"

	"github.com/anchore/syft/internal/log"

	"github.com/anchore/client-go/pkg/external"
)

type dockerfileImportAPI interface {
	ImportImageDockerfile(ctx context.Context, sessionID string, contents string) (external.ImageImportContentResponse, *http.Response, error)
}

func importDockerfile(ctx context.Context, api dockerfileImportAPI, sessionID string, dockerfile []byte, stage *progress.Stage) (string, error) {
	if len(dockerfile) > 0 {
		log.Debug("importing dockerfile")
		stage.Current = "dockerfile"

		response, httpResponse, err := api.ImportImageDockerfile(ctx, sessionID, string(dockerfile))
		if err != nil {
			var openAPIErr external.GenericOpenAPIError
			if errors.As(err, &openAPIErr) {
				log.Errorf("api response: %+v", string(openAPIErr.Body()))
			}
			return "", fmt.Errorf("unable to import Dockerfile: %w", err)
		}

		defer httpResponse.Body.Close()

		if httpResponse.StatusCode != 200 {
			return "", fmt.Errorf("unable to import Dockerfile: %s", httpResponse.Status)
		}

		return response.Digest, nil
	}
	return "", nil
}
