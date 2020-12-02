package anchore

import (
	"context"
	"fmt"
	"net/http"

	"github.com/anchore/client-go/pkg/external"
)

type dockerfileImportAPI interface {
	ImportImageDockerfile(ctx context.Context, sessionID string, contents string) (external.ImageImportContentResponse, *http.Response, error)
}

func importDockerfile(ctx context.Context, api dockerfileImportAPI, sessionID string, dockerfile []byte) (string, error) {
	if len(dockerfile) > 0 {
		response, httpResponse, err := api.ImportImageDockerfile(ctx, sessionID, string(dockerfile))
		if err != nil {
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
