package anchore

import (
	"context"
	"fmt"
	"net/http"

	"github.com/anchore/client-go/pkg/external"
)

type manifestImportAPI interface {
	ImportImageManifest(ctx context.Context, sessionID string, contents string) (external.ImageImportContentResponse, *http.Response, error)
}

func importManifest(ctx context.Context, api manifestImportAPI, sessionID string, manifest []byte) (string, error) {
	if len(manifest) > 0 {
		response, httpResponse, err := api.ImportImageManifest(ctx, sessionID, string(manifest))
		if err != nil {
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
