// nolint:dupl
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

type configImportAPI interface {
	ImportImageConfig(ctx context.Context, sessionID string, contents interface{}) (external.ImageImportContentResponse, *http.Response, error)
}

func importConfig(ctx context.Context, api configImportAPI, sessionID string, config []byte, stage *progress.Stage) (string, error) {
	if len(config) > 0 {
		log.Debug("importing image config")
		stage.Current = "image config"

		// API requires an object, but we do not verify the shape of this object locally
		var sender map[string]interface{}
		if err := json.Unmarshal(config, &sender); err != nil {
			return "", err
		}

		response, httpResponse, err := api.ImportImageConfig(ctx, sessionID, sender)
		if err != nil {
			var openAPIErr external.GenericOpenAPIError
			if errors.As(err, &openAPIErr) {
				log.Errorf("api response: %+v", string(openAPIErr.Body()))
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
