package anchore

import (
	"context"
	"fmt"

	"github.com/anchore/syft/syft/pkg"
)

type importer func() error

func (c *Client) Import(ctx context.Context, catalog *pkg.Catalog) (string, string, error) {
	authedCtx := c.newRequestContext(ctx)
	startOperation, _, err := c.client.ImportsApi.StartImageImport(authedCtx)
	if err != nil {
		return "", "", fmt.Errorf("unable to start doImport session: %w", err)
	}
	sessionID := startOperation.Uuid

	// do the imports...

	var importers = []importer{
		generatePackageSbomImporter(authedCtx, c.client.ImportsApi, sessionID, catalog),
	}

	for _, importer := range importers {
		// TODO: are there any useful return values that should be persisted or shown to the user?
		if err := importer(); err != nil {
			return "", "", err
		}
	}

	// TODO: are there any useful return values that should be persisted or shown to the user?
	//finalizeResponse, _, err := c.client.ImportsApi.FinalizeImageImport(authedCtx, sessionID, _TODO_)
	//if err != nil {
	//	return "", "", fmt.Errorf("unable to complete doImport session=%q: %w", sessionID, err)
	//}
	//return sessionID, finalizeResponse.Status, nil
	return "", "", nil
}
