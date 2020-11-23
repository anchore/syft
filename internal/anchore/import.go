package anchore

import (
	"context"
	"fmt"
)

type Importer interface {
	doImport(ctx context.Context, sessionID string, importsApi interface{}) error
}

func (c *Client) Import(ctx context.Context, importers ...Importer) (string, string, error) {

	if c.sessionID == "" {
		startOperation, _, err := c.client.ImportsApi.StartImageImport(c.newRequestContext(ctx))
		if err != nil {
			return "", "", fmt.Errorf("unable to start doImport session: %w", err)
		}
		c.sessionID = startOperation.Uuid
	}

	for _, importer := range importers {
		// TODO: are there any useful return values that should be persisted or shown to the user?
		err := importer.doImport(c.newRequestContext(ctx), c.sessionID, c.client.ImportsApi)
		if err != nil {
			return "", "", err
		}
	}

	// TODO: are there any useful return values that should be persisted or shown to the user?
	//finalizeResponse, _, err := c.client.ImportsApi.FinalizeImageImport(c.newRequestContext(ctx), c.sessionID, _TODO_)
	//if err != nil {
	//	return "", "", fmt.Errorf("unable to complete doImport session=%q: %w", c.sessionID, err)
	//}
	//return c.sessionID, finalizeResponse.Status, nil
	return "", "", nil
}
