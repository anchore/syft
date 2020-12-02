package anchore

import (
	"context"
	"fmt"

	"github.com/anchore/client-go/pkg/external"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft/pkg"
)

func (c *Client) Import(ctx context.Context, imageMetadata image.Metadata, catalog *pkg.Catalog, dockerfile []byte) error {
	authedCtx := c.newRequestContext(ctx)
	startOperation, _, err := c.client.ImportsApi.CreateOperation(authedCtx)
	if err != nil {
		return fmt.Errorf("unable to start import session: %w", err)
	}
	sessionID := startOperation.Uuid

	packageDigest, err := importPackageSBOM(authedCtx, c.client.ImportsApi, sessionID, catalog)
	if err != nil {
		return fmt.Errorf("failed to import Package SBOM: %w", err)
	}

	manifestDigest, err := importManifest(authedCtx, c.client.ImportsApi, sessionID, imageMetadata.RawManifest)
	if err != nil {
		return fmt.Errorf("failed to import Manifest: %w", err)
	}

	dockerfileDigest, err := importDockerfile(authedCtx, c.client.ImportsApi, sessionID, dockerfile)
	if err != nil {
		return fmt.Errorf("failed to import Dockerfile: %w", err)
	}

	imageModel := addImageModel(imageMetadata, packageDigest, manifestDigest, dockerfileDigest)
	_, _, err = c.client.ImagesApi.AddImage(authedCtx, imageModel, nil)
	if err != nil {
		return fmt.Errorf("unable to complete import session=%q: %w", sessionID, err)
	}
	return nil
}

func addImageModel(imageMetadata image.Metadata, packageDigest, manifestDigest, dockerfileDigest string) external.ImageAnalysisRequest {
	var tags = make([]string, len(imageMetadata.Tags))
	for i, t := range imageMetadata.Tags {
		tags[i] = t.String()
	}
	return external.ImageAnalysisRequest{
		Source: external.ImageSource{
			Import: external.ImageImportManifest{
				Contents: external.ImportContentDigests{
					Packages:   packageDigest,
					Manifest:   manifestDigest,
					Dockerfile: dockerfileDigest,
				},
				Tags:         tags,
				Digest:       imageMetadata.ManifestDigest,
				LocalImageId: imageMetadata.ID,
			},
		},
	}
}
