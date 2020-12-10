package anchore

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/anchore/client-go/pkg/external"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/internal/bus"
	"github.com/anchore/syft/syft/distro"
	"github.com/anchore/syft/syft/event"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/go-progress"
)

func importProgress(source string) (*progress.Stage, *progress.Manual) {
	stage := &progress.Stage{}
	prog := &progress.Manual{
		// this is the number of stages to expect; start + individual endpoints + stop
		Total: 6,
	}
	bus.Publish(partybus.Event{
		Type:   event.ImportStarted,
		Source: source,
		Value: progress.StagedProgressable(&struct {
			progress.Stager
			progress.Progressable
		}{
			Stager:       progress.Stager(stage),
			Progressable: prog,
		}),
	})

	return stage, prog
}

// nolint:funlen
func (c *Client) Import(ctx context.Context, imageMetadata image.Metadata, s source.Metadata, catalog *pkg.Catalog, d *distro.Distro, dockerfile []byte) error {
	stage, prog := importProgress(imageMetadata.ID)

	ctxWithTimeout, cancel := context.WithTimeout(ctx, time.Second*30)
	defer cancel()

	authedCtx := c.newRequestContext(ctxWithTimeout)

	stage.Current = "starting session"
	startOperation, _, err := c.client.ImportsApi.CreateOperation(authedCtx)
	if err != nil {
		var detail = "no details given"
		var openAPIErr external.GenericOpenAPIError
		if errors.As(err, &openAPIErr) {
			detail = string(openAPIErr.Body())
		}
		return fmt.Errorf("unable to start import session: %w: %s", err, detail)
	}
	prog.N++
	sessionID := startOperation.Uuid

	packageDigest, err := importPackageSBOM(authedCtx, c.client.ImportsApi, sessionID, s, catalog, d, stage)
	if err != nil {
		return fmt.Errorf("failed to import Package SBOM: %w", err)
	}
	prog.N++

	manifestDigest, err := importManifest(authedCtx, c.client.ImportsApi, sessionID, imageMetadata.RawManifest, stage)
	if err != nil {
		return fmt.Errorf("failed to import Manifest: %w", err)
	}
	prog.N++

	configDigest, err := importConfig(authedCtx, c.client.ImportsApi, sessionID, imageMetadata.RawConfig, stage)
	if err != nil {
		return fmt.Errorf("failed to import Config: %w", err)
	}
	prog.N++

	dockerfileDigest, err := importDockerfile(authedCtx, c.client.ImportsApi, sessionID, dockerfile, stage)
	if err != nil {
		return fmt.Errorf("failed to import Dockerfile: %w", err)
	}
	prog.N++

	stage.Current = "finalizing"
	imageModel := addImageModel(imageMetadata, packageDigest, manifestDigest, dockerfileDigest, configDigest, sessionID)
	_, _, err = c.client.ImagesApi.AddImage(authedCtx, imageModel, nil)
	if err != nil {
		var detail = "no details given"
		var openAPIErr external.GenericOpenAPIError
		if errors.As(err, &openAPIErr) {
			detail = string(openAPIErr.Body())
		}
		return fmt.Errorf("unable to complete import session=%q: %w: %s", sessionID, err, detail)
	}
	prog.N++

	stage.Current = ""
	prog.SetCompleted()

	return nil
}

func addImageModel(imageMetadata image.Metadata, packageDigest, manifestDigest, dockerfileDigest, configDigest, sessionID string) external.ImageAnalysisRequest {
	var tags = make([]string, len(imageMetadata.Tags))
	for i, t := range imageMetadata.Tags {
		tags[i] = t.String()
	}

	return external.ImageAnalysisRequest{
		Source: external.ImageSource{
			Import: &external.ImageImportManifest{
				Contents: external.ImportContentDigests{
					Packages:    packageDigest,
					Manifest:    manifestDigest,
					Dockerfile:  dockerfileDigest,
					ImageConfig: configDigest,
				},
				Tags:          tags,
				Digest:        imageMetadata.ManifestDigest,
				LocalImageId:  imageMetadata.ID,
				OperationUuid: sessionID,
			},
		},
	}
}
