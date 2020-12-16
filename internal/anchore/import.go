package anchore

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/antihax/optional"

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

type ImportConfig struct {
	ImageMetadata           image.Metadata
	SourceMetadata          source.Metadata
	Catalog                 *pkg.Catalog
	Distro                  *distro.Distro
	Dockerfile              []byte
	OverwriteExistingUpload bool
}

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
func (c *Client) Import(ctx context.Context, cfg ImportConfig) error {
	stage, prog := importProgress(c.config.Hostname)

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

	packageDigest, err := importPackageSBOM(authedCtx, c.client.ImportsApi, sessionID, cfg.SourceMetadata, cfg.Catalog, cfg.Distro, stage)
	if err != nil {
		return fmt.Errorf("failed to import Package SBOM: %w", err)
	}
	prog.N++

	manifestDigest, err := importManifest(authedCtx, c.client.ImportsApi, sessionID, cfg.ImageMetadata.RawManifest, stage)
	if err != nil {
		return fmt.Errorf("failed to import Manifest: %w", err)
	}
	prog.N++

	configDigest, err := importConfig(authedCtx, c.client.ImportsApi, sessionID, cfg.ImageMetadata.RawConfig, stage)
	if err != nil {
		return fmt.Errorf("failed to import Config: %w", err)
	}
	prog.N++

	dockerfileDigest, err := importDockerfile(authedCtx, c.client.ImportsApi, sessionID, cfg.Dockerfile, stage)
	if err != nil {
		return fmt.Errorf("failed to import Dockerfile: %w", err)
	}
	prog.N++

	stage.Current = "finalizing"
	imageModel := addImageModel(cfg.ImageMetadata, packageDigest, manifestDigest, dockerfileDigest, configDigest, sessionID)
	opts := external.AddImageOpts{
		Force: optional.NewBool(cfg.OverwriteExistingUpload),
	}

	_, _, err = c.client.ImagesApi.AddImage(authedCtx, imageModel, &opts)
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
