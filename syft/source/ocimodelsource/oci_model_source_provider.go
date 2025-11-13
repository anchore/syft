package ocimodelsource

import (
	"context"
	"fmt"

	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/source"
)

// NewSourceProvider creates a new OCI model artifact source provider.
func NewSourceProvider(reference string, registryOpts *image.RegistryOptions, alias source.Alias) source.Provider {
	return &ociModelSourceProvider{
		reference:    reference,
		registryOpts: registryOpts,
		alias:        alias,
	}
}

type ociModelSourceProvider struct {
	reference    string
	registryOpts *image.RegistryOptions
	alias        source.Alias
}

func (p *ociModelSourceProvider) Name() string {
	return "oci-model-artifact"
}

func (p *ociModelSourceProvider) Provide(ctx context.Context) (source.Source, error) {
	// Create registry client
	client, err := NewRegistryClient(p.registryOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to create registry client: %w", err)
	}

	// Check if this is a model artifact (lightweight check)
	log.WithFields("reference", p.reference).Debug("checking if reference is a model artifact")

	isModel, err := client.IsModelArtifactReference(ctx, p.reference)
	if err != nil {
		// Log the error but don't fail - let other providers try
		log.WithFields("reference", p.reference, "error", err).Debug("failed to check if reference is a model artifact")
		return nil, fmt.Errorf("not an OCI model artifact: %w", err)
	}

	if !isModel {
		log.WithFields("reference", p.reference).Debug("reference is not a model artifact")
		return nil, fmt.Errorf("not an OCI model artifact")
	}

	log.WithFields("reference", p.reference).Info("detected OCI model artifact, fetching headers")

	// Fetch the full model artifact with metadata
	artifact, err := client.FetchModelArtifact(ctx, p.reference)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch model artifact: %w", err)
	}

	// Check if there are any GGUF layers
	if len(artifact.GGUFLayers) == 0 {
		log.WithFields("reference", p.reference).Warn("model artifact has no GGUF layers")
		return nil, fmt.Errorf("model artifact has no GGUF layers")
	}

	log.WithFields("reference", p.reference, "ggufLayers", len(artifact.GGUFLayers)).Info("found GGUF layers in model artifact")

	// Create the source
	src, err := NewFromArtifact(artifact, client, p.alias)
	if err != nil {
		return nil, fmt.Errorf("failed to create OCI model source: %w", err)
	}

	return src, nil
}
