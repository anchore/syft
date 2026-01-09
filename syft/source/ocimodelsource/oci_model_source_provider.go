package ocimodelsource

import (
	"context"

	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft/source"
)

type ociModelSourceProvider struct {
	reference    string
	registryOpts *image.RegistryOptions
	alias        source.Alias
}

// NewSourceProvider creates a new OCI model artifact source provider.
func NewSourceProvider(reference string, registryOpts *image.RegistryOptions, alias source.Alias) source.Provider {
	return &ociModelSourceProvider{
		reference:    reference,
		registryOpts: registryOpts,
		alias:        alias,
	}
}

func (p *ociModelSourceProvider) Name() string {
	return "oci-model"
}

func (p *ociModelSourceProvider) Provide(ctx context.Context) (source.Source, error) {
	cfg := Config{
		Reference:       p.reference,
		RegistryOptions: p.registryOpts,
		Alias:           p.alias,
	}
	return NewFromRegistry(ctx, cfg)
}
