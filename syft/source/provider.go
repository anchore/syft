package source

import (
	"context"

	"github.com/anchore/stereoscope/pkg/image"
)

// Provider is able to resolve a source request
type Provider interface {
	Name() string
	ProvideSource(ctx context.Context, req Request) (Source, error)
}

// Request holds all the common arguments passed to a Provider.Provide call
type Request struct {
	Input    string
	Platform *image.Platform
}
