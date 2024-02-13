package source

import (
	"context"
)

// Provider is able to resolve a source request
type Provider interface {
	Name() string
	ProvideSource(ctx context.Context) (Source, error)
}
