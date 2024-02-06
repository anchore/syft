package source

import (
	"context"
)

// Provider is the signature used for detectors passed to Detect(cfg, detectors...)
type Provider interface {
	Name() string
	Provide(ctx context.Context, userInput string) (Source, error)
}
