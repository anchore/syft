package xfssource

import (
    "context"
    "fmt"
	"crypto"

    "github.com/anchore/syft/syft/source"
	"github.com/anchore/syft/internal/log"

)

type xfsSourceProvider struct {
	path             string
	exclude          source.ExcludeConfig
	digestAlgorithms []crypto.Hash
	alias            source.Alias
}

func NewSourceProvider(path string, exclude source.ExcludeConfig, digestAlgorithms []crypto.Hash, alias source.Alias) source.Provider {
	log.Debugf("NewSourceProvider: %s - %s - %s - %s", path , exclude, digestAlgorithms, alias)
    return &xfsSourceProvider{
		path:             path,
		exclude:          exclude,
		digestAlgorithms: digestAlgorithms,
		alias:            alias,
    }
}

func (p xfsSourceProvider) Name() string {
    return "xfs-image"
}

func (p xfsSourceProvider) Provide(ctx context.Context) (source.Source, error) {
	log.Debugf("Provide Init: %s", p.path)
    if !isXFSImage(p.path) {
        return nil, fmt.Errorf("not a valid XFS image: %s", p.path)
    }
    return New(p.path)
}

