package cataloger

import (
	"github.com/anchore/syft/syft/pkg/cataloger/golang"
	"github.com/anchore/syft/syft/pkg/cataloger/java"
	"github.com/anchore/syft/syft/pkg/cataloger/kernel"
)

type Config struct {
	Search      SearchConfig
	Golang      golang.GoCatalogerOpts
	KernelOpts  kernel.CatalogerOpts
	Catalogers  []string
	Parallelism int
}

func DefaultConfig() Config {
	return Config{
		Search:      DefaultSearchConfig(),
		Parallelism: 1,
	}
}

func (c Config) Java() java.Config {
	return java.Config{
		SearchUnindexedArchives: c.Search.IncludeUnindexedArchives,
		SearchIndexedArchives:   c.Search.IncludeIndexedArchives,
	}
}

func (c Config) Go() golang.GoCatalogerOpts {
	return c.Golang
}

func (c Config) Kernel() kernel.CatalogerOpts {
	return c.KernelOpts
}
