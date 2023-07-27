package cataloger

import (
	"github.com/anchore/syft/syft/pkg/cataloger/golang"
	"github.com/anchore/syft/syft/pkg/cataloger/java"
	"github.com/anchore/syft/syft/pkg/cataloger/kernel"
	"github.com/anchore/syft/syft/pkg/cataloger/python"
)

// TODO: these field naming vs helper function naming schemes are inconsistent.

type Config struct {
	Search      SearchConfig
	Golang      golang.GoCatalogerOpts
	LinuxKernel kernel.LinuxCatalogerConfig
	Python      python.CatalogerConfig
	Catalogers  []string
	Parallelism int
}

func DefaultConfig() Config {
	return Config{
		Search:      DefaultSearchConfig(),
		Parallelism: 1,
		LinuxKernel: kernel.DefaultLinuxCatalogerConfig(),
		Python:      python.DefaultCatalogerConfig(),
	}
}

func (c Config) Java() java.Config {
	return java.Config{
		SearchUnindexedArchives: c.Search.IncludeUnindexedArchives,
		SearchIndexedArchives:   c.Search.IncludeIndexedArchives,
	}
}
