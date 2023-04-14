package cataloger

import (
	"github.com/anchore/syft/syft/pkg/cataloger/golang"
	"github.com/anchore/syft/syft/pkg/cataloger/java"
	"github.com/anchore/syft/syft/pkg/cataloger/kernel"
)

// TODO: these field naming vs helper function naming schemes are inconsistent.

type Config struct {
	Search      SearchConfig
	Golang      golang.GoCatalogerOpts
	LinuxKernel kernel.LinuxCatalogerConfig
	Catalogers  []string
	Parallelism int
}

func DefaultConfig() Config {
	return Config{
		Search:      DefaultSearchConfig(),
		Parallelism: 1,
		LinuxKernel: kernel.DefaultLinuxCatalogerConfig(),
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

func (c Config) Kernel() kernel.LinuxCatalogerConfig {
	return c.LinuxKernel
}
