package cataloger

import (
	"github.com/anchore/syft/syft/pkg/cataloger/golang"
	"github.com/anchore/syft/syft/pkg/cataloger/java"
	"github.com/anchore/syft/syft/pkg/cataloger/kernel"
	"github.com/anchore/syft/syft/pkg/cataloger/python"
)

// TODO: these field naming vs helper function naming schemes are inconsistent.
type Config struct {
	Search                          SearchConfig
	Golang                          golang.GoCatalogerOpts
	LinuxKernel                     kernel.LinuxCatalogerConfig
	Python                          python.CatalogerConfig
	Java                            java.CatalogerOpts
	Catalogers                      []string
	Parallelism                     int
	ExcludeBinaryOverlapByOwnership bool
}

func DefaultConfig() Config {
	return Config{
		Search:                          DefaultSearchConfig(),
		Parallelism:                     1,
		LinuxKernel:                     kernel.DefaultLinuxCatalogerConfig(),
		Python:                          python.DefaultCatalogerConfig(),
		Java:                            java.DefaultCatalogerOpts(),
		ExcludeBinaryOverlapByOwnership: true,
	}
}

// JavaConfig merges relevant config values from Config to return a java.Config struct.
// Values like IncludeUnindexedArchives and IncludeIndexedArchives are used across catalogers
// and are not specific to Java requiring this merge.
func (c Config) JavaConfig() java.Config {
	return java.Config{
		SearchUnindexedArchives: c.Search.IncludeUnindexedArchives,
		SearchIndexedArchives:   c.Search.IncludeIndexedArchives,
		UseNetwork:              c.Java.UseNetwork,
		MavenBaseURL:            c.Java.MavenURL,
		MaxParentRecursiveDepth: c.Java.MaxParentRecursiveDepth,
	}
}
