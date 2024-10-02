package options

import (
	"github.com/anchore/clio"
	"github.com/anchore/syft/syft/cataloging"
)

type packageConfig struct {
	SearchUnindexedArchives         bool `yaml:"search-unindexed-archives" json:"search-unindexed-archives" mapstructure:"search-unindexed-archives"`
	SearchIndexedArchives           bool `yaml:"search-indexed-archives" json:"search-indexed-archives" mapstructure:"search-indexed-archives"`
	ExcludeBinaryOverlapByOwnership bool `yaml:"exclude-binary-overlap-by-ownership" json:"exclude-binary-overlap-by-ownership" mapstructure:"exclude-binary-overlap-by-ownership"` // exclude synthetic binary packages owned by os package files
}

var _ interface {
	clio.FieldDescriber
} = (*packageConfig)(nil)

func (o *packageConfig) DescribeFields(descriptions clio.FieldDescriptionSet) {
	descriptions.Add(&o.SearchUnindexedArchives, `search within archives that do contain a file index to search against (zip)
note: for now this only applies to the java package cataloger`)
	descriptions.Add(&o.SearchIndexedArchives, `search within archives that do not contain a file index to search against (tar, tar.gz, tar.bz2, etc)
note: enabling this may result in a performance impact since all discovered compressed tars will be decompressed
note: for now this only applies to the java package cataloger`)
	descriptions.Add(&o.ExcludeBinaryOverlapByOwnership, `allows users to exclude synthetic binary packages from the sbom
these packages are removed if an overlap with a non-synthetic package is found`)
}

func defaultPackageConfig() packageConfig {
	c := cataloging.DefaultArchiveSearchConfig()
	return packageConfig{
		SearchIndexedArchives:           c.IncludeIndexedArchives,
		SearchUnindexedArchives:         c.IncludeUnindexedArchives,
		ExcludeBinaryOverlapByOwnership: true,
	}
}
