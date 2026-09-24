package options

import (
	"github.com/anchore/clio"
	"github.com/anchore/syft/syft/cataloging"
)

type archiveConfig struct {
	MaxDepth                int      `yaml:"max-depth" json:"max-depth" mapstructure:"max-depth"`
	MaxExtractionSizeBytes  int64    `yaml:"max-extraction-size-bytes" json:"max-extraction-size-bytes" mapstructure:"max-extraction-size-bytes"`
	MaxFileCount            int      `yaml:"max-file-count" json:"max-file-count" mapstructure:"max-file-count"`
	MaxTotalExtractionBytes int64    `yaml:"max-total-extraction-bytes" json:"max-total-extraction-bytes" mapstructure:"max-total-extraction-bytes"`
	ExcludeExtensions       []string `yaml:"exclude-extensions" json:"exclude-extensions" mapstructure:"exclude-extensions"`
}

var _ interface {
	clio.FieldDescriber
} = (*archiveConfig)(nil)

func defaultArchiveConfig() archiveConfig {
	return archiveConfig{
		MaxDepth:                cataloging.DefaultArchiveMaxDepth,
		MaxExtractionSizeBytes:  cataloging.DefaultArchiveMaxExtractionSizeBytes,
		MaxFileCount:            cataloging.DefaultArchiveMaxFileCount,
		MaxTotalExtractionBytes: cataloging.DefaultArchiveMaxTotalExtractionBytes,
	}
}

func (o *archiveConfig) DescribeFields(descriptions clio.FieldDescriptionSet) {
	descriptions.Add(&o.MaxDepth, `maximum depth of recursive archive extraction (0 = disabled, no recursive extraction)
enabling this allows syft to discover packages inside nested archives (e.g., a tar.gz containing Python packages)`)
	descriptions.Add(&o.MaxExtractionSizeBytes, `maximum total bytes to extract from a single archive before stopping`)
	descriptions.Add(&o.MaxFileCount, `maximum number of files to extract from a single archive before stopping`)
	descriptions.Add(&o.MaxTotalExtractionBytes, `maximum total bytes to extract across all archives before stopping`)
	descriptions.Add(&o.ExcludeExtensions, `archive file extensions to skip during recursive extraction (e.g., [".rpm", ".deb"])`)
}
