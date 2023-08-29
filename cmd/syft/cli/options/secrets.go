package options

import (
	"github.com/anchore/syft/internal/file"
	"github.com/anchore/syft/syft/source"
)

type secrets struct {
	Cataloger           scope             `yaml:"cataloger" json:"cataloger" mapstructure:"cataloger"`
	AdditionalPatterns  map[string]string `yaml:"additional-patterns" json:"additional-patterns" mapstructure:"additional-patterns"`
	ExcludePatternNames []string          `yaml:"exclude-pattern-names" json:"exclude-pattern-names" mapstructure:"exclude-pattern-names"`
	RevealValues        bool              `yaml:"reveal-values" json:"reveal-values" mapstructure:"reveal-values"`
	SkipFilesAboveSize  int64             `yaml:"skip-files-above-size" json:"skip-files-above-size" mapstructure:"skip-files-above-size"`
}

func defaultSecrets() secrets {
	return secrets{
		Cataloger: scope{
			Scope: source.AllLayersScope.String(),
		},
		SkipFilesAboveSize: 1 * file.MB,
	}
}
