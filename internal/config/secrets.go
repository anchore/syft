package config

import (
	"fmt"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/file/cataloger/secrets"
	"github.com/anchore/syft/syft/source"
	"github.com/spf13/viper"
)

type secretsCfg struct {
	Cataloger           catalogerOptions  `yaml:"cataloger" json:"cataloger" mapstructure:"cataloger"`
	AdditionalPatterns  map[string]string `yaml:"additional-patterns" json:"additional-patterns" mapstructure:"additional-patterns"`
	ExcludePatternNames []string          `yaml:"exclude-pattern-names" json:"exclude-pattern-names" mapstructure:"exclude-pattern-names"`
	RevealValues        bool              `yaml:"reveal-values" json:"reveal-values" mapstructure:"reveal-values"`
	SkipFilesAboveSize  int64             `yaml:"skip-files-above-size" json:"skip-files-above-size" mapstructure:"skip-files-above-size"`
}

func (cfg secretsCfg) loadDefaultValues(v *viper.Viper) {
	v.SetDefault("secrets.cataloger.enabled", catalogerEnabledDefault)
	v.SetDefault("secrets.cataloger.scope", source.AllLayersScope)
	v.SetDefault("secrets.reveal-values", false)
	v.SetDefault("secrets.skip-files-above-size", 1*file.MB)
	v.SetDefault("secrets.additional-patterns", map[string]string{})
	v.SetDefault("secrets.exclude-pattern-names", []string{})
}

func (cfg *secretsCfg) parseConfigValues() error {
	return cfg.Cataloger.parseConfigValues()
}

func (cfg secretsCfg) ToConfig() (*secrets.CatalogerConfig, error) {
	patterns, err := file.GenerateSearchPatterns(secrets.DefaultSecretsPatterns, cfg.AdditionalPatterns, cfg.ExcludePatternNames)
	if err != nil {
		return nil, fmt.Errorf("unable to process secrets config patterns: %w", err)
	}
	return &secrets.CatalogerConfig{
		Patterns:     patterns,
		RevealValues: cfg.RevealValues,
		MaxFileSize:  cfg.SkipFilesAboveSize,
	}, nil
}
