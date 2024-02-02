package filecataloging

import (
	"crypto"
	"encoding/json"
	"fmt"
	"strings"

	intFile "github.com/anchore/syft/internal/file"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/file/cataloger/executable"
	"github.com/anchore/syft/syft/file/cataloger/filecontent"
)

type Config struct {
	Selection  file.Selection     `yaml:"selection" json:"selection" mapstructure:"selection"`
	Hashers    []crypto.Hash      `yaml:"hashers" json:"hashers" mapstructure:"hashers"`
	Content    filecontent.Config `yaml:"content" json:"content" mapstructure:"content"`
	Executable executable.Config  `yaml:"executable" json:"executable" mapstructure:"executable"`
}

type configMarshaledForm struct {
	Selection file.Selection     `yaml:"selection" json:"selection" mapstructure:"selection"`
	Hashers   []string           `yaml:"hashers" json:"hashers" mapstructure:"hashers"`
	Content   filecontent.Config `yaml:"content" json:"content" mapstructure:"content"`
}

func DefaultConfig() Config {
	hashers, err := intFile.Hashers("sha256")
	if err != nil {
		log.WithFields("error", err).Warn("unable to create file hashers")
	}
	return Config{
		Selection:  file.FilesOwnedByPackageSelection,
		Hashers:    hashers,
		Content:    filecontent.DefaultConfig(),
		Executable: executable.DefaultConfig(),
	}
}

func (cfg Config) MarshalJSON() ([]byte, error) {
	marshaled := configMarshaledForm{
		Selection: cfg.Selection,
		Hashers:   hashersToString(cfg.Hashers),
	}
	return json.Marshal(marshaled)
}

func hashersToString(hashers []crypto.Hash) []string {
	var result []string
	for _, h := range hashers {
		result = append(result, strings.ToLower(h.String()))
	}
	return result
}

func (cfg *Config) UnmarshalJSON(data []byte) error {
	var marshaled configMarshaledForm
	if err := json.Unmarshal(data, &marshaled); err != nil {
		return err
	}

	hashers, err := intFile.Hashers(marshaled.Hashers...)
	if err != nil {
		return fmt.Errorf("unable to parse configured hashers: %w", err)
	}
	cfg.Selection = marshaled.Selection
	cfg.Hashers = hashers
	return nil
}

func (cfg Config) WithSelection(selection file.Selection) Config {
	cfg.Selection = selection
	return cfg
}

func (cfg Config) WithHashers(hashers ...crypto.Hash) Config {
	cfg.Hashers = intFile.NormalizeHashes(hashers)
	return cfg
}

func (cfg Config) WithContentConfig(content filecontent.Config) Config {
	cfg.Content = content
	return cfg
}
