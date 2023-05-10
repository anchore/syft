package config

import (
	"fmt"

	"github.com/mitchellh/go-homedir"

	"github.com/anchore/fangs"
	"github.com/anchore/go-logger"
)

// logging contains all logging-related configuration options available to the user via the application config.
type logging struct {
	Structured   bool         `yaml:"structured" json:"structured" mapstructure:"structured"` // show all log entries as JSON formatted strings
	Level        logger.Level `yaml:"level" json:"level" mapstructure:"level"`                // the log level string hint
	FileLocation string       `yaml:"file" json:"file-location" mapstructure:"file"`          // the file path to write logs to
}

var _ fangs.PostLoad = (*logging)(nil)

func newLogging() logging {
	return logging{
		Level: logger.WarnLevel,
	}
}

func (cfg *logging) PostLoad() error {
	if cfg.FileLocation != "" {
		expandedPath, err := homedir.Expand(cfg.FileLocation)
		if err != nil {
			return fmt.Errorf("unable to expand log file path=%q: %w", cfg.FileLocation, err)
		}
		cfg.FileLocation = expandedPath
	}
	return nil
}
