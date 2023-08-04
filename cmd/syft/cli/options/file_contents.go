package options

import (
	"github.com/anchore/syft/internal/file"
	"github.com/anchore/syft/syft/source"
)

type fileContents struct {
	Cataloger          catalogerOptions `yaml:"cataloger" json:"cataloger" mapstructure:"cataloger"`
	SkipFilesAboveSize int64            `yaml:"skip-files-above-size" json:"skip-files-above-size" mapstructure:"skip-files-above-size"`
	Globs              []string         `yaml:"globs" json:"globs" mapstructure:"globs"`
}

func fileContentsDefault() fileContents {
	return fileContents{
		Cataloger: catalogerOptions{
			Scope: source.SquashedScope.String(),
		},
		SkipFilesAboveSize: 1 * file.MB,
	}
}
