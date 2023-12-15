package options

import (
	"fmt"

	intFile "github.com/anchore/syft/internal/file"
	"github.com/anchore/syft/syft/file"
)

type fileConfig struct {
	Metadata fileMetadata `yaml:"metadata" json:"metadata" mapstructure:"metadata"`
	Content  fileContent  `yaml:"content" json:"content" mapstructure:"content"`
}

type fileMetadata struct {
	Selection file.Selection `yaml:"selection" json:"selection" mapstructure:"selection"`
	Digests   []string       `yaml:"digests" json:"digests" mapstructure:"digests"`
}

type fileContent struct {
	SkipFilesAboveSize int64    `yaml:"skip-files-above-size" json:"skip-files-above-size" mapstructure:"skip-files-above-size"`
	Globs              []string `yaml:"globs" json:"globs" mapstructure:"globs"`
}

func defaultFile() fileConfig {
	return fileConfig{
		Metadata: fileMetadata{
			Selection: file.OwnedFilesSelection,
			Digests:   []string{"sha1", "sha256"},
		},
		Content: fileContent{
			SkipFilesAboveSize: 1 * intFile.MB,
		},
	}
}

func (c *fileConfig) PostLoad() error {
	switch c.Metadata.Selection {
	case file.NoFilesSelection, file.OwnedFilesSelection, file.AllFilesSelection:
		return nil
	}
	return fmt.Errorf("invalid file metadata selection: %q", c.Metadata.Selection)
}
