package options

import (
	"fmt"
	"sort"

	"github.com/scylladb/go-set/strset"

	intFile "github.com/anchore/syft/internal/file"
	"github.com/anchore/syft/syft/file"
)

type fileConfig struct {
	Metadata   fileMetadata   `yaml:"metadata" json:"metadata" mapstructure:"metadata"`
	Content    fileContent    `yaml:"content" json:"content" mapstructure:"content"`
	Executable fileExecutable `yaml:"executable" json:"executable" mapstructure:"executable"`
}

type fileMetadata struct {
	Selection file.Selection `yaml:"selection" json:"selection" mapstructure:"selection"`
	Digests   []string       `yaml:"digests" json:"digests" mapstructure:"digests"`
}

type fileContent struct {
	SkipFilesAboveSize int64    `yaml:"skip-files-above-size" json:"skip-files-above-size" mapstructure:"skip-files-above-size"`
	Globs              []string `yaml:"globs" json:"globs" mapstructure:"globs"`
}

type fileExecutable struct {
	Globs []string `yaml:"globs" json:"globs" mapstructure:"globs"`
}

func defaultFileConfig() fileConfig {
	return fileConfig{
		Metadata: fileMetadata{
			Selection: file.FilesOwnedByPackageSelection,
			Digests:   []string{"sha1", "sha256"},
		},
		Content: fileContent{
			SkipFilesAboveSize: 250 * intFile.KB,
		},
		Executable: fileExecutable{
			Globs: nil,
		},
	}
}

func (c *fileConfig) PostLoad() error {
	digests := strset.New(c.Metadata.Digests...).List()
	sort.Strings(digests)
	c.Metadata.Digests = digests

	switch c.Metadata.Selection {
	case file.NoFilesSelection, file.FilesOwnedByPackageSelection, file.AllFilesSelection:
		return nil
	}
	return fmt.Errorf("invalid file metadata selection: %q", c.Metadata.Selection)
}
