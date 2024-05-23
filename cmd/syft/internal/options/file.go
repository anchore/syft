package options

import (
	"fmt"
	"sort"

	"github.com/scylladb/go-set/strset"

	"github.com/anchore/clio"
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

var _ interface {
	clio.PostLoader
	clio.FieldDescriber
} = (*fileConfig)(nil)

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

func (c *fileConfig) DescribeFields(descriptions clio.FieldDescriptionSet) {
	descriptions.Add(&c.Metadata.Selection, `select which files should be captured by the file-metadata cataloger and included in the SBOM. 
Options include:
 - "all": capture all files from the search space
 - "owned-by-package": capture only files owned by packages
 - "none", "": do not capture any files`)
	descriptions.Add(&c.Metadata.Digests, `the file digest algorithms to use when cataloging files (options: "md5", "sha1", "sha224", "sha256", "sha384", "sha512")`)

	descriptions.Add(&c.Content.SkipFilesAboveSize, `skip searching a file entirely if it is above the given size (default = 1MB; unit = bytes)`)
	descriptions.Add(&c.Content.Globs, `file globs for the cataloger to match on`)

	descriptions.Add(&c.Executable.Globs, `file globs for the cataloger to match on`)
}
