package options

import (
	"fmt"
	"sort"

	"github.com/scylladb/go-set/strset"

	"github.com/anchore/clio"
	intFile "github.com/anchore/syft/internal/file"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/file/cataloger/executable"
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
	Globs   []string         `yaml:"globs" json:"globs" mapstructure:"globs"`
	Symbols fileSymbolConfig `yaml:"symbols" json:"symbols" mapstructure:"symbols"`
}

type fileSymbolConfig struct {
	CaptureScope []executable.SymbolCaptureScope `yaml:"capture" json:"capture" mapstructure:"capture"`
	Types        []string                        `yaml:"types" json:"types" mapstructure:"types"`
	Go           fileGoSymbolConfig              `yaml:"go" json:"go" mapstructure:"go"`
}

type fileGoSymbolConfig struct {
	StandardLibrary         bool `yaml:"standard-library" json:"standard-library" mapstructure:"standard-library"`
	ExtendedStandardLibrary bool `yaml:"extended-standard-library" json:"extended-standard-library" mapstructure:"extended-standard-library"`
	ThirdPartyModules       bool `yaml:"third-party-modules" json:"third-party-modules" mapstructure:"third-party-modules"`
}

func defaultFileConfig() fileConfig {
	api := executable.DefaultConfig()

	// start with API defaults and override CLI-specific values
	cfg := fileConfig{
		Metadata: fileMetadata{
			Selection: file.FilesOwnedByPackageSelection,
			Digests:   []string{"sha1", "sha256"},
		},
		Content: fileContent{
			SkipFilesAboveSize: 250 * intFile.KB,
		},
		Executable: fileExecutable{
			Globs: api.Globs,
			Symbols: fileSymbolConfig{
				CaptureScope: api.Symbols.CaptureScope,
				Types:        api.Symbols.Types,
				Go: fileGoSymbolConfig{
					StandardLibrary:         api.Symbols.Go.StandardLibrary,
					ExtendedStandardLibrary: api.Symbols.Go.ExtendedStandardLibrary,
					ThirdPartyModules:       api.Symbols.Go.ThirdPartyModules,
				},
			},
		},
	}
	return cfg
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

	// symbol capture configuration
	descriptions.Add(&c.Executable.Symbols.CaptureScope, `the scope of symbols to capture from executables (options: "golang")`)
	descriptions.Add(&c.Executable.Symbols.Types, `the types of symbols to capture, relative to "go tool nm" output (options: "T", "t", "R", "r", "D", "d", "B", "b", "C", "U")`)

	// go symbol configuration
	descriptions.Add(&c.Executable.Symbols.Go.StandardLibrary, `capture Go standard library symbols (e.g. "fmt", "net/http")`)
	descriptions.Add(&c.Executable.Symbols.Go.ExtendedStandardLibrary, `capture extended Go standard library symbols (e.g. "golang.org/x/net")`)
	descriptions.Add(&c.Executable.Symbols.Go.ThirdPartyModules, `capture third-party module symbols (e.g. "github.com/spf13/cobra")`)
}
