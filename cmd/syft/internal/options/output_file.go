package options

import (
	"fmt"

	"github.com/mitchellh/go-homedir"

	"github.com/anchore/clio"
	"github.com/anchore/fangs"
	"github.com/anchore/syft/syft/sbom"
)

var _ interface {
	clio.FlagAdder
	clio.PostLoader
} = (*OutputFile)(nil)

// Deprecated: OutputFile supports the --file to write the SBOM output to
type OutputFile struct {
	Enabled    bool   `yaml:"-" json:"-" mapstructure:"-"`
	LegacyFile string `yaml:"-" json:"-" mapstructure:"legacyFile"`
}

func (o *OutputFile) AddFlags(flags clio.FlagSet) {
	if o.Enabled {
		flags.StringVarP(&o.LegacyFile, "file", "",
			"file to write the default report output to (default is STDOUT)")

		if pfp, ok := flags.(fangs.PFlagSetProvider); ok {
			flagSet := pfp.PFlagSet()
			flagSet.Lookup("file").Deprecated = "use: --output FORMAT=PATH"
		}
	}
}

func (o *OutputFile) PostLoad() error {
	if !o.Enabled {
		return nil
	}
	if o.LegacyFile != "" {
		file, err := expandFilePath(o.LegacyFile)
		if err != nil {
			return err
		}
		o.LegacyFile = file
	}
	return nil
}

func (o *OutputFile) SBOMWriter(f sbom.FormatEncoder) (sbom.Writer, error) {
	if !o.Enabled {
		return nil, nil
	}
	writer, err := newSBOMMultiWriter(newSBOMWriterDescription(f, o.LegacyFile))
	if err != nil {
		return nil, err
	}

	return writer, nil
}

func expandFilePath(file string) (string, error) {
	if file != "" {
		expandedPath, err := homedir.Expand(file)
		if err != nil {
			return "", fmt.Errorf("unable to expand file path=%q: %w", file, err)
		}
		file = expandedPath
	}
	return file, nil
}
