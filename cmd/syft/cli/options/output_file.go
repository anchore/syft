package options

import (
	"github.com/anchore/clio"
	"github.com/anchore/syft/syft/sbom"
)

var _ interface {
	clio.FlagAdder
	clio.PostLoader
} = (*OutputFile)(nil)

// OutputFile is only the --file argument
type OutputFile struct {
	File string `yaml:"file" json:"file" mapstructure:"file"` // --file, the file to write report output to
}

func (o *OutputFile) AddFlags(flags clio.FlagSet) {
	flags.StringVarP(&o.File, "file", "",
		"file to write the default report output to (default is STDOUT)")
}

func (o *OutputFile) PostLoad() error {
	if o.File != "" {
		file, err := expandFilePath(o.File)
		if err != nil {
			return err
		}
		o.File = file
	}
	return nil
}

func (o *OutputFile) SBOMWriter(f sbom.FormatEncoder) (sbom.Writer, error) {
	writer, err := newSBOMMultiWriter(newSBOMWriterDescription(f, o.File))
	if err != nil {
		return nil, err
	}

	return writer, nil
}
