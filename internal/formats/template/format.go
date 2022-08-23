package template

import (
	"io"

	"github.com/anchore/syft/internal/formats/syftjson"
	"github.com/anchore/syft/syft/sbom"
)

const ID sbom.FormatID = "template"

func Format() sbom.Format {
	return OutputFormat{}
}

// implementation of sbom.Format interface
// to make use of format options
type OutputFormat struct {
	templateFilePath string
}

func (f OutputFormat) ID() sbom.FormatID {
	return ID
}

func (f OutputFormat) Decode(reader io.Reader) (*sbom.SBOM, error) {
	return nil, sbom.ErrDecodingNotSupported
}

func (f OutputFormat) Encode(output io.Writer, s sbom.SBOM) error {
	tmpl, err := makeTemplateExecutor(f.templateFilePath)
	if err != nil {
		return err
	}

	doc := syftjson.ToFormatModel(s)
	return tmpl.Execute(output, doc)
}

func (f OutputFormat) Validate(reader io.Reader) error {
	return sbom.ErrValidationNotSupported
}

func (f OutputFormat) Parse(input interface{}) (*sbom.SBOM, error) {
	return nil, sbom.ErrParsingNotSupported
}

// SetTemplatePath sets path for template file
func (f *OutputFormat) SetTemplatePath(filePath string) {
	f.templateFilePath = filePath
}
