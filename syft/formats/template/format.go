package template

import (
	"fmt"
	"io"

	"github.com/anchore/syft/syft/formats/syftjson"
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

func (f OutputFormat) IDs() []sbom.FormatID {
	return []sbom.FormatID{ID}
}

func (f OutputFormat) Version() string {
	return sbom.AnyVersion
}

func (f OutputFormat) String() string {
	return fmt.Sprintf("template: " + f.templateFilePath)
}

func (f OutputFormat) Decode(_ io.Reader) (*sbom.SBOM, error) {
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

func (f OutputFormat) Validate(_ io.Reader) error {
	return sbom.ErrValidationNotSupported
}

// SetTemplatePath sets path for template file
func (f *OutputFormat) SetTemplatePath(filePath string) {
	f.templateFilePath = filePath
}

var _ sbom.Format = (*OutputFormat)(nil)
