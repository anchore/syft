package template

import (
	"io"

	"github.com/anchore/syft/internal/formats/syftjson"
	options "github.com/anchore/syft/syft/format-options"
	"github.com/anchore/syft/syft/sbom"
)

const ID sbom.FormatID = "template"

func Format() sbom.Format {
	return format{}
}

// implementation of sbom.Format interface
// to make use of format options
type format struct {
	opts options.Format
}

func (f format) ID() sbom.FormatID {
	return ID
}

func (f format) Decode(reader io.Reader) (*sbom.SBOM, error) {
	return nil, sbom.ErrDecodingNotSupported
}

func (f format) Encode(output io.Writer, s sbom.SBOM) error {
	tmpl, err := makeTemplateExecutor(f.opts.TemplateFilePath)
	if err != nil {
		return err
	}

	doc := syftjson.ToFormatModel(s)
	return tmpl.Execute(output, doc)
}

func (f format) Validate(reader io.Reader) error {
	return sbom.ErrValidationNotSupported
}

func (f format) WithOptions(opts options.Format) sbom.Format {
	f.opts = opts
	return f
}
