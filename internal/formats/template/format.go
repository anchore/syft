package template

import (
	options "github.com/anchore/syft/syft/format-options"
	"github.com/anchore/syft/syft/sbom"
)

const ID sbom.FormatID = "template"

func Format() sbom.Format {
	return sbom.NewFormat(
		ID,
		makeEncoderWithTemplate(""),
		nil,
		nil,
	)
}

func MakeFormatter(options options.Format) sbom.Format {
	enc := makeEncoderWithTemplate(options.TemplateFilePath)
	return sbom.NewFormat(
		ID,
		enc,
		nil,
		nil,
	)
}
