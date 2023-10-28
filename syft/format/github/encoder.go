package github

import (
	"encoding/json"
	"io"

	"github.com/anchore/syft/syft/format/github/internal/model"
	"github.com/anchore/syft/syft/sbom"
)

const ID sbom.FormatID = "github-json"

type encoder struct {
}

func NewFormatEncoder() sbom.FormatEncoder {
	return encoder{}
}

func (e encoder) ID() sbom.FormatID {
	return ID
}

func (e encoder) Aliases() []string {
	return []string{
		"github",
	}
}

func (e encoder) Version() string {
	return sbom.AnyVersion
}

func (e encoder) Encode(writer io.Writer, s sbom.SBOM) error {
	bom := model.ToGithubModel(&s)

	enc := json.NewEncoder(writer)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")

	return enc.Encode(bom)
}
