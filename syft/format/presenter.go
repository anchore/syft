package format

import (
	"io"

	"github.com/anchore/syft/syft/sbom"
)

type Presenter struct {
	sbom    sbom.SBOM
	encoder Encoder
}

func NewPresenter(encoder Encoder, s sbom.SBOM) *Presenter {
	return &Presenter{
		sbom:    s,
		encoder: encoder,
	}
}

func (pres *Presenter) Present(output io.Writer) error {
	return pres.encoder(output, pres.sbom)
}
