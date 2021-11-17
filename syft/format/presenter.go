package format

import (
	"io"

	"github.com/anchore/syft/syft/sbom"
)

type Presenter struct {
	sbom      sbom.SBOM
	appConfig interface{}
	encoder   Encoder
}

func NewPresenter(encoder Encoder, s sbom.SBOM, appConfig interface{}) *Presenter {
	return &Presenter{
		sbom:      s,
		appConfig: appConfig,
		encoder:   encoder,
	}
}

func (pres *Presenter) Present(output io.Writer) error {
	return pres.encoder(output, pres.sbom, pres.appConfig)
}
