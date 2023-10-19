package cyclonedxxml

import (
	"github.com/CycloneDX/cyclonedx-go"

	"github.com/anchore/syft/syft/format/internal/cyclonedxutil"
	"github.com/anchore/syft/syft/sbom"
)

var _ sbom.FormatEncoder = (*encoder)(nil)

const ID = cyclonedxutil.XMLFormatID

func SupportedVersions() []string {
	return cyclonedxutil.SupportedVersions(ID)
}

type EncoderConfig struct {
	Version string
}

type encoder struct {
	cfg EncoderConfig
	cyclonedxutil.Encoder
}

func NewFormatEncoderWithConfig(cfg EncoderConfig) (sbom.FormatEncoder, error) {
	enc, err := cyclonedxutil.NewEncoder(cfg.Version, cyclonedx.BOMFileFormatXML)
	if err != nil {
		return nil, err
	}
	return encoder{
		cfg:     cfg,
		Encoder: enc,
	}, nil
}

func DefaultEncoderConfig() EncoderConfig {
	return EncoderConfig{
		Version: cyclonedxutil.DefaultVersion,
	}
}

func (e encoder) ID() sbom.FormatID {
	return ID
}

func (e encoder) Aliases() []string {
	return []string{
		"cyclonedx",
		"cyclone",
		"cdx",
	}
}

func (e encoder) Version() string {
	return e.cfg.Version
}
