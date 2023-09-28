package cyclonedxjson

import (
	"github.com/CycloneDX/cyclonedx-go"

	"github.com/anchore/syft/syft/format/internal/cyclonedxutil"
	"github.com/anchore/syft/syft/sbom"
)

const ID sbom.FormatID = "cyclonedx-json"

type EncoderConfig struct {
	Version string
}

type encoder struct {
	cfg EncoderConfig
	cyclonedxutil.Encoder
}

func NewFormatEncoder(cfg EncoderConfig) (sbom.FormatEncoder, error) {
	enc, err := cyclonedxutil.NewEncoder(cfg.Version, cyclonedx.BOMFileFormatJSON)
	if err != nil {
		return nil, err
	}
	return encoder{
		cfg:     cfg,
		Encoder: enc,
	}, nil
}

func DefaultFormatEncoder() sbom.FormatEncoder {
	enc, err := NewFormatEncoder(DefaultEncoderConfig())
	if err != nil {
		panic(err)
	}
	return enc
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
	return []string{}
}

func (e encoder) Version() string {
	return e.cfg.Version
}
