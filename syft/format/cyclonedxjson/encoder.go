package cyclonedxjson

import (
	"github.com/CycloneDX/cyclonedx-go"

	"github.com/anchore/syft/syft/format/internal/cyclonedxutil"
	"github.com/anchore/syft/syft/sbom"
)

const ID = cyclonedxutil.JSONFormatID

func SupportedVersions() []string {
	return cyclonedxutil.SupportedVersions(ID)
}

type EncoderConfig struct {
	Version    string
	Compact    bool // don't include spaces and newlines; same as jq -c
	EscapeHTML bool // escape >, <, and & in the output
}

type encoder struct {
	cfg EncoderConfig
	cyclonedxutil.Encoder
}

func NewFormatEncoderWithConfig(cfg EncoderConfig) (sbom.FormatEncoder, error) {
	enc, err := cyclonedxutil.NewEncoder(cfg.Version, cyclonedx.BOMFileFormatJSON, !cfg.Compact, cfg.EscapeHTML)
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
		Version:    cyclonedxutil.DefaultVersion,
		Compact:    false,
		EscapeHTML: false,
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
