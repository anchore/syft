package syftjson

import (
	"encoding/json"
	"io"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/syft/sbom"
)

var _ sbom.FormatEncoder = (*encoder)(nil)

const ID sbom.FormatID = "syft-json"

type EncoderConfig struct {
	Legacy bool // transform the output to the legacy syft-json format (pre v1.0 changes, enumerated in the README.md)
}

type encoder struct {
	cfg EncoderConfig
}

func NewFormatEncoder() sbom.FormatEncoder {
	enc, err := NewFormatEncoderWithConfig(DefaultEncoderConfig())
	if err != nil {
		panic(err)
	}
	return enc
}

func NewFormatEncoderWithConfig(cfg EncoderConfig) (sbom.FormatEncoder, error) {
	return encoder{
		cfg: cfg,
	}, nil
}

func DefaultEncoderConfig() EncoderConfig {
	return EncoderConfig{
		Legacy: false,
	}
}

func (e encoder) ID() sbom.FormatID {
	return ID
}

func (e encoder) Aliases() []string {
	return []string{
		"json",
		"syft",
	}
}

func (e encoder) Version() string {
	return internal.JSONSchemaVersion
}

func (e encoder) Encode(writer io.Writer, s sbom.SBOM) error {
	doc := ToFormatModel(s, e.cfg)

	enc := json.NewEncoder(writer)
	// prevent > and < from being escaped in the payload
	enc.SetEscapeHTML(false)
	enc.SetIndent("", " ")

	return enc.Encode(&doc)
}
