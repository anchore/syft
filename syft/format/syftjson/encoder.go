package syftjson

import (
	"encoding/json"
	"github.com/anchore/syft/internal"
	"io"

	"github.com/anchore/syft/syft/sbom"
)

var _ sbom.FormatEncoder = (*encoder)(nil)

const ID sbom.FormatID = "syft-json"

type EncoderConfig struct {
	Legacy bool
}

type encoder struct {
	cfg EncoderConfig
}

func DefaultEncoderConfig() EncoderConfig {
	return EncoderConfig{
		Legacy: false,
	}
}

func NewFormatEncoder(cfg EncoderConfig) (sbom.FormatEncoder, error) {
	return encoder{
		cfg: cfg,
	}, nil
}

func DefaultFormatEncoder() sbom.FormatEncoder {
	enc, err := NewFormatEncoder(DefaultEncoderConfig())
	if err != nil {
		panic(err)
	}
	return enc
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
