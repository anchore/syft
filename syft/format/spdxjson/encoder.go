package spdxjson

import (
	"encoding/json"
	"github.com/anchore/syft/syft/format/internal/spdxutil"
	"io"

	"github.com/anchore/syft/syft/sbom"
)

const ID sbom.FormatID = "spdx-json"

type EncoderConfig struct {
	Version string
}

type encoder struct {
	cfg EncoderConfig
	doc any
}

func NewFormatEncoder(cfg EncoderConfig) (sbom.FormatEncoder, error) {
	doc, err := spdxutil.DocumentPrototypeFromVersion(cfg.Version)
	if err != nil {
		return nil, err
	}
	return encoder{
		cfg: cfg,
		doc: doc,
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
		Version: spdxutil.DefaultVersion,
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

func (e encoder) Encode(writer io.Writer, s sbom.SBOM) error {
	err := spdxutil.ToDocument(s, &e.doc)
	if err != nil {
		return err
	}

	enc := json.NewEncoder(writer)
	// prevent > and < from being escaped in the payload
	enc.SetEscapeHTML(false)
	enc.SetIndent("", " ")

	return enc.Encode(e.doc)
}
