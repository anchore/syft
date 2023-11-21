package spdxjson

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/spdx/tools-golang/convert"
	"github.com/spdx/tools-golang/spdx/v2/v2_1"
	"github.com/spdx/tools-golang/spdx/v2/v2_2"
	"github.com/spdx/tools-golang/spdx/v2/v2_3"

	"github.com/anchore/syft/syft/format/common/spdxhelpers"
	"github.com/anchore/syft/syft/format/internal/spdxutil"
	"github.com/anchore/syft/syft/sbom"
)

const ID = spdxutil.JSONFormatID

func SupportedVersions() []string {
	return spdxutil.SupportedVersions(ID)
}

type EncoderConfig struct {
	Version string
	Pretty  bool // don't include spaces and newlines; same as jq -c
}

type encoder struct {
	cfg EncoderConfig
}

func NewFormatEncoderWithConfig(cfg EncoderConfig) (sbom.FormatEncoder, error) {
	return encoder{
		cfg: cfg,
	}, nil
}

func DefaultEncoderConfig() EncoderConfig {
	return EncoderConfig{
		Version: spdxutil.DefaultVersion,
		Pretty:  false,
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
	latestDoc := spdxhelpers.ToFormatModel(s)
	if latestDoc == nil {
		return fmt.Errorf("unable to convert SBOM to SPDX document")
	}

	var err error
	var encodeDoc any
	switch e.cfg.Version {
	case "2.1":
		doc := v2_1.Document{}
		err = convert.Document(latestDoc, &doc)
		encodeDoc = doc
	case "2.2":
		doc := v2_2.Document{}
		err = convert.Document(latestDoc, &doc)
		encodeDoc = doc

	case "2.3":
		doc := v2_3.Document{}
		err = convert.Document(latestDoc, &doc)
		encodeDoc = doc
	default:
		return fmt.Errorf("unsupported SPDX version %q", e.cfg.Version)
	}

	if err != nil {
		return fmt.Errorf("unable to convert SBOM to SPDX document: %w", err)
	}

	enc := json.NewEncoder(writer)

	enc.SetEscapeHTML(false)

	if e.cfg.Pretty {
		enc.SetIndent("", " ")
	}

	return enc.Encode(encodeDoc)
}
