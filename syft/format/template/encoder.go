package template

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"text/template"

	"github.com/Masterminds/sprig/v3"

	"github.com/anchore/go-homedir"
	"github.com/anchore/syft/syft/format/syftjson"
	"github.com/anchore/syft/syft/sbom"
)

const ID sbom.FormatID = "template"

type EncoderConfig struct {
	TemplatePath string
	Legacy       bool
	syftjson.EncoderConfig
}

type encoder struct {
	cfg     EncoderConfig
	funcMap template.FuncMap
}

func NewFormatEncoder(cfg EncoderConfig) (sbom.FormatEncoder, error) {
	// TODO: revisit this... should no template file be an error or simply render an empty result? or render the json output?
	// Note: do not check for the existence of the template file here, as the default encoder cannot provide one.
	f := sprig.HermeticTxtFuncMap()
	f["getLastIndex"] = func(collection interface{}) int {
		if v := reflect.ValueOf(collection); v.Kind() == reflect.Slice {
			return v.Len() - 1
		}

		return 0
	}
	// Checks if a field is defined
	f["hasField"] = func(obj interface{}, field string) bool {
		t := reflect.TypeOf(obj)
		_, ok := t.FieldByName(field)
		return ok
	}

	return encoder{
		cfg: cfg,
		// These are custom functions available to template authors.
		funcMap: f,
	}, nil
}

func DefaultEncoderConfig() EncoderConfig {
	return EncoderConfig{
		EncoderConfig: syftjson.DefaultEncoderConfig(),
	}
}

func (e encoder) ID() sbom.FormatID {
	return ID
}

func (e encoder) Aliases() []string {
	return []string{}
}

func (e encoder) Version() string {
	return sbom.AnyVersion
}

func (e encoder) Encode(writer io.Writer, s sbom.SBOM) error {
	if e.cfg.TemplatePath == "" {
		return errors.New("no template file provided")
	}

	templatePath, err := homedir.Expand(e.cfg.TemplatePath)
	if err != nil {
		return fmt.Errorf("unable to expand path %s", e.cfg.TemplatePath)
	}

	templateContents, err := os.ReadFile(templatePath)
	if err != nil {
		return fmt.Errorf("unable to get template content: %w", err)
	}

	tmpl, err := template.New(templatePath).Funcs(e.funcMap).Parse(string(templateContents))
	if err != nil {
		return fmt.Errorf("unable to parse template: %w", err)
	}

	var doc any
	if e.cfg.Legacy {
		doc = syftjson.ToFormatModel(s, e.cfg.EncoderConfig)
	} else {
		enc, err := syftjson.NewFormatEncoderWithConfig(e.cfg.EncoderConfig)
		if err != nil {
			return fmt.Errorf("unable to create json encoder: %w", err)
		}

		var buff bytes.Buffer
		if err = enc.Encode(&buff, s); err != nil {
			return fmt.Errorf("unable to encode json: %w", err)
		}

		deserializedDoc := make(map[string]any)

		if err = json.Unmarshal(buff.Bytes(), &deserializedDoc); err != nil {
			return fmt.Errorf("unable to unmarshal json for template: %w", err)
		}

		doc = deserializedDoc
	}

	return tmpl.Execute(writer, doc)
}
