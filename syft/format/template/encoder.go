package template

import (
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"text/template"

	"github.com/Masterminds/sprig/v3"
	"github.com/mitchellh/go-homedir"

	"github.com/anchore/syft/syft/format/syftjson"
	"github.com/anchore/syft/syft/sbom"
)

const ID sbom.FormatID = "template"

type EncoderConfig struct {
	TemplatePath string
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
	return EncoderConfig{}
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
	return []string{}
}

func (e encoder) Version() string {
	return sbom.AnyVersion
}

func (e encoder) Encode(writer io.Writer, s sbom.SBOM) error {
	if e.cfg.TemplatePath == "" {
		return errors.New("no template file provided")
	}

	expandedPathToTemplateFile, err := homedir.Expand(e.cfg.TemplatePath)
	if err != nil {
		return fmt.Errorf("unable to expand path %s", e.cfg.TemplatePath)
	}

	templateContents, err := os.ReadFile(expandedPathToTemplateFile)
	if err != nil {
		return fmt.Errorf("unable to get template content: %w", err)
	}

	templateName := expandedPathToTemplateFile
	tmpl, err := template.New(templateName).Funcs(e.funcMap).Parse(string(templateContents))
	if err != nil {
		return fmt.Errorf("unable to parse template: %w", err)
	}

	doc := syftjson.ToFormatModel(s)
	return tmpl.Execute(writer, doc)
}
