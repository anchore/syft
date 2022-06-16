package template

import (
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"text/template"

	"github.com/Masterminds/sprig/v3"
	"github.com/anchore/syft/internal/formats/syftjson"
	"github.com/anchore/syft/syft/sbom"
	"github.com/mitchellh/go-homedir"
)

func makeTemplateExecutor(templateFilePath string) (*template.Template, error) {
	if templateFilePath == "" {
		return nil, errors.New("no template file: please provide a template path")
	}

	expandedPathToTemplateFile, err := homedir.Expand(templateFilePath)
	if err != nil {
		return nil, fmt.Errorf("unable to expand path %s", templateFilePath)
	}

	templateContents, err := os.ReadFile(expandedPathToTemplateFile)
	if err != nil {
		return nil, fmt.Errorf("unable to get template content: %w", err)
	}

	templateName := expandedPathToTemplateFile
	tmpl, err := template.New(templateName).Funcs(funcMap).Parse(string(templateContents))
	if err != nil {
		return nil, fmt.Errorf("unable to parse template: %w", err)
	}

	return tmpl, nil
}

// makeEncoderWithTemplate makes a dynamic encoder based off a given
// template file. If making the template parser errors this function
// returns an encoder that will forward the error message.
func makeEncoderWithTemplate(templateFilePath string) sbom.Encoder {
	tmpl, err := makeTemplateExecutor(templateFilePath)
	if err != nil {
		return func(w io.Writer, s sbom.SBOM) error { return fmt.Errorf("template encoder error: %w", err) }
	}

	return func(w io.Writer, s sbom.SBOM) error {
		doc := syftjson.ToFormatModel(s)
		return tmpl.Execute(w, doc)
	}
}

// These are custom functions available to template authors.
var funcMap = func() template.FuncMap {
	f := sprig.HermeticTxtFuncMap()
	f["getLastIndex"] = func(collection interface{}) int {
		if v := reflect.ValueOf(collection); v.Kind() == reflect.Slice {
			return v.Len() - 1
		}

		return 0
	}
	return f
}()
